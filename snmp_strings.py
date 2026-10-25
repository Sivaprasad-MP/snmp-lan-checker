#!/usr/bin/env python3
"""Native Python SNMP v1/v2c community checker. No external dependencies."""
import argparse
import concurrent.futures as futures
import csv
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import time

OIDS = {'description': '1.3.6.1.2.1.1.1.0', 'name': '1.3.6.1.2.1.1.5.0',
        'uptime': '1.3.6.1.2.1.1.3.0'}


def tlv(tag, data):
    n = len(data)
    length = bytes([n]) if n < 128 else (lambda b: bytes([128 | len(b)]) + b)(n.to_bytes((n.bit_length()+7)//8, 'big'))
    return bytes([tag]) + length + data


def integer(n):
    return tlv(2, n.to_bytes(max(1, (n.bit_length()+8)//8), 'big', signed=True))


def base128(n):
    result = [n & 127]
    n >>= 7
    while n:
        result.insert(0, (n & 127) | 128)
        n >>= 7
    return bytes(result)


def encode_oid(oid):
    parts = [int(x) for x in oid.split('.')]
    return tlv(6, b''.join(base128(x) for x in [40*parts[0]+parts[1], *parts[2:]]))


def read_tlv(data, pos=0):
    if pos+2 > len(data):
        raise ValueError('Truncated BER header')
    tag, size = data[pos:pos+2]
    pos += 2
    if size & 128:
        count = size & 127
        if not 1 <= count <= 4 or pos+count > len(data):
            raise ValueError('Invalid BER length')
        size = int.from_bytes(data[pos:pos+count], 'big')
        pos += count
    end = pos+size
    if end > len(data):
        raise ValueError('Truncated BER value')
    return tag, data[pos:end], end


def children(data):
    pos = 0
    result = []
    while pos < len(data):
        tag, value, pos = read_tlv(data, pos)
        result.append((tag, value))
    return result


def decode_oid(data):
    values, value = [], 0
    for byte in data:
        value = (value << 7) | (byte & 127)
        if not byte & 128:
            values.append(value)
            value = 0
    if not values or data[-1] & 128:
        raise ValueError('Invalid OID')
    first = values.pop(0)
    a = min(first//40, 2)
    return '.'.join(map(str, [a, first-40*a, *values]))


def request(community, version, request_id):
    bindings = b''.join(tlv(48, encode_oid(oid)+tlv(5, b'')) for oid in OIDS.values())
    pdu = tlv(160, integer(request_id)+integer(0)+integer(0)+tlv(48, bindings))
    return tlv(48, integer(version)+tlv(4, community.encode())+pdu)


def parse_response(packet, community, version, request_id):
    tag, body, end = read_tlv(packet)
    if tag != 48 or end != len(packet):
        raise ValueError('Invalid message')
    fields = children(body)
    if len(fields) != 3 or fields[0] != (2, bytes([version])) or fields[1] != (4, community.encode()) or fields[2][0] != 162:
        raise ValueError('Unmatched response')
    pdu = children(fields[2][1])
    if len(pdu) != 4 or [x[0] for x in pdu] != [2, 2, 2, 48]:
        raise ValueError('Invalid response PDU')
    if not all(x[1] for x in pdu[:3]) or int.from_bytes(pdu[0][1], 'big', signed=True) != request_id:
        raise ValueError('Unmatched request ID')
    error = int.from_bytes(pdu[1][1], 'big', signed=True)
    if error:
        return None, f'SNMP error {error}'
    info = {}
    expected = dict(zip(OIDS.values(), OIDS.keys()))
    for tag, binding in children(pdu[3][1]):
        pair = children(binding)
        if tag != 48 or len(pair) != 2 or pair[0][0] != 6:
            raise ValueError('Invalid variable binding')
        oid = decode_oid(pair[0][1])
        kind, value = pair[1]
        name = expected.get(oid)
        # Exception values and unexpected types never establish read access.
        if name in ('description', 'name') and kind == 4:
            info[name] = value.decode('utf-8', errors='replace')
        elif name == 'uptime' and kind == 67 and value:
            info[name] = int.from_bytes(value, 'big') / 100
    return (info, None) if info else (None, 'No requested readable OIDs')


def query(ip, community, version, timeout, retries, port):
    family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    request_id = secrets.randbelow(2147483647)
    packet = request(community, version, request_id)
    detail = 'No valid response (timeout)'
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.connect((ip, port))
        for _ in range(retries+1):
            sock.send(packet)
            deadline = time.monotonic()+timeout
            while time.monotonic() < deadline:
                sock.settimeout(max(0.001, deadline-time.monotonic()))
                try:
                    response = sock.recv(65535)
                except socket.timeout:
                    break
                try:
                    info, error = parse_response(response, community, version, request_id)
                except ValueError:
                    detail = 'Malformed or unmatched response received'
                    continue
                return info, error
    return None, detail


def scan_host(ip, args):
    details = []
    for community in args.community:
        for version in args.versions:
            try:
                info, detail = query(ip, community, 0 if version == '1' else 1,
                                     args.timeout, args.retries, args.port)
            except OSError as error:
                info, detail = None, str(error)
            if info is not None:
                return {'ip': ip, 'status': 'read_confirmed', 'community': community,
                        'version': version, 'info': info}
            details.append({'version': version, 'detail': detail})
    return {'ip': ip, 'status': 'inconclusive', 'attempts': details}


def targets(ranges, limit):
    unique = {}
    for item in ranges.split(','):
        item = item.strip()
        if '/' in item:
            net = ipaddress.ip_network(item, strict=False)
            count = net.num_addresses
            if net.version == 4 and net.prefixlen < 31:
                count -= 2
            elif net.version == 6 and net.prefixlen < 127:
                count -= 1
            if count > limit:
                raise ValueError(f'{item} exceeds host limit {limit}')
            addresses = net.hosts()
        elif '-' in item:
            start, end = item.split('-', 1)
            first = ipaddress.ip_address(start)
            if first.version == 4 and '.' not in end:
                end = start.rsplit('.', 1)[0]+'.'+end
            last = ipaddress.ip_address(end)
            if first.version != last.version or int(last) < int(first):
                raise ValueError(f'Invalid range: {item}')
            if int(last)-int(first)+1 > limit:
                raise ValueError(f'{item} exceeds host limit {limit}')
            addresses = (type(first)(n) for n in range(int(first), int(last)+1))
        else:
            addresses = [ipaddress.ip_address(item)]
        for address in addresses:
            unique[str(address)] = None
            if len(unique) > limit:
                raise ValueError(f'Combined targets exceed host limit {limit}')
    return list(unique)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ranges', help='IP, CIDR, range, or comma-separated targets')
    parser.add_argument('threads', nargs='?', type=int, default=10, help='Concurrent hosts, 1-64 (default 10)')
    parser.add_argument('--community', action='append', help='Community to check; repeat for additional values (default public)')
    parser.add_argument('--version', choices=['1', '2c', 'both'], default='2c')
    parser.add_argument('--timeout', type=float, default=2)
    parser.add_argument('--retries', type=int, default=0)
    parser.add_argument('--port', type=int, default=161)
    parser.add_argument('--max-hosts', type=int, default=4096)
    parser.add_argument('--output', type=Path, help='Report directory')
    args = parser.parse_args()
    if not 1 <= args.threads <= 64 or not 0.1 <= args.timeout <= 30 or not 0 <= args.retries <= 3 or not 1 <= args.port <= 65535 or args.max_hosts < 1:
        parser.error('Invalid threads (1-64), timeout (0.1-30), retries (0-3), port, or host limit')
    args.community = list(dict.fromkeys(args.community or ['public']))
    if any(not c or len(c.encode()) > 255 for c in args.community):
        parser.error('Communities must contain 1-255 UTF-8 bytes')
    args.versions = ['2c', '1'] if args.version == 'both' else [args.version]
    try:
        ips = targets(args.ranges, args.max_hosts)
    except ValueError as error:
        parser.error(str(error))
    output = args.output or Path('snmp_range_'+datetime.now().strftime('%Y%m%d_%H%M%S_%f'))
    output.mkdir(parents=True, exist_ok=True)
    results = []
    interrupted = False
    print(f'Checking {len(ips)} hosts; {args.threads} workers; output: {output}', flush=True)
    pool = futures.ThreadPoolExecutor(max_workers=args.threads)
    pending = {}
    remaining = iter(ips)
    def submit_next():
        ip = next(remaining, None)
        if ip is not None:
            pending[pool.submit(scan_host, ip, args)] = ip
    try:
        with (output/'results.jsonl').open('w', encoding='utf-8') as stream:
            for _ in range(min(args.threads, len(ips))):
                submit_next()
            while pending:
                done, _ = futures.wait(pending, return_when=futures.FIRST_COMPLETED)
                for future in done:
                    ip = pending.pop(future)
                    try:
                        result = future.result()
                    except Exception as error:
                        result = {'ip': ip, 'status': 'error', 'detail': str(error)}
                    results.append(result)
                    stream.write(json.dumps(result)+'\n')
                    stream.flush()
                    print(f'[{len(results)}/{len(ips)}] {ip}: {result["status"]}', flush=True)
                    submit_next()
    except KeyboardInterrupt:
        interrupted = True
        print('\nInterrupted; saving completed results.', flush=True)
    finally:
        for future in pending:
            future.cancel()
        pool.shutdown(wait=True)
    confirmed = [r for r in results if r['status'] == 'read_confirmed']
    report = {'scan_time': datetime.now(timezone.utc).isoformat(), 'targets': args.ranges,
              'total_targets': len(ips), 'completed': len(results), 'interrupted': interrupted,
              'accessible': len(confirmed), 'results': results}
    (output/'results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    with (output/'accessible.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(['IP', 'Community', 'Version', 'System Name', 'Description', 'Uptime Seconds'])
        for result in confirmed:
            info = result['info']
            writer.writerow([result['ip'], result['community'], result['version'], info.get('name', ''), info.get('description', ''), info.get('uptime', '')])
    print(f'Completed {len(results)}/{len(ips)}; read access confirmed: {len(confirmed)}; reports: {output}')
    return 130 if interrupted else (1 if confirmed else 0)


if __name__ == '__main__':
    raise SystemExit(main())
