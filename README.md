# Native Python SNMP LAN checker

Requires Python 3.8+ only. No snmpwalk, Nmap, pip packages, or administrator privileges required. Use on networks you own or are authorized to assess.

```bash
python3 snmp_strings.py 192.168.1.0/24 16
python3 snmp_strings.py 192.168.1.1-254 16 --version both
python3 snmp_strings.py 192.168.1.0/24,192.168.2.0/24 16 --output reports
python3 snmp_strings.py 192.168.1.0/24 --community public --community your-known-community
```

The original positional range and thread arguments still work. CIDRs, IPv4 shorthand ranges, full address ranges, and individual IPv4/IPv6 addresses are supported. Overlapping addresses are deduplicated. IPv4 network/broadcast addresses are skipped for prefixes shorter than /31. The default host limit is 4096; override with `--max-hosts`.

Each attempt sends a read-only SNMP GET for description, name, and uptime to UDP 161. The response must come from the queried endpoint, match the request ID, community and version, have no SNMP error, and contain a requested OID with its expected value type. Missing-object exceptions do not count as read access. `read_confirmed` establishes access only to returned OIDs from this source machine; it does not establish write access. A timeout, error, unsupported OID, or malformed reply is inconclusive.

Defaults: public community, SNMPv2c, 10 concurrent hosts, two-second timeout, zero retries. `--version both` checks v2c then v1. Communities and versions are tried sequentially per host and stop at the first confirmed result. There is no automatic dictionary guessing or full device dump. Use `--timeout`, `--retries`, `--port`, and `--community` to configure checks.

Reports: `results.jsonl` is flushed per completed host; `results.json` includes summary and results; `accessible.csv` contains confirmed hosts with correct CSV escaping. Reports include working communities; store them accordingly. Ctrl+C preserves completed results, stops new work, and waits for currently running bounded checks before writing summaries. Exit status is 1 when read access is confirmed, 0 when none is confirmed, 2 for argument errors, and 130 for interruption. Zero does not prove the network is secure.

Tests use a local simulated agent only:

```bash
python3 -m unittest -v test_snmp_strings.py
```
