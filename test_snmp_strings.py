import socket
import threading
import unittest
from unittest.mock import MagicMock, patch
import snmp_strings as s


def response(rid, value=None, error=0):
    value = s.tlv(4, b'test device') if value is None else value
    binding = s.tlv(48, s.encode_oid(s.OIDS['description']) + value)
    return s.tlv(48, s.integer(1) + s.tlv(4, b'public') +
                 s.tlv(162, s.integer(rid)+s.integer(error)+s.integer(0)+s.tlv(48, binding)))


class Tests(unittest.TestCase):
    def udp_socket(self):
        try:
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except PermissionError:
            self.skipTest('Environment prohibits UDP sockets')

    def test_mocked_transport(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.side_effect = [b'malformed', response(123)]
        with patch.object(s.socket, 'socket', return_value=sock), patch.object(s.secrets, 'randbelow', return_value=123):
            info, error = s.query('127.0.0.1', 'public', 1, 1, 0, 161)
        self.assertEqual(info, {'description': 'test device'})
        self.assertIsNone(error)
        sock.connect.assert_called_once_with(('127.0.0.1', 161))
        sock.recv.side_effect = socket.timeout()
        sock.send.reset_mock()
        with patch.object(s.socket, 'socket', return_value=sock):
            info, error = s.query('127.0.0.1', 'public', 1, 0.02, 1, 161)
        self.assertIsNone(info)
        self.assertIn('timeout', error)
        self.assertEqual(sock.send.call_count, 2)

    def test_response_validation(self):
        self.assertEqual(s.parse_response(response(123), 'public', 1, 123)[0], {'description': 'test device'})
        self.assertIsNone(s.parse_response(response(123, s.tlv(128, b'')), 'public', 1, 123)[0])
        self.assertIsNone(s.parse_response(response(123, error=2), 'public', 1, 123)[0])
        for data in (response(122), response(123)[:-1], b'garbage'):
            with self.assertRaises(ValueError):
                s.parse_response(data, 'public', 1, 123)
        with self.assertRaises(ValueError):
            s.parse_response(response(123), 'private', 1, 123)

    def test_targets(self):
        self.assertEqual(len(s.targets('192.168.1.0/24', 4096)), 254)
        self.assertEqual(s.targets('192.0.2.1-2,192.0.2.1', 10), ['192.0.2.1', '192.0.2.2'])
        self.assertEqual(s.targets('::/127', 10), ['::', '::1'])
        for target in ('10.0.0.0/8', '192.0.2.5-1', 'bad'):
            with self.assertRaises(ValueError):
                s.targets(target, 4096)

    def test_ber_long_length(self):
        packet = s.tlv(4, b'x'*300)
        self.assertEqual(s.read_tlv(packet), (4, b'x'*300, len(packet)))
        for oid in ('1.3.6.1.2.1.1.1.0', '2.200.999.0'):
            self.assertEqual(s.decode_oid(s.read_tlv(s.encode_oid(oid))[1]), oid)

    def test_udp_exchange(self):
        with self.udp_socket() as server:
            server.bind(('127.0.0.1', 0))
            server.settimeout(2)
            def agent():
                packet, peer = server.recvfrom(65535)
                fields = s.children(s.read_tlv(packet)[1])
                rid = int.from_bytes(s.children(fields[2][1])[0][1], 'big')
                server.sendto(b'malformed', peer)
                server.sendto(response(rid), peer)
            worker = threading.Thread(target=agent)
            worker.start()
            info, error = s.query('127.0.0.1', 'public', 1, 1, 0, server.getsockname()[1])
            worker.join()
            self.assertEqual(info, {'description': 'test device'})
            self.assertIsNone(error)

    def test_timeout(self):
        with self.udp_socket() as server:
            server.bind(('127.0.0.1', 0))
            info, error = s.query('127.0.0.1', 'public', 1, 0.02, 0, server.getsockname()[1])
            self.assertIsNone(info)
            self.assertIn('timeout', error)


if __name__ == '__main__':
    unittest.main()
