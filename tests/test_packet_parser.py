import unittest

from packet_parser import parse_ipv4


class TestIPv4Parser(unittest.TestCase):

    def test_ipv4_udp_packet(self):
        # First 20 bytes of the packet you captured.
        raw_packet = bytes.fromhex(
            "45 00 00 8B EC 13 00 00 FF 11 "
            "F9 1E C0 A8 34 8B 00 00 00 00"
        )

        result = parse_ipv4(
            raw_packet + bytes(139 - len(raw_packet))
        )

        self.assertEqual(result["version"], 4)
        self.assertEqual(result["header_length"], 20)
        self.assertEqual(result["total_length"], 139)
        self.assertEqual(result["ttl"], 255)
        self.assertEqual(result["protocol"], "UDP")
        self.assertEqual(result["checksum"], 0xF91E)
        self.assertEqual(result["source_ip"], "192.168.52.139")

    def test_packet_too_short(self):
        with self.assertRaises(ValueError):
            parse_ipv4(b"\x45\x00")

    def test_invalid_ip_version(self):
        raw_packet = bytes(20)

        with self.assertRaises(ValueError):
            parse_ipv4(raw_packet)


if __name__ == "__main__":
    unittest.main(verbosity=2)
