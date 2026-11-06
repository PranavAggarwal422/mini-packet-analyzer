import unittest
from packet_parser import parse_tcp, parse_udp


class TestTransportParser(unittest.TestCase):

    def test_tcp_header(self):
        # TCP header:
        # Src=49152, Dst=8080
        # Seq=105482, Ack=208713
        # Header length=20 bytes
        # Flags=PSH, ACK
        # Window=65535, Checksum=0x2F81
        tcp_header = bytes.fromhex(
            "C0 00 1F 90 "
            "00 01 9C 0A "
            "00 03 2F 49 "
            "50 18 "
            "FF FF "
            "2F 81 "
            "00 00"
        )

        result = parse_tcp(tcp_header, 0, len(tcp_header))

        self.assertEqual(result["source_port"], 49152)
        self.assertEqual(result["destination_port"], 8080)
        self.assertEqual(result["sequence_number"], 105482)
        self.assertEqual(result["acknowledgment_number"], 208713)
        self.assertEqual(result["header_length"], 20)
        self.assertEqual(result["flags"], ["ACK", "PSH"])
        self.assertEqual(result["window_size"], 65535)
        self.assertEqual(result["checksum"], 0x2F81)
        self.assertEqual(result["payload_length"], 0)

    def test_udp_header(self):
      # UDP header:
      # Source port = 53000
      # Destination port = 53
      # Length = 16 bytes
      # Checksum = 0x1234
      #
      # The packet contains an 8-byte header and
      # an 8-byte payload.

      udp_header = bytes.fromhex(
          "CF 08 00 35 00 10 12 34"
      )

      # Append 8 bytes of payload.
      udp_packet = udp_header + bytes(8)

      result = parse_udp(
          udp_packet,
          0,
          len(udp_packet)
      )

      self.assertEqual(result["source_port"], 53000)
      self.assertEqual(result["destination_port"], 53)
      self.assertEqual(result["length"], 16)
      self.assertEqual(result["checksum"], 0x1234)
      self.assertEqual(result["payload_length"], 8)

    def test_invalid_udp_length(self):
        # UDP length cannot be less than 8 bytes.
        udp_header = bytes.fromhex(
            "00 35 00 35 00 07 00 00"
        )

        with self.assertRaises(ValueError):
            parse_udp(udp_header, 0, len(udp_header))

    def test_truncated_tcp_header(self):
        with self.assertRaises(ValueError):
            parse_tcp(bytes(10), 0, 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
