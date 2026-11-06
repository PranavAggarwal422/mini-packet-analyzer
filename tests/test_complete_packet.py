import unittest
import struct

from packet_parser import parse_packet


def build_ipv4_packet(protocol, transport_header, payload=b""):
    """
    Construct a minimal IPv4 packet for testing.
    """

    total_length = 20 + len(transport_header) + len(payload)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,                   # IPv4, 20-byte header
        0,                      # Type of service
        total_length,
        1,                      # Identification
        0,                      # Flags and fragment offset
        64,                     # TTL
        protocol,
        0,                      # Header checksum
        bytes([192, 168, 1, 10]),
        bytes([192, 168, 1, 20]),
    )

    return ip_header + transport_header + payload


class TestCompletePacketParser(unittest.TestCase):

    def test_complete_udp_packet(self):
        udp_header = struct.pack(
            "!HHHH",
            53000,
            53,
            11,       # 8-byte header + 3-byte payload
            0x1234,
        )

        raw_packet = build_ipv4_packet(
            17,
            udp_header,
            b"abc",
        )

        result = parse_packet(raw_packet)

        self.assertEqual(result["ip"]["protocol"], "UDP")
        self.assertEqual(result["transport"]["source_port"], 53000)
        self.assertEqual(result["transport"]["destination_port"], 53)
        self.assertEqual(result["payload"], b"abc")
        self.assertEqual(result["analysis_status"], "complete")

    def test_complete_tcp_packet(self):
        tcp_header = struct.pack(
            "!HHIIHHHH",
            49152,      # Source port
            8080,       # Destination port
            105482,     # Sequence number
            208713,     # Acknowledgment number
            (5 << 12) | 0x18,  # 20-byte header, PSH + ACK
            65535,      # Window size
            0x2F81,     # Checksum
            0,          # Urgent pointer
        )

        raw_packet = build_ipv4_packet(
            6,
            tcp_header,
            b"HELLO",
        )

        result = parse_packet(raw_packet)

        self.assertEqual(result["ip"]["protocol"], "TCP")
        self.assertEqual(result["transport"]["source_port"], 49152)
        self.assertEqual(result["transport"]["destination_port"], 8080)
        self.assertEqual(result["transport"]["sequence_number"], 105482)
        self.assertEqual(result["transport"]["acknowledgment_number"], 208713)
        self.assertEqual(result["transport"]["flags"], ["ACK", "PSH"])
        self.assertEqual(result["payload"], b"HELLO")

    def test_empty_tcp_payload(self):
        tcp_header = struct.pack(
            "!HHIIHHHH",
            50000,
            443,
            1,
            0,
            (5 << 12) | 0x02,  # SYN
            8192,
            0,
            0,
        )

        raw_packet = build_ipv4_packet(6, tcp_header)

        result = parse_packet(raw_packet)

        self.assertEqual(result["payload"], b"")
        self.assertEqual(result["transport"]["payload_length"], 0)

    def test_non_initial_fragment(self):
        # IPv4 fragment offset = 1.
        # The packet must not be interpreted as a TCP header.
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            24,
            2,
            1,
            64,
            6,
            0,
            bytes([192, 168, 1, 10]),
            bytes([192, 168, 1, 20]),
        )

        raw_packet = ip_header + bytes(4)

        result = parse_packet(raw_packet)

        self.assertEqual(
            result["analysis_status"],
            "non_initial_fragment",
        )
        self.assertIsNone(result["transport"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
