import unittest

from filters import filter_packets


class TestPacketFilters(unittest.TestCase):

    def setUp(self):
        self.packets = [
            {
                "number": 1,
                "parsed": {
                    "ip": {
                        "source_ip": "192.168.1.10",
                        "destination_ip": "8.8.8.8",
                        "protocol": "UDP",
                    },
                    "transport": {
                        "source_port": 53000,
                        "destination_port": 53,
                    },
                },
            },
            {
                "number": 2,
                "parsed": {
                    "ip": {
                        "source_ip": "192.168.1.10",
                        "destination_ip": "142.250.183.14",
                        "protocol": "TCP",
                    },
                    "transport": {
                        "source_port": 51234,
                        "destination_port": 443,
                    },
                },
            },
            {
                "number": 3,
                "parsed": {
                    "ip": {
                        "source_ip": "192.168.1.20",
                        "destination_ip": "192.168.1.10",
                        "protocol": "TCP",
                    },
                    "transport": None,
                },
            },
        ]

    def test_protocol_filter(self):
        result = filter_packets(self.packets, protocol="TCP")
        self.assertEqual([p["number"] for p in result], [2, 3])

    def test_source_ip_filter(self):
        result = filter_packets(
            self.packets,
            source_ip="192.168.1.10",
        )
        self.assertEqual([p["number"] for p in result], [1, 2])

    def test_destination_ip_filter(self):
        result = filter_packets(
            self.packets,
            destination_ip="8.8.8.8",
        )
        self.assertEqual([p["number"] for p in result], [1])

    def test_destination_port_filter(self):
        result = filter_packets(
            self.packets,
            destination_port=443,
        )
        self.assertEqual([p["number"] for p in result], [2])

    def test_combined_filters(self):
        result = filter_packets(
            self.packets,
            protocol="TCP",
            source_ip="192.168.1.10",
            destination_port=443,
        )
        self.assertEqual([p["number"] for p in result], [2])

    def test_port_filter_excludes_packet_without_transport_header(self):
        result = filter_packets(self.packets, destination_port=80)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
