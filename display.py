from datetime import datetime


def format_timestamp(timestamp):
    """Format a packet timestamp for display."""

    return datetime.fromtimestamp(timestamp).strftime(
        "%H:%M:%S.%f"
    )[:-3]


def display_packet_summary(packets):
    """
    Display a table containing summaries of captured packets.

    Each item in packets is expected to contain:
    number, timestamp, raw_data, and parsed.
    """

    if not packets:
        print("\nNo packets to display.")
        return

    header = (
        f"{'No.':<6}"
        f"{'Time':<15}"
        f"{'Source IP':<18}"
        f"{'Destination IP':<18}"
        f"{'Protocol':<10}"
        f"{'Src Port':<10}"
        f"{'Dst Port':<10}"
        f"{'Length':<8}"
    )

    print("\n" + header)
    print("-" * len(header))

    for packet in packets:
        parsed = packet["parsed"]
        ip_info = parsed["ip"]
        transport = parsed["transport"]

        source_port = "-"
        destination_port = "-"

        if transport is not None:
            source_port = str(transport["source_port"])
            destination_port = str(transport["destination_port"])

        timestamp = format_timestamp(packet["timestamp"])

        print(
            f"{packet['number']:<6}"
            f"{timestamp:<15}"
            f"{ip_info['source_ip']:<18}"
            f"{ip_info['destination_ip']:<18}"
            f"{ip_info['protocol']:<10}"
            f"{source_port:<10}"
            f"{destination_port:<10}"
            f"{packet['packet_length']:<8}"
        )


def display_packet_details(packet):
    """Display detailed information about one captured packet."""

    parsed = packet["parsed"]
    ip_info = parsed["ip"]
    transport = parsed["transport"]
    payload = parsed["payload"]

    print("\n" + "=" * 60)
    print(f"PACKET #{packet['number']}")
    print("=" * 60)

    print(f"Time: {format_timestamp(packet['timestamp'])}")
    print(f"Captured Size: {len(packet['raw_data'])} bytes")
    print(f"IPv4 Total Length: {ip_info['total_length']} bytes")

    print("\nIP HEADER")
    print("-" * 40)
    print(f"Version: {ip_info['version']}")
    print(f"Header Length: {ip_info['header_length']} bytes")
    print(f"Total Length: {ip_info['total_length']} bytes")
    print(f"TTL: {ip_info['ttl']}")
    print(f"Protocol: {ip_info['protocol']}")
    print(f"Header Checksum: 0x{ip_info['checksum']:04X}")
    print(f"Source IP: {ip_info['source_ip']}")
    print(f"Destination IP: {ip_info['destination_ip']}")
    print(f"Identification: {ip_info['identification']}")
    print(f"Flags: {ip_info['flags']}")
    print(f"Fragment Offset: {ip_info['fragment_offset']}")

    if transport is not None:
        print(f"\n{ip_info['protocol']} HEADER")
        print("-" * 40)

        print(f"Source Port: {transport['source_port']}")
        print(f"Destination Port: {transport['destination_port']}")

        if ip_info["protocol"] == "TCP":
            print(f"Sequence Number: {transport['sequence_number']}")
            print(
                "Acknowledgment Number: "
                f"{transport['acknowledgment_number']}"
            )
            print(f"Header Length: {transport['header_length']} bytes")
            print(
                "Flags: "
                + (", ".join(transport["flags"]) or "None")
            )
            print(f"Window Size: {transport['window_size']}")
            print(f"Checksum: 0x{transport['checksum']:04X}")

        elif ip_info["protocol"] == "UDP":
            print(f"Length: {transport['length']} bytes")
            print(f"Checksum: 0x{transport['checksum']:04X}")

        print(f"Payload Length: {transport['payload_length']} bytes")

    elif parsed["analysis_status"] == "non_initial_fragment":
        print("\nTransport header unavailable in this fragment.")

    else:
        print("\nNo TCP/UDP header was decoded for this packet.")

    print("\nPAYLOAD")
    print("-" * 40)

    if not payload:
        print("Empty payload (0 bytes).")
    else:
        print("Hex:")
        print(payload.hex(" ").upper())

        print("\nText:")
        print(payload.decode("utf-8", errors="replace"))
