import time
import ipaddress
import struct
import pydivert

from packet_parser import parse_packet
from display import display_packet_summary, display_packet_details
from filters import filter_packets


def capture_packets():
    """Capture IPv4 packets until the user presses Ctrl+C."""

    packets = []
    malformed_count = 0

    print("\nStarting packet capture...")
    print("Generate network traffic by browsing or using an application.")
    print("Press Ctrl+C to stop capturing and return to the menu.\n")

    try:
        with pydivert.WinDivert(
            "ip and (outbound or inbound)",
            layer=pydivert.Layer.NETWORK,
            flags=pydivert.Flag.SNIFF,
        ) as capture:

            print("Capture started successfully.\n")

            for packet in capture:
                raw_data = bytes(packet.raw)
                timestamp = time.time()

                try:
                    parsed = parse_packet(raw_data)

                    record = {
                        "number": len(packets) + 1,
                        "timestamp": timestamp,
                        "raw_data": raw_data,
                        "packet_length": len(raw_data),
                        "parsed": parsed,
                    }

                    packets.append(record)

                    if len(packets) % 100 == 0:
                        print(
                            f"Captured {len(packets)} valid packets..."
                        )

                except (ValueError, IndexError, struct.error) as exc:
                    malformed_count += 1

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    except Exception as exc:
        print(f"\nCapture error: {type(exc).__name__}: {exc}")
        print("Try running VS Code as Administrator.")

    print(f"\nValid packets captured: {len(packets)}")
    print(f"Malformed packets skipped: {malformed_count}")

    return packets


def get_optional_ip(prompt):
    """Read and validate an optional IPv4 address."""

    value = input(prompt).strip()

    if not value:
        return None

    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        print("Invalid IPv4 address.")
        return False


def get_optional_port(prompt):
    """Read and validate an optional port number."""

    value = input(prompt).strip()

    if not value:
        return None

    try:
        port = int(value)

        if 0 <= port <= 65535:
            return port

    except ValueError:
        pass

    print("Invalid port. Enter an integer between 0 and 65535.")
    return False


def apply_filters(packets):
    """Ask the user for filters and display matching packets."""

    print("\n--- Filter Packets ---")
    print("Leave a field empty to ignore that filter.")

    protocol = input("Protocol (TCP/UDP): ").strip().upper() or None

    if protocol is not None and protocol not in ("TCP", "UDP"):
        print("Invalid protocol. Enter TCP, UDP, or leave it empty.")
        return

    source_ip = get_optional_ip("Source IP: ")

    if source_ip is False:
        return

    destination_ip = get_optional_ip("Destination IP: ")

    if destination_ip is False:
        return

    source_port = get_optional_port("Source port: ")

    if source_port is False:
        return

    destination_port = get_optional_port("Destination port: ")

    if destination_port is False:
        return

    matching_packets = filter_packets(
        packets,
        protocol=protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
    )

    print(f"\nMatching packets: {len(matching_packets)}")
    display_packet_summary(matching_packets)


def inspect_packet(packets):
    """Display detailed information for a selected packet."""

    if not packets:
        print("\nNo packets available. Capture packets first.")
        return

    try:
        number = int(input("Enter the packet number to inspect: "))
    except ValueError:
        print("Invalid packet number.")
        return

    for packet in packets:
        if packet["number"] == number:
            display_packet_details(packet)
            return

    print(f"Packet #{number} was not found.")


def main():
    """Main menu for the Mini Packet Analyzer."""

    packets = []

    while True:
        print("\n" + "=" * 45)
        print("          MINI PACKET ANALYZER")
        print("=" * 45)
        print("1. Capture packets")
        print("2. Display packet summary")
        print("3. Filter packets")
        print("4. Inspect a packet")
        print("5. Exit")

        choice = input("\nEnter your choice (1-5): ").strip()

        if choice == "1":
            new_packets = capture_packets()

            # Number packets continuously across capture sessions.
            next_number = len(packets) + 1

            for packet in new_packets:
                packet["number"] = next_number
                next_number += 1

            packets.extend(new_packets)

        elif choice == "2":
            display_packet_summary(packets)

        elif choice == "3":
            if not packets:
                print("\nNo packets available. Capture packets first.")
            else:
                apply_filters(packets)

        elif choice == "4":
            inspect_packet(packets)

        elif choice == "5":
            print("Exiting Mini Packet Analyzer.")
            break

        else:
            print("Invalid choice. Please enter a number from 1 to 5.")


if __name__ == "__main__":
    main()