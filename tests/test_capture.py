import sys
import pydivert


def main():
    print("Mini Packet Analyzer - Capture Test")
    print("-" * 40)
    print(f"PyDivert version: {getattr(pydivert, '__version__', 'unknown')}")

    packet_count = 0

    try:
        # Observe outbound and inbound IPv4 packets.
        # Do not modify or intentionally block traffic.
        with pydivert.WinDivert(
            "ip and (outbound or inbound)",
            layer=pydivert.Layer.NETWORK,
            flags=pydivert.Flag.SNIFF,
        ) as capture:
            print("Capture started successfully.")
            print("Generate normal network traffic on your computer.")
            print("Press Ctrl+C to stop.\n")

            for packet in capture:
                packet_count += 1

                # Use the raw bytes, not decoded protocol-header fields.
                raw_data = bytes(packet.raw)

                print(
                    f"Packet #{packet_count} | "
                    f"Size: {len(raw_data)} bytes | "
                    f"First bytes: {raw_data[:16].hex(' ').upper()}"
                )

    except KeyboardInterrupt:
        print(f"\nCapture stopped. Packets observed: {packet_count}")

    except Exception as exc:
        print(f"\nCapture failed: {type(exc).__name__}: {exc}")
        print(
            "\nCheck whether WinDivert is available and whether "
            "the terminal has the required permissions."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
