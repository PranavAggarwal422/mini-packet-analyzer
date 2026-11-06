import ipaddress
import struct


def parse_ipv4(raw_data):
    """
    Parse an IPv4 header directly from raw packet bytes.

    No automatic packet-decoding library is used.
    """

    # An IPv4 header must contain at least 20 bytes.
    if len(raw_data) < 20:
        raise ValueError("Packet is too short for an IPv4 header")

    # The first byte contains the version and IHL.
    version_ihl = raw_data[0]

    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    header_length = ihl * 4

    if version != 4:
        raise ValueError("Packet is not IPv4")

    if ihl < 5:
        raise ValueError("Invalid IPv4 header length")

    if len(raw_data) < header_length:
        raise ValueError("Truncated IPv4 header")

    # Extract fields using their byte offsets.
    total_length = struct.unpack_from("!H", raw_data, 2)[0]
    identification = struct.unpack_from("!H", raw_data, 4)[0]

    flags_fragment = struct.unpack_from("!H", raw_data, 6)[0]
    flags = (flags_fragment >> 13) & 0b111
    fragment_offset = flags_fragment & 0x1FFF

    ttl = raw_data[8]
    protocol_number = raw_data[9]

    checksum = struct.unpack_from("!H", raw_data, 10)[0]

    source_ip = str(
        ipaddress.IPv4Address(raw_data[12:16])
    )

    destination_ip = str(
        ipaddress.IPv4Address(raw_data[16:20])
    )

    if total_length < header_length:
        raise ValueError("Invalid IPv4 total length")

    if total_length > len(raw_data):
        raise ValueError("Captured data is shorter than the IPv4 total length")

    protocol_names = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }

    return {
        "version": version,
        "header_length": header_length,
        "total_length": total_length,
        "identification": identification,
        "flags": flags,
        "fragment_offset": fragment_offset,
        "ttl": ttl,
        "protocol_number": protocol_number,
        "protocol": protocol_names.get(
            protocol_number,
            f"Other ({protocol_number})"
        ),
        "checksum": checksum,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "header_bytes": raw_data[:header_length],
    }

def parse_tcp(raw_data, offset, ip_payload_length):
    """
    Parse a TCP header from raw packet bytes.

    offset: position where the TCP header begins.
    ip_payload_length: IPv4 payload length, including TCP header.
    """

    if ip_payload_length < 20:
        raise ValueError("IPv4 payload is too short for a TCP header")

    if len(raw_data) < offset + 20:
        raise ValueError("Truncated TCP header")

    # First four bytes: source and destination ports.
    source_port, destination_port = struct.unpack_from(
        "!HH", raw_data, offset
    )

    # Next eight bytes: sequence and acknowledgment numbers.
    sequence_number, acknowledgment_number = struct.unpack_from(
        "!II", raw_data, offset + 4
    )

    # Data offset occupies the upper four bits of byte 12.
    data_offset = raw_data[offset + 12]
    header_length = (data_offset >> 4) * 4

    if header_length < 20:
        raise ValueError("Invalid TCP header length")

    if header_length > ip_payload_length:
        raise ValueError("TCP header exceeds IPv4 payload length")

    if len(raw_data) < offset + header_length:
        raise ValueError("Truncated TCP header or TCP options")

    # TCP flags are the low six bits of byte 13.
    flags_byte = raw_data[offset + 13]

    flag_values = {
        "URG": 0x20,
        "ACK": 0x10,
        "PSH": 0x08,
        "RST": 0x04,
        "SYN": 0x02,
        "FIN": 0x01,
    }

    flags = [
        name
        for name, mask in flag_values.items()
        if flags_byte & mask
    ]

    window_size, checksum = struct.unpack_from(
        "!HH", raw_data, offset + 14
    )

    payload_length = ip_payload_length - header_length

    return {
        "source_port": source_port,
        "destination_port": destination_port,
        "sequence_number": sequence_number,
        "acknowledgment_number": acknowledgment_number,
        "header_length": header_length,
        "flags": flags,
        "window_size": window_size,
        "checksum": checksum,
        "payload_length": payload_length,
    }

def parse_udp(raw_data, offset, ip_payload_length):
    """
    Parse a UDP header from raw packet bytes.

    offset: position where the UDP header begins.
    ip_payload_length: IPv4 payload length, including UDP header.
    """

    if ip_payload_length < 8:
        raise ValueError("IPv4 payload is too short for a UDP header")

    if len(raw_data) < offset + 8:
        raise ValueError("Truncated UDP header")

    source_port, destination_port, udp_length, checksum = (
        struct.unpack_from("!HHHH", raw_data, offset)
    )

    if udp_length < 8:
        raise ValueError("Invalid UDP length")

    if udp_length > ip_payload_length:
        raise ValueError("UDP length exceeds IPv4 payload length")

    payload_length = udp_length - 8

    return {
        "source_port": source_port,
        "destination_port": destination_port,
        "length": udp_length,
        "checksum": checksum,
        "payload_length": payload_length,
    }


def parse_packet(raw_data):
    """
    Parse an entire captured IPv4 packet.

    The IPv4, TCP, and UDP headers are parsed manually.
    """

    ip_info = parse_ipv4(raw_data)

    ip_header_length = ip_info["header_length"]
    total_length = ip_info["total_length"]
    protocol_number = ip_info["protocol_number"]

    # Ignore any trailing bytes outside the IPv4 packet.
    packet_data = raw_data[:total_length]

    # The IPv4 payload excludes the IPv4 header.
    ip_payload_length = total_length - ip_header_length

    result = {
        "ip": ip_info,
        "transport": None,
        "payload": b"",
        "packet_length": total_length,
        "analysis_status": "complete",
    }

    # A non-initial IPv4 fragment does not begin with a
    # TCP or UDP header.
    if ip_info["fragment_offset"] != 0:
        result["analysis_status"] = "non_initial_fragment"
        return result

    transport_offset = ip_header_length

    if protocol_number == 6:
        transport_info = parse_tcp(
            packet_data,
            transport_offset,
            ip_payload_length,
        )

        transport_header_length = transport_info["header_length"]

    elif protocol_number == 17:
        transport_info = parse_udp(
            packet_data,
            transport_offset,
            ip_payload_length,
        )

        transport_header_length = 8

    else:
        # Other IPv4 protocols are not decoded as TCP or UDP.
        return result

    payload_offset = transport_offset + transport_header_length

    if protocol_number == 17:
        # UDP length can be smaller than the IPv4 payload
        # when extra bytes follow the UDP datagram.
        payload_end = transport_offset + transport_info["length"]
    else:
        payload_end = total_length

    payload = packet_data[payload_offset:payload_end]

    # Preserve the exact payload bytes.
    result["transport"] = transport_info
    result["payload"] = payload

    return result

