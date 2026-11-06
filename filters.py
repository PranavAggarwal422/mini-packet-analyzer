def filter_packets(
    packets,
    protocol=None,
    source_ip=None,
    destination_ip=None,
    source_port=None,
    destination_port=None,
):
    """
    Filter packets using any combination of supported criteria.

    String comparisons for protocol and IP addresses are
    case-insensitive. Port comparisons are numeric.
    """

    filtered = []

    for packet in packets:
        parsed = packet["parsed"]
        ip_info = parsed["ip"]
        transport = parsed["transport"]

        if protocol is not None:
            if ip_info["protocol"].upper() != protocol.upper():
                continue

        if source_ip is not None:
            if ip_info["source_ip"] != source_ip:
                continue

        if destination_ip is not None:
            if ip_info["destination_ip"] != destination_ip:
                continue

        if source_port is not None or destination_port is not None:
            # Packets without a decoded TCP/UDP header
            # cannot match port filters.
            if transport is None:
                continue

        if source_port is not None:
            if transport["source_port"] != source_port:
                continue

        if destination_port is not None:
            if transport["destination_port"] != destination_port:
                continue

        filtered.append(packet)

    return filtered
