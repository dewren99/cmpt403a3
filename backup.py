def get_packet_dict(packet_data):
    # First line of each packet contains the IPv4 header
    ip_header = packet_data[0].split(":")[1].split()
    # print(f"IP header: {ip_header}")

    ipv4or6 = int(ip_header[0][0], 16)
    print(f"IPv{ipv4or6}")
    header_length = int(ip_header[0][1], 16)
    print(f"Header length: {header_length}")
    packet_length = int(ip_header[1], 16)
    print(f"Packet length: {packet_length}")
    indentifier = int(ip_header[2], 16)
    print(f"Indentifier: {indentifier}")
    ip_flags = int(ip_header[3][0], 16)
    print(f"Flags: {ip_flags}")
    fragment_offset = int(ip_header[3][1:], 16)
    print(f"Fragment offset: {fragment_offset}")
    time_to_live = int(ip_header[4][0:2], 16)
    print(f"Time to live: {time_to_live}")
    # Get the protocol number (6th byte in the IP header)
    protocol = int(ip_header[4][2:], 16)
    print(f"Protocol: {protocol}")
    header_checksum = int(ip_header[5], 16)
    print(f"Header checksum: {header_checksum}")
    # ip_header[6], [7] are source IP address
    # ip_header[8], [9] are destination IP address
    icmp_header = (
        packet_data[1].split(":")[1].split()[2:]
    )  # 0 and 1 are destination IP address
    print(f"ICMP header: {icmp_header}")
    icmp_type = int(icmp_header[0][0:2], 16)
    print(f"ICMP type: {icmp_type}")
    icmp_code = int(icmp_header[0][2:], 16)
    print(f"ICMP code: {icmp_code}")
    source_ip, destination_ip = get_ip_addresses(packet_data)
    print(f"Source IP: {source_ip}")
    print(f"Destination IP: {destination_ip}")

    return {
        "ipv4or6": ipv4or6,
        "header_length": header_length,
        "packet_length": packet_length,
        "indentifier": indentifier,
        "ip_flags": ip_flags,
        "tcp_flags": tcp_flags,
        "tcp_flag_str": tcp_flag_str,
        "fragment_offset": fragment_offset,
        "time_to_live": time_to_live,
        "protocol": protocol,
        "header_checksum": header_checksum,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
    }
