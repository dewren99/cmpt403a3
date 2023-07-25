import sys

__SUBNET__ = "142.58.22."


def parse_packet_file(filename):
    # Open the file and parse the packets
    with open(filename, "r") as f:
        lines = f.readlines()

    packets = {}
    packet_number = 0
    packet_data = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.isdigit():  # if the line is a packet number
            if packet_data:  # if we have collected some packet data
                packets[packet_number] = packet_data

            # reset packet data and update packet number
            packet_number = int(line)
            packet_data = []
        else:  # if the line is part of the packet data
            packet_data.append(line)

    # Add the last packet
    if packet_data:
        packets[packet_number] = packet_data

    print(f"Total number of packets: {len(packets)}")
    # print(packets)
    for i in packets:
        print(f"Packet {i}: {packets[i]}")
    return packets


def get_ip_addresses(packet_data):
    def parse_ip_address_parts(i):
        return packet_data[i].split(":")[1].split()

    def parse_ip_address(ip_address):
        return ".".join(str(int(part, 16)) for part in ip_address)

    # Convert hexadecimal IP address to decimal
    ip_header = parse_ip_address_parts(0)
    # print(f"IP header: {ip_header}")
    source_ip_parts = [
        ip_header[6][0:2],
        ip_header[6][2:4],
        ip_header[7][0:2],
        ip_header[7][2:4],
    ]
    source_ip = parse_ip_address(source_ip_parts)
    print(f"Source IP: {source_ip}")

    ip_header = parse_ip_address_parts(1)
    # print(f"IP header: {ip_header}")
    destination_ip_parts = [
        ip_header[0][0:2],
        ip_header[0][2:4],
        ip_header[1][0:2],
        ip_header[1][2:4],
    ]
    destination_ip = parse_ip_address(destination_ip_parts)
    print(f"Destination IP: {destination_ip}")

    return source_ip, destination_ip


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
    flags = int(ip_header[3][0], 16)
    print(f"Flags: {flags}")
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
    icmp_header = packet_data[1].split(":")[1].split()[2:]
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
        "flags": flags,
        "fragment_offset": fragment_offset,
        "time_to_live": time_to_live,
        "protocol": protocol,
        "header_checksum": header_checksum,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
    }


def is_ping_attack(icmp_type, icmp_code, protocol, destination_ip):
    return (
        icmp_type == 8
        and icmp_code == 0
        and protocol == 1
        and destination_ip.startswith(__SUBNET__)
    )


def parse_packet_data(packet_data, option):
    packet = get_packet_dict(packet_data)

    # Check the option and apply appropriate filtering rules
    if option == "-i":
        # Egress filtering rule
        if not packet.get("source_ip").startswith(__SUBNET__) or packet.get(
            "destination_ip"
        ).startswith(__SUBNET__):
            return True  # Drop the packet
    elif option == "-j":
        # ICMP filtering rule
        if is_ping_attack(
            packet.get("icmp_type"),
            packet.get("icmp_code"),
            packet.get("protocol"),
            packet.get("destination_ip"),
        ):
            return True

    return False  # Do not drop the packet


def examine_packet_data(packet_data, packet_number, option):
    if packet_data and parse_packet_data(packet_data, option):
        print(f"{packet_number} yes")
    else:
        print(f"{packet_number} no")


def main():
    # Check command line arguments
    if len(sys.argv) != 3:
        print("Usage: python3 filter.py <option> <filename>")
        sys.exit(1)

    option, filename = sys.argv[1], sys.argv[2]

    # Parse the packet file
    packets = parse_packet_file(filename)

    for packet_number, packet_data in packets.items():
        examine_packet_data(packet_data, packet_number, option)


if __name__ == "__main__":
    main()
