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
    # Convert hexadecimal IP address to decimal
    ip_header = packet_data[0].split(":")[1].split()
    print(f"IP header: {ip_header}")
    source_ip_parts = [
        ip_header[6][0:2],
        ip_header[6][2:4],
        ip_header[7][0:2],
        ip_header[7][2:4],
    ]
    source_ip = ".".join(str(int(part, 16)) for part in source_ip_parts)
    print(f"Source IP: {source_ip}")

    ip_header = packet_data[1].split(":")[1].split()
    print(f"IP header: {ip_header}")
    destination_ip_parts = [
        ip_header[0][0:2],
        ip_header[0][2:4],
        ip_header[1][0:2],
        ip_header[1][2:4],
    ]
    destination_ip = ".".join(str(int(part, 16)) for part in destination_ip_parts)
    print(f"Destination IP: {destination_ip}")

    return source_ip, destination_ip


def parse_packet_data(packet_data, option="-i"):
    # First line of each packet contains the IPv4 header
    ip_header = packet_data[0].split(":")[1].split()
    print(f"IP header: {ip_header}")

    source_ip, destination_ip = get_ip_addresses(packet_data)

    # Get the protocol number (6th byte in the IP header)
    protocol = int(ip_header[4], 16)

    # Check the option and apply appropriate filtering rules
    if option == "-i":
        # Egress filtering rule
        if not source_ip.startswith(__SUBNET__) or destination_ip.startswith(
            __SUBNET__
        ):
            return True  # Drop the packet
    elif option == "-j":
        # ICMP filtering rule
        if protocol == 1:  # ICMP protocol
            return True  # Drop the packet

    return False  # Do not drop the packet


def examine_packet_data(packet_data, packet_number):
    if packet_data and parse_packet_data(packet_data):
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
        examine_packet_data(packet_data, packet_number)


if __name__ == "__main__":
    main()
