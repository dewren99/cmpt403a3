import sys

HALF_OPEN_CONNECTIONS = {}

__TCP_CONNECTION_KILL_FLAGS__ = ["RST", "FIN"]
__TCP_PROTOCOL__ = 6
__ICMP_PROTOCOL__ = 1

__DROP_PACKAGE__ = True
__ALLOW_PACKAGE__ = False


class IpPacketIO:
    @staticmethod
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


class IpPacketHelper:
    __SUBNET__ = "142.58.22."
    __BROADCAST_IP__ = __SUBNET__ + "255"

    # IP Packet parsing helper functions
    @staticmethod
    def parse_ip_packet_parts(packet, i):
        return packet[i].split(":")[1].split()

    @staticmethod
    def in_subnet(ip_address):
        return ip_address.startswith(IpPacketHelper.__SUBNET__)


class IpHeader:
    def __init__(self, packet_data):
        self.__raw_packet_data = packet_data
        self.parse_packet_ip_header()

    @staticmethod
    def parse_ip_address(ip_address_raw):
        return ".".join(str(int(part, 16)) for part in ip_address_raw)

    def get_ip_addresses(self):
        # Convert hexadecimal IP address to decimal
        ip_header = IpPacketHelper.parse_ip_packet_parts(self.__raw_packet_data, 0)
        # print(f"IP header: {ip_header}")
        source_ip_parts = [
            ip_header[6][0:2],
            ip_header[6][2:4],
            ip_header[7][0:2],
            ip_header[7][2:4],
        ]
        source_ip = self.parse_ip_address(source_ip_parts)
        ip_header = IpPacketHelper.parse_ip_packet_parts(self.__raw_packet_data, 1)
        destination_ip_parts = [
            ip_header[0][0:2],
            ip_header[0][2:4],
            ip_header[1][0:2],
            ip_header[1][2:4],
        ]
        destination_ip = self.parse_ip_address(destination_ip_parts)
        # print(f"Source IP: {source_ip}")
        # print(f"Destination IP: {destination_ip}")

        return source_ip, destination_ip

    # Parse the IP header
    def parse_packet_ip_header(self):
        # First line of each packet contains the IPv4 header
        ip_header = IpPacketHelper.parse_ip_packet_parts(self.__raw_packet_data, 0)

        self.ipv4or6 = int(ip_header[0][0], 16)
        self.header_length = int(ip_header[0][1], 16)
        self.packet_length = int(ip_header[1], 16)
        self.indentifier = int(ip_header[2], 16)
        self.ip_flags = int(ip_header[3][0], 16)
        self.fragment_offset = int(ip_header[3][1:], 16)
        self.time_to_live = int(ip_header[4][0:2], 16)
        self.protocol = int(ip_header[4][2:], 16)
        self.header_checksum = int(ip_header[5], 16)
        # ip_header[6], [7] are source IP address
        # ip_header[8], [9] are destination IP address
        self.source_ip, self.destination_ip = self.get_ip_addresses()


class BitManipulation:
    @staticmethod
    def is_bit_set(x, n):
        """Check if nth bit is set in binary representation of x."""
        return (x & (1 << n)) != 0


class TcpFlag:
    def __init__(self, tcp_flags_field):
        self.__tcp_flags_field = tcp_flags_field
        self.__str = TcpFlag.determine_tcp_flag(self.__tcp_flags_field)

    def __str__(self):
        return self.__str

    def __eq__(self, other):
        return self.__str == str(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.__str)

    def __cmp__(self, other):
        return self.__str == str(other)

    def is_ack(flags):
        return BitManipulation.is_bit_set(flags, 4)

    def is_syn(flags):
        return BitManipulation.is_bit_set(flags, 1)

    def is_rst(flags):
        return BitManipulation.is_bit_set(flags, 2)

    def is_fin(flags):
        return BitManipulation.is_bit_set(flags, 0)

    def is_syn_ack(flags):
        return TcpFlag.is_syn(flags) and TcpFlag.is_ack(flags)

    @staticmethod
    def determine_tcp_flag(tcp_flags):
        if TcpFlag.is_syn_ack(tcp_flags):
            tcp_flag_str = "SYN-ACK"
        elif TcpFlag.is_fin(tcp_flags):
            tcp_flag_str = "FIN"
        elif TcpFlag.is_rst(tcp_flags):
            tcp_flag_str = "RST"
        elif TcpFlag.is_ack(tcp_flags):
            tcp_flag_str = "ACK"
        elif TcpFlag.is_syn(tcp_flags):
            tcp_flag_str = "SYN"
        else:
            tcp_flag_str = None

        return tcp_flag_str


class TcpHeader:
    def __init__(self, packet_data):
        self.__raw_packet_data = packet_data
        tcp_flags_field = IpPacketHelper.parse_ip_packet_parts(
            self.__raw_packet_data, 2
        )[0][2:]
        self.__tcp_flags_field = int(tcp_flags_field, 16)
        self.tcp_flag = TcpFlag(self.__tcp_flags_field)

        self.source_port = int(
            IpPacketHelper.parse_ip_packet_parts(self.__raw_packet_data, 1)[2], 16
        )
        # print(f"Source port: {self.source_port}")
        self.destination_port = int(
            IpPacketHelper.parse_ip_packet_parts(self.__raw_packet_data, 1)[3], 16
        )
        # print(f"Destination port: {self.destination_port}")


class IcmpHeader:
    def __init__(self, packet_data):
        self.__raw_packet_data = packet_data
        self.parse_icmp_header()

    def parse_icmp_header(self):
        icmp_header = IpPacketHelper.parse_ip_packet_parts(self.__raw_packet_data, 1)[
            2:
        ]  # index 0 and 1 are destination IP address (part of IP header), hence [2:]
        print(f"ICMP header: {icmp_header}")
        self.icmp_type = int(icmp_header[0][0:2], 16)
        print(f"ICMP type: {self.icmp_type}")
        self.icmp_code = int(icmp_header[0][2:], 16)
        print(f"ICMP code: {self.icmp_code}")


class IpPacket:
    def __init__(self, packet_data):
        self.__raw_packet_data = packet_data
        self.ip_header = IpHeader(self.__raw_packet_data)
        self.is_tcp_packet = self.ip_header.protocol == __TCP_PROTOCOL__
        self.is_icmp_packet = self.ip_header.protocol == __ICMP_PROTOCOL__

        self.tcp_header = None
        self.icmp_header = None

        if self.is_tcp_packet:
            self.tcp_header = TcpHeader(self.__raw_packet_data)
        elif self.is_icmp_packet:
            self.icmp_header = IcmpHeader(self.__raw_packet_data)


class TcpConnectionKey:
    def __init__(self, source_ip, destination_ip, source_port, destination_port):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.source_port = source_port
        self.destination_port = destination_port

    def __hash__(self):
        return hash(
            (
                self.source_ip,
                self.source_port,
                self.destination_ip,
                self.destination_port,
            )
        )

    def __eq__(self, other):
        return (
            self.source_ip == other.source_ip
            and self.source_port == other.source_port
            and self.destination_ip == other.destination_ip
            and self.destination_port == other.destination_port
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return f"{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}"

    def reverse(self):
        return TcpConnectionKey(
            self.destination_ip,
            self.source_ip,
            self.destination_port,
            self.source_port,
        )


class TcpConnectionState:
    def __init__(self):
        self.__SYN = False
        self.__ACK = False
        self.__SYN_ACK = False

    def __str__(self):
        return f"SYN: {self.__SYN}, SYN-ACK: {self.__SYN_ACK}, ACK: {self.__ACK}"

    def update_state(self, tcp_flag_str, current_connection_key):
        if tcp_flag_str == "SYN":
            self.__SYN = True
        elif tcp_flag_str == "SYN-ACK" and TcpHandsake.we_can_send_syn_ack_because_we_recieved_syn(current_connection_key):
            self.__SYN_ACK = True
        elif tcp_flag_str == "ACK" and TcpHandsake.we_can_send_ack_because_we_recieved_syn_ack(current_connection_key):
            self.__ACK = True
        return __ALLOW_PACKAGE__

    def get_SYN(self):
        return self.__SYN

    def get_SYN_ACK(self):
        return self.__SYN_ACK
    
    def get_ACK(self):
        return self.__ACK


class TcpConnection:
    """
    __TCP_CONNECTIONS__ = {
        TcpConnectionKey: TcpConnectionState
    }
    """

    __TCP_CONNECTIONS__ = {}
    
    @staticmethod
    def print_connections():
        for key, state in TcpConnection.__TCP_CONNECTIONS__.items():
            print(f"{key} -> {state}")

    @staticmethod
    def get_keys_by_source_ip_address(source_ip):
        return list(
            filter(
                lambda key: key.source_ip == source_ip,
                TcpConnection.__TCP_CONNECTIONS__.keys(),
            )
        )

    @staticmethod
    def get_or_create_connection_state(connection_key):
        connection_state = TcpConnection.__TCP_CONNECTIONS__.get(connection_key, None)
        if connection_state is None:
            connection_state = TcpConnectionState()
            TcpConnection.__TCP_CONNECTIONS__[connection_key] = connection_state
        return connection_state

    @staticmethod
    def close_connection(connection_key):
        TcpConnection.__TCP_CONNECTIONS__.pop(connection_key, None)

    @staticmethod
    def add_packet_to_connections(packet):
        if not packet.is_tcp_packet:
            print(f"Cannot add non-TCP packet to connection: {packet}")
            return __DROP_PACKAGE__

        connection_key = TcpConnectionKey(
            packet.ip_header.source_ip,
            packet.ip_header.destination_ip,
            packet.tcp_header.source_port,
            packet.tcp_header.destination_port,
        )

        tcp_flag = packet.tcp_header.tcp_flag
        if tcp_flag in __TCP_CONNECTION_KILL_FLAGS__:
            TcpConnection.close_connection(connection_key)
            return __ALLOW_PACKAGE__

        connection_state = TcpConnection.get_or_create_connection_state(connection_key)

        if tcp_flag == "SYN":
            if connection_state.get_SYN():
                return __DROP_PACKAGE__
            if connection_state.get_SYN_ACK():
                return __DROP_PACKAGE__

        if not TcpConnectionPolicyEnforcer.can_add_packet_to_connection(connection_key, tcp_flag):
            return __DROP_PACKAGE__

        print(f"Connection state: {connection_state} for {connection_key}")


        return connection_state.update_state(tcp_flag, connection_key)

class TcpHandsake:
    @staticmethod
    def we_can_send_syn_ack_because_we_recieved_syn(interigator_connection_key):
        interigated_connection_key = interigator_connection_key.reverse()
        connection_state = TcpConnection.get_or_create_connection_state(interigated_connection_key)
        return connection_state.get_SYN()

    @staticmethod
    def we_can_send_ack_because_we_recieved_syn_ack(interigator_connection_key):
        interigated_connection_key = interigator_connection_key.reverse()
        connection_state = TcpConnection.get_or_create_connection_state(interigated_connection_key)
        print(f"current key: {interigator_connection_key}, reverse key: {interigated_connection_key} and reverse connection state: {connection_state}")
        return connection_state.get_SYN_ACK()



class TcpConnectionPolicyEnforcer:
    @staticmethod
    def must_obey_throttle_policy(connection_key):
        source_ip_is_outside_subnet = not IpPacketHelper.in_subnet(connection_key.source_ip)
        destination_ip_is_in_subnet = IpPacketHelper.in_subnet(connection_key.destination_ip)
        return source_ip_is_outside_subnet and destination_ip_is_in_subnet

    @staticmethod
    def get_full_connection_count(connection_key, ignore_ports = True):
        if not ignore_ports:
            return 1 if TcpConnection.get_or_create_connection_state(connection_key).get_ACK() else 0
        connection_keys = TcpConnection.get_keys_by_source_ip_address(connection_key.source_ip)
        throttled_keys = list(filter(TcpConnectionPolicyEnforcer.must_obey_throttle_policy, connection_keys))
        count = 0
        for key in throttled_keys:
            connection_state = TcpConnection.get_or_create_connection_state(key)
            if connection_state.get_ACK():
                count += 1
        return count

    @staticmethod
    def get_half_open_connection_count(connection_key, ignore_ports = True):
        if not ignore_ports:
            return 1 if TcpConnection.get_or_create_connection_state(connection_key).get_SYN() or TcpConnection.get_or_create_connection_state(connection_key).get_SYN_ACK() else 0
        connection_keys = TcpConnection.get_keys_by_source_ip_address(connection_key.source_ip)
        throttled_keys = list(filter(TcpConnectionPolicyEnforcer.must_obey_throttle_policy, connection_keys))
        count = 0
        for key in throttled_keys:
            connection_state = TcpConnection.get_or_create_connection_state(key)
            if connection_state.get_SYN() or connection_state.get_SYN_ACK():
                print(f"throtled key: {key}")
                count += 1
        return count

    @staticmethod
    def throttled_address_is_at_max_half_open_connections(connection_key):
        count = TcpConnectionPolicyEnforcer.get_half_open_connection_count(connection_key)
        print(f"Half open connections: {count}")
        return count >= 10

    @staticmethod
    def tcp_ports_are_inuse(connection_key):
        '''Only one TCP connection, whether half-open or fully open, can exist at a time
        between two TCP ports. Any attempt to open a new connection between two
        TCP ports while a connection already exists will be completely ignored by the
        application without affecting the current connection.'''
        open_connection_count = TcpConnectionPolicyEnforcer.get_full_connection_count(connection_key, False) + TcpConnectionPolicyEnforcer.get_half_open_connection_count(connection_key, False)
        return open_connection_count > 0

    @staticmethod
    def can_add_packet_to_connection(connection_key, incoming_tcp_flag):
        is_new_connection_request = incoming_tcp_flag == "SYN"
        ports_are_inuse = TcpConnectionPolicyEnforcer.tcp_ports_are_inuse(connection_key)
        at_max_half_open_connections = TcpConnectionPolicyEnforcer.throttled_address_is_at_max_half_open_connections(connection_key)
        print(f"Ports are in use: {ports_are_inuse}")
        print(f"At max half open connections: {at_max_half_open_connections}")
        return not (ports_are_inuse and is_new_connection_request) and not at_max_half_open_connections


def is_ping_attack(icmp_type, icmp_code, protocol, destination_ip):
    return (
        icmp_type == 8
        and icmp_code == 0
        and protocol == 1
        and destination_ip == IpPacketHelper.__BROADCAST_IP__
    )



def process_packet_data(packet_data, option):
    packet = IpPacket(packet_data)

    ip_header = packet.ip_header
    tcp_header = packet.tcp_header
    icmp_header = packet.icmp_header
    is_tcp_packet = packet.is_tcp_packet
    is_icmp_packet = packet.is_icmp_packet


    if is_tcp_packet:
        connection_type = f"TCP({tcp_header.tcp_flag})"
        print(f"Processing connection: [{connection_type}] {packet.ip_header.source_ip}:{packet.tcp_header.source_port} -> {packet.ip_header.destination_ip}:{packet.tcp_header.destination_port}")
    elif is_icmp_packet:
        print(f"Processing connection: [ICMP] {packet.ip_header.source_ip} -> {packet.ip_header.destination_ip}")

    # Check the option and apply appropriate filtering rules
    if option == "-i":
        # Egress filtering rule
        if not IpPacketHelper.in_subnet(
            ip_header.source_ip
            ) or IpPacketHelper.in_subnet(
            ip_header.destination_ip
            ):
            return __DROP_PACKAGE__  # Drop the packet
    elif option == "-j":
        # ICMP filtering rule
        if is_icmp_packet and is_ping_attack(
            icmp_header.icmp_type,
            icmp_header.icmp_code,
            ip_header.protocol,
            ip_header.destination_ip,
        ):
            return __DROP_PACKAGE__
    elif option == "-k" and is_tcp_packet:
        # TODO: check protocol == 6 and flag == 18?
        return TcpConnection.add_packet_to_connections(packet)

    return __ALLOW_PACKAGE__  # Do not drop the packet


def examine_packet_data(packet_data, packet_number, option):
    if packet_data and process_packet_data(packet_data, option):
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
    packets = IpPacketIO.parse_packet_file(filename)

    for packet_number, packet_data in packets.items():
        examine_packet_data(packet_data, packet_number, option)
    
    TcpConnection.print_connections()


if __name__ == "__main__":
    main()
