import socket
import struct
import textwrap

Tab_1 = '\t - '
Tab_2 = '\t\t - '
Tab_3 = '\t\t\t - '
Tab_4 = '\t\t\t\t - '

def main():

    print("Starting packet sniffer...")
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    #conn.bind(('ens33', 0))
    while True:
        try:
            raw_data, addr = conn.recvfrom(65535)
            print("Packet received:")
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print(Tab_1 + "Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))
        except socket.timeout:
            # Socket timeout - no packets received
            print("No packets received within timeout period.")
        except Exception as e:
            # Other exception - print error message and continue
            print("Error receiving packet:", e)
            continue

        # 8 for IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(Tab_1 + "IPv4 Packet:")
            print(Tab_2 + "Version: {}, Header Lenght: {}, TTL: {}".format(version, header_length, ttl))
            print(Tab_2 + 'Protocol: {}, Soucrce: {}, Target: {}'.format(proto, src, target))

            # ICMP 
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(Tab_1 + "ICMP Packet:")
                print(Tab_2 + "Type: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))
                print(Tab_2 + 'Data:')
                print(format_multi_line(Tab_1 + Tab_1 + Tab_1, data))
            
            # TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segement(data)
                print(Tab_1 + "TCP Segment:")
                print(Tab_2 + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                print(Tab_2 + "Sequence: {}, Acknowledgement: {}".format(sequence, acknowledgement))
                print(Tab_2 + 'Flags:')
                print(Tab_2 + Tab_1 + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(Tab_2 + 'Data:')
                print(format_multi_line(Tab_3, data))

            # UDP
            elif proto == 17:
                (scr_port, dest_port, size , data) = udp_segment(data)
                print(Tab_1 + "UDP Segment:")
                print(Tab_2 + "Source Port: {}, Destination Port: {}, Length: {}".format(scr_port, dest_port, size))

            # Other
            else:
                print(Tab_1 + "Data:")
                print(format_multi_line(Tab_2, data))
        else:
            print(Tab_1 + "Data:")
            print(format_multi_line(Tab_1, data))

# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC adderss (i.e AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Returns properly formatted IPv4 address like 127.0.0.1
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks ICMP packets
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP packets
def tcp_segement(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpacks UDP segment
def udp_segment(data):
    scr_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return scr_port, dest_port, size, data[8:]

# Format multi-line data
def format_multi_line(prefix, string, size=80):
    if isinstance(string, bytes):
        string = '.'.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join(prefix + line for line in textwrap.wrap(string, width=size-len(prefix)))

main()