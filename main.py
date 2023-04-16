import socket
import struct
import textwrap

def main():

    print("Starting packet sniffer...")
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    #conn.bind(('ens33', 0))

    while True:
        try:
            raw_data, addr = conn.recvfrom(65535)
            print("Packet received:")
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print("Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))
        except socket.timeout:
            # Socket timeout - no packets received
            print("No packets received within timeout period.")
        except Exception as e:
            # Other exception - print error message and continue
            print("Error receiving packet:", e)
            continue

# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC adderss (i.e AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


main()