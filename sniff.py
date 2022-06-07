import socket
import struct
import os
import binascii
import sys

#################################################################################
# Byte-order transformation functions
# uint32_t htonl(uint32_t hostlong)  host-to-network
# uint16_t htons(uint16_t hostshort) host-to-network
#
# uint32_t ntohl(uint32_t netlong)   network-to-host
# uint16_t ntohs(uint16_t netshort)  network-to-host
#################################################################################
#ETHERNET FRAME
###############
# 0 - 6 = EthDhost (Destination MAC Address)
# 6 - 11 = EthShost (Source MAC Address)
# 12 - 14 = EthType (IP or another Inner protocol being used)
#################################################################################
#IPV4 PACKET
############
# Following bytes goes to the IP headers, then the TCP, and then the Application:
# 0-3 = Version
# 4-7 = IHL
# 8-15 = Type of Service
# 16-31 = Total length
#################################################################################
#TCP-FRAME
##########
##Source port (16 bits)
#Destination port (16 bits)
#Sequence number (32 bits)
#Acknowledgment number (32 bits)
#Data offset (4 bits)
#Reserved (3 bits)
#Flags (9 bits)
#Window size (16 bits)
#Checksum (16 bits)
#Urgent pointer (16 bits)
#Options (Variable 0–320 bits, in units of 32 bits)
#################################################################################


def get_mac(bytes_mac) -> str:
    bytes_str = map('{:02x}'.format, bytes_mac)
    return ':'.join(bytes_str).upper()


def ethernet_frame(raw_data) -> tuple:
    dest_mac, src_mac, proto = struct.unpack("!6s6sH", raw_data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), raw_data[14:]


def ip(addr) -> str:
    return '.'.join(map(str, addr))


def icmp_packet(raw_data) -> tuple:
    icmp_type, code, checksum = struct.unpack('!BBH', raw_data[:4])
    return icmp_type, code, checksum, raw_data[4:]




def main():

    if not os.environ.get("SUDO_UID") and os.geteuid() != 0:
        print ("You need to run this script with sudo or as root.")
        exit(1)

    ETH_FRAME_SIZE = 14
    ETH_PROTCOLS = {'IP': 8}
    IP_PROTOCOLS = {'ICMP': 1, 'TCP': 6, 'UDP': 17}
    UDP_HEADER_LENGTH = 8

    packet_cnt = 0
    output = ""
    filter_ip = '192.168.3.141'
    output_newline = str(">" * 10)+" -- "+str("-" * 160)+"\n"

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    while True:
        try:
            # addr not used but recvfrom returns a tuple
            # 65535 -- max header len
            packet, addr = s.recvfrom(65535)
            packet_cnt += 1
            dest_mac, src_mac, eth_proto, data = ethernet_frame(packet)

            output += f"Packet [{packet_cnt}] "
            indent = len(output)
            output += f">>> Eth frame{'':<{2}}-- src MAC: {src_mac} | dst MAC: {dest_mac} | eth_proto: {eth_proto}\n{'':<{indent}}>>> {output_newline}"

            ipheader = packet[ETH_FRAME_SIZE:34]
            ip_header = struct.unpack('!BBHHHBBH4s4s' , ipheader)
            # ---------------------------------------------------------------
            # -- Version (4 bits) -- unsigned char -- extracted from 1st byte
            # -- IHL (4 bits) -- unsigned char -- extracted from 1st byte
            # -- Type of service (8 bits) -- unsigned short
            # -- Total length (16 bits) -- unsigned short
            # ---------------------------------------------------------------
            # -- ID (16 bits) -- unsigned short
            # -- Flags (3 bits) -- unsigned char -- extracted from 3rd byte
            # -- Fragment offset (13 bits) -- unsigned short
            # ---------------------------------------------------------------
            # -- TTL (8 bits) -- unsigned short
            # -- Protocol (8 bits) -- unsigned short
            # -- Header checksum (16 bits) -- unsigned short
            # ---------------------------------------------------------------
            # -- Source addr (32 bits) -- char[]
            # ---------------------------------------------------------------
            # -- Destination addr (32 bits) -- char[]
            # ---------------------------------------------------------------

            ip_version_ihl = ip_header[0]

            ip_version = ip_version_ihl >> 4
            ip_ihl = ip_version_ihl & 0xF
            ip_h_length = ip_ihl * 4

            ip_tos = ip_header[1]
            ip_len = ip_header[2]
            ip_id = ip_header[3]
            ip_frag_off = ip_header[4]
            ip_ttl = ip_header[5]
            ip_protocol = ip_header[6]
            ip_checksum = ip_header[7]

            ip_id_hex = '0x{:02x}'.format(ip_id)
            ip_checksum_hex = '0x{:02x}'.format(ip_checksum)

            ip_s_addr = socket.inet_ntoa(ip_header[8])
            ip_d_addr = socket.inet_ntoa(ip_header[9])

            if eth_proto == ETH_PROTCOLS["IP"]:
                output += f"{'':<{indent}}>>> " \
                          f"IPv4{'':<{7}}-- " \
                          f"version: {ip_version} | " \
                          f"header len: {ip_h_length} | " \
                          f"ihl: {ip_ihl} | " \
                          f"tos: {ip_tos} | " \
                          f"len: {ip_len} | " \
                          f"id: {ip_id} ({ip_id_hex}) | " \
                          f"flags: | " \
                          f"frag off: {ip_frag_off}\n" \
                          f"{'':<{indent}}{'':<15}-- " \
                          f"ttl: {ip_ttl} | " \
                          f"protocol: {ip_protocol} | " \
                          f"checksum: {ip_checksum} = ({ip_checksum_hex}) | " \
                          f"src: {ip_s_addr} | " \
                          f"dst: {ip_d_addr}\n" \
                          f"{'':<{indent}}>>> {output_newline}" \

        
                if ip_protocol == IP_PROTOCOLS["ICMP"]:
                    icmp_type, code, checksum, data = icmp_packet(ip_data)
                    output += f"{'':<{indent}} >>> ICMP packet: {icmp_type} | {code} | {checksum} | {data}\n"

                elif ip_protocol == IP_PROTOCOLS["TCP"]:
                    tcp_header = packet[ (ip_h_length + ETH_FRAME_SIZE):(ip_h_length + ETH_FRAME_SIZE) + 20 ]
                    tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
                    # -------------------------------------------------------------------
                    # -- Source port (16 bits) -- unsigned short
                    # -- Destination port (16 bits) -- unsigned short
                    # -------------------------------------------------------------------
                    # -- Sequence number (32 bits) -- unsigned long
                    # -------------------------------------------------------------------
                    # -- Acknowledgment number (32 bits) -- unsigned long
                    # -------------------------------------------------------------------
                    # -- Data offset (4 bits) -- unsigned char -- extracted from 1st byte
                    # -- Reserved (3 bits) -- unsigned char -- extracted from 1st byte
                    # -- Flags (9 bits) -- unsigned short
                    # -- Window size (16 bits) -- unsigned short
                    # -------------------------------------------------------------------
                    # -- Checksum (16 bits) -- unsigned short
                    # -- Urgent pointer (16 bits) -- unsigned short
                    # -------------------------------------------------------------------
                    # -- Options (Variable 0–320 bits, in units of 32 bits)
                    # -------------------------------------------------------------------

                    tcp_src_port = tcph[0]
                    tcp_dst_port = tcph[1]
                    tcp_seq = tcph[2]
                    tcp_ack = tcph[3]
                    tcp_data_off_reserved = tcph[4]
                    tcp_flags = tcph[5]
                    tcp_win_size = tcph[6]
                    tcp_checksum = tcph[7]
                    tcp_urg_pointer = tcph[8]

                    tcp_checksumhex = '0x{:02x}'.format(tcp_checksum)
                    tcp_h_length = tcp_data_off_reserved >> 4
                    
                    tcp_flag_urg = (tcp_flags & 0x020) >> 5
                    tcp_flag_ack = (tcp_flags & 0x010) >> 4
                    tcp_flag_psh = (tcp_flags & 0x008) >> 3
                    tcp_flag_rst = (tcp_flags & 0x004) >> 2
                    tcp_flag_syn = (tcp_flags & 0x002) >> 1
                    tcp_flag_fin = (tcp_flags & 0x001) >> 0

                    tcp_h_size = ETH_FRAME_SIZE + ip_h_length + tcp_h_length * 4
                    data_size = len(packet) - tcp_h_size
                    data = packet[tcp_h_size:]

                    if not tcp_src_port or not tcp_dst_port or not data:
                        output = ""
                        continue

                    hex_data = binascii.hexlify(data)
                    bin_data = bin(int(hex_data, 16))[2:].encode()

                    output += f"{'':<{indent}}>>> TCP packet -- " \
                              f"src port: {tcp_src_port} | " \
                              f"dst port: {tcp_dst_port} | " \
                              f"seq: {tcp_seq} | ack: {tcp_ack}\n" \
                              f"{'':<{indent}}{'':<15}" \
                              f"-- flags: " \
                              f"urg: {tcp_flag_urg} | " \
                              f"ack: {tcp_flag_ack} | " \
                              f"psh: {tcp_flag_psh} | " \
                              f"rst: {tcp_flag_rst} | " \
                              f"syn: {tcp_flag_syn} | " \
                              f"fin: {tcp_flag_fin}\n" \
                              f"{'':<{indent}}{'':<15}-- " \
                              f"window size: {tcp_win_size} | " \
                              f"checksum: {tcp_checksum} = ({tcp_checksumhex}) | " \
                              f"header len: {tcp_h_length} | " \
                              f"urg pointer: {tcp_urg_pointer}\n" \
                              f"{'':<{indent}}{'':<15}--\n" \
                              f"{'':<{indent + 3}} Data {'':<6}-- hex: {hex_data[:100]} ...\n" \
                                      f"{'':<{indent}}{'':<15}-- bin: {bin_data[:100]} ...\n" \
                                      f"{'':<{indent}}{'':<15}-- dec: {data[:50]} ...\n" \
                                      f"{'':<{indent}}>>> {output_newline}"

                elif ip_protocol == IP_PROTOCOLS["UDP"]:
                    udp_header = packet[ (ip_h_length + ETH_FRAME_SIZE):(ip_h_length + ETH_FRAME_SIZE) + UDP_HEADER_LENGTH ]
                    udp_h = struct.unpack('!HHHH' , udp_header)
                    
                    udp_source_port = udp_h[0]
                    udp_dest_port = udp_h[1]
                    udp_length = udp_h[2]
                    udp_checksum = udp_h[3]
                    
                    udp_h_size = ETH_FRAME_SIZE + ip_h_length + UDP_HEADER_LENGTH
                    udp_data_size = len(packet) - udp_h_size
                    
                    data = packet[udp_h_size:]
                    hex_data = binascii.hexlify(data)
                    bin_data = bin(int(hex_data, 16))[2:].encode()

                    output += f"{'':<{indent}}>>> UDP packet -- " \
                              f"src port: {str(udp_source_port)} | " \
                              f"dst port: {str(udp_dest_port)} | " \
                              f"header len: {str(udp_length)} | " \
                              f"checksum: {str(udp_checksum)}\n" \
                              f"{'':<{indent}}{'':<15}--\n" \
                              f"{'':<{indent + 3}} Data {'':<6}-- hex: {hex_data[:100]} ...\n" \
                                      f"{'':<{indent}}{'':<15}-- dec: {bin_data[:100]} ...\n" \
                                      f"{'':<{indent}}{'':<15}-- dec: {data[:50]} ...\n" \
                                      f"{'':<{indent}}>>> {output_newline}"
 
                else:
                    output += f"{'':<{indent}}>>> non-TCP/UDP/ICMP packet of protocol: {ip_protocol}\n"

            else:
                # non IPv4 packet
                pass

            # debug: only remote machine traffic
            # if ip_s_addr and ip_d_addr and (ip_s_addr == filter_ip or ip_d_addr == filter_ip):
            print(f"{output}\n")

            output = ""

        except KeyboardInterrupt:
            print("Exiting program..")
            break

    exit(0)


################################

if __name__ == '__main__':
    main()
