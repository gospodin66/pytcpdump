#!/bin/python3

import socket
import struct
import os
import binascii
import logging
import platform
import json
from geolocator.geolocation import GeoLocation
from database.database import Database

if platform.system() == "Windows":
    from scapy.all import sniff as scapy_sniff, IP, ICMP, TCP, UDP

# Byte-order transformation functions:
# uint32_t htonl(uint32_t hostlong)  >>> host-to-network
# uint16_t htons(uint16_t hostshort) >>> host-to-network
# uint32_t ntohl(uint32_t netlong)   >>> network-to-host
# uint16_t ntohs(uint16_t netshort)  >>> network-to-host

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray
BOLD = '\033[1m'
END = '\033[0m'

logging.basicConfig(
    filename='./log.log',
    filemode='a',
    format='[%(asctime)s] [module %(module)s] line: %(lineno)d - %(levelname)s :: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.DEBUG
)

geo_location = GeoLocation()
db = Database()  # Initialize the database connection

class sniff:

    ETH_FRAME_SIZE = 14
    ETH_PROTCOLS = {'IP': 8}
    IP_PROTOCOLS = {'ICMP': 1, 'TCP': 6, 'UDP': 17}
    UDP_HEADER_LENGTH = 8

    packet_cnt = 0
    detected_sources = list()

    json_file = 'sources.json'

    filter_ips = [
        '10.5.0.2',
        '192.168.56.1',
        '192.168.5.192',
        # <add-adapter-ip>
    ]
    output_newline = str(">" * 10)+" -- "+str("-" * 90)+"\n"

    def get_mac(self, bytes_mac) -> str:
        bytes_str = map('{:02x}'.format, bytes_mac)
        return ':'.join(bytes_str).upper()


    def ethernet_frame(self, raw_data) -> tuple:
        dest_mac, src_mac, proto = struct.unpack("!6s6sH", raw_data[:14])
        return self.get_mac(dest_mac), self.get_mac(src_mac), socket.htons(proto), raw_data[14:]


    def ip(self, addr) -> str:
        return '.'.join(map(str, addr))


    def icmp_packet(self, raw_data) -> tuple:
        icmp_type, code, checksum = struct.unpack('!BBH', raw_data[:4])
        return icmp_type, code, checksum, raw_data[4:]


    def init(self):
        if platform.system() == "Windows":
            scapy_sniff(prn=self.process_packet_windows, store=0)
        else:
            if not os.environ.get("SUDO_UID") and os.geteuid() != 0:
                print("You need to run this script with sudo or as root.")
                exit(1)
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            while True:
                # 65535 -- max header len
                packet, _addr = s.recvfrom(65535)
                self.process_packet(packet)

    
    def process_packet(self, packet):
        self.packet_cnt += 1
        dest_mac, src_mac, eth_proto, data = self.ethernet_frame(packet)

        output = f"Packet [{self.packet_cnt}] "
        indent = len(output)
        output += f">>> Eth frame{'':<{2}}-- " \
                f"src MAC: {B}{src_mac}{END} | " \
                f"dst MAC: {B}{dest_mac}{END} | " \
                f"eth_proto: {eth_proto}\n" \
                f"{'':<{indent}}>>> {self.output_newline}"

        ipheader = packet[self.ETH_FRAME_SIZE:34]
        try:
            ip_header = struct.unpack('!BBHHHBBH4s4s' , ipheader)
        except struct.error as e:
            logging.error(f"Error unpacking IP frame: {e.args[::-1]} -- IP header len: {len(ipheader)}\r\nIP header: {ipheader}")
            return
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
        ip_tos = ip_header[1]
        ip_len = ip_header[2]
        ip_id = ip_header[3]
        ip_flags_frag_off = ip_header[4]
        ip_ttl = ip_header[5]
        ip_protocol = ip_header[6]
        ip_checksum = ip_header[7]

        ip_version = ip_version_ihl >> 4
        ip_ihl = ip_version_ihl & 0xF
        ip_h_length = ip_ihl * 4

        ip_flags = ip_flags_frag_off >> 13
        ip_frag_off = ip_flags_frag_off & 0x1FF

        ip_id_hex = '0x{:02x}'.format(ip_id)
        ip_checksum_hex = '0x{:02x}'.format(ip_checksum)

        ip_s_addr = socket.inet_ntoa(ip_header[8])
        ip_d_addr = socket.inet_ntoa(ip_header[9])

        geo_location.process_ips(ip_s_addr, ip_d_addr)

        if eth_proto == self.ETH_PROTCOLS["IP"]:
            output += f"{'':<{indent}}>>> " \
                    f"IPv4{'':<{7}}-- " \
                    f"version: {ip_version} | " \
                    f"header len: {ip_h_length} | " \
                    f"ihl: {ip_ihl} | " \
                    f"tos: {ip_tos} | " \
                    f"len: {ip_len} | " \
                    f"id: {ip_id} ({ip_id_hex}) | " \
                    f"flags: {str(ip_flags)} = {format(ip_flags, '#04x')} | " \
                    f"frag off: {ip_frag_off}\n" \
                    f"{'':<{indent}}{'':<15}-- " \
                    f"ttl: {ip_ttl} | " \
                    f"protocol: {ip_protocol} | " \
                    f"checksum: {ip_checksum} = ({ip_checksum_hex}) | " \
                    f"src: {B}{ip_s_addr}{END} | " \
                    f"dst: {B}{ip_d_addr}{END}\n" \
                    f"{'':<{indent}}>>> {self.output_newline}" \
    
            if ip_protocol == self.IP_PROTOCOLS["ICMP"]:
                icmp_type, code, checksum, data = self.icmp_packet(data)
                output += f"{'':<{indent}}>>> ICMP packet: {icmp_type} | {code} | {checksum} | {data}\n"

            elif ip_protocol == self.IP_PROTOCOLS["TCP"]:
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
                tcp_header = packet[ (ip_h_length + self.ETH_FRAME_SIZE):(ip_h_length + self.ETH_FRAME_SIZE) + 20 ]
                tcph = struct.unpack('!HHLLBBHHH' , tcp_header)

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

                tcp_h_size = self.ETH_FRAME_SIZE + ip_h_length + tcp_h_length * 4
                data_size = len(packet) - tcp_h_size
                data = packet[tcp_h_size:]

                if not tcp_src_port or not tcp_dst_port or not data:
                    output = ""
                    return

                hex_data = binascii.hexlify(data)
                bin_data = bin(int(hex_data, 16))[2:].encode()

                output += f"{'':<{indent}}>>> TCP packet -- " \
                        f"src port: {B}{tcp_src_port}{END} | " \
                        f"dst port: {B}{tcp_dst_port}{END} | " \
                        f"seq: {tcp_seq} | ack: {tcp_ack}\n" \
                        f"{'':<{indent}}{'':<15}" \
                        f"-- flags: " \
                        f"urg: {O}{tcp_flag_urg}{END} | " \
                        f"ack: {O}{tcp_flag_ack}{END} | " \
                        f"psh: {O}{tcp_flag_psh}{END} | " \
                        f"rst: {O}{tcp_flag_rst}{END} | " \
                        f"syn: {O}{tcp_flag_syn}{END} | " \
                        f"fin: {O}{tcp_flag_fin}{END}\n" \
                        f"{'':<{indent}}{'':<15}-- " \
                        f"window size: {tcp_win_size} | " \
                        f"checksum: {tcp_checksum} = ({tcp_checksumhex}) | " \
                        f"header len: {tcp_h_length} | " \
                        f"urg pointer: {tcp_urg_pointer}\n" \
                        f"{'':<{indent}}{'':<15}--\n" \
                        f"{'':<{indent + 3}} Data {'':<6}-- hex: {hex_data}\n" \
                                f"{'':<{indent}}{'':<15}-- dec: {data}\n" \
                                f"{'':<{indent}}>>> {self.output_newline}"

            elif ip_protocol == self.IP_PROTOCOLS["UDP"]:
                udp_header = packet[ (ip_h_length + self.ETH_FRAME_SIZE):(ip_h_length + self.ETH_FRAME_SIZE) + self.UDP_HEADER_LENGTH ]
                udp_h = struct.unpack('!HHHH' , udp_header)
                
                udp_source_port = udp_h[0]
                udp_dest_port = udp_h[1]
                udp_length = udp_h[2]
                udp_checksum = udp_h[3]
                
                udp_h_size = self.ETH_FRAME_SIZE + ip_h_length + self.UDP_HEADER_LENGTH
                udp_data_size = len(packet) - udp_h_size
                
                data = packet[udp_h_size:]
                hex_data = binascii.hexlify(data)
                bin_data = bin(int(hex_data, 16))[2:].encode()

                output += f"{'':<{indent}}>>> UDP packet -- " \
                        f"src port: {B}{str(udp_source_port)}{END} | " \
                        f"dst port: {B}{str(udp_dest_port)}{END} | " \
                        f"header len: {str(udp_length)} | " \
                        f"checksum: {str(udp_checksum)}\n" \
                        f"{'':<{indent}}{'':<15}--\n" \
                        f"{'':<{indent + 3}} Data {'':<6}-- hex: {hex_data}\n" \
                                f"{'':<{indent}}{'':<15}-- dec: {data}\n" \
                                f"{'':<{indent}}>>> {self.output_newline}"

            else:
                output += f"{'':<{indent}}>>> non-TCP/UDP/ICMP packet of protocol: {ip_protocol}\n"

        else:
            # non IPv4 packet
            pass

        # debug: only remote machine traffic
        if self.filter_ips:
            if ip_s_addr in self.filter_ips:
                print(f"{output}\n")

        output = ""


    def process_packet_windows(self, packet):
        self.packet_cnt += 1
        if IP not in packet:
            return

        ip_header = packet[IP]

        output = f"Packet [{self.packet_cnt}] "
        indent = len(output)
        output += f">>> IPv4{'':<{7}}-- " \
                f"src: {ip_header.src} | " \
                f"dst: {ip_header.dst}\n" \
                f"{'':<{indent}}>>> {self.output_newline}"

        geo_location.process_ips(ip_header.src, ip_header.dst)

        if ip_header.proto == 1 and ICMP in packet:
            icmp_type = packet[ICMP].type
            code = packet[ICMP].code
            checksum = packet[ICMP].chksum
            data = packet[ICMP].payload
            output += f"{'':<{indent}}>>> ICMP packet: {icmp_type} | {code} | {checksum} | {data}\n"

        elif ip_header.proto == 6 and TCP in packet:
            tcp_header = packet[TCP]
            tcp_src_port = tcp_header.sport
            tcp_dst_port = tcp_header.dport
            tcp_seq = tcp_header.seq
            tcp_ack = tcp_header.ack
            tcp_flags = tcp_header.flags
            tcp_win_size = tcp_header.window
            tcp_checksum = tcp_header.chksum
            tcp_urg_pointer = tcp_header.urgptr
            data = tcp_header.payload

            output += f"{'':<{indent}}>>> TCP packet -- " \
                    f"src port: {tcp_src_port} | " \
                    f"dst port: {tcp_dst_port} | " \
                    f"seq: {tcp_seq} | ack: {tcp_ack}\n" \
                    f"{'':<{indent}}{'':<15}" \
                    f"-- flags: {tcp_flags} | " \
                    f"window size: {tcp_win_size} | " \
                    f"checksum: {tcp_checksum} | " \
                    f"urg pointer: {tcp_urg_pointer}\n" \
                    f"{'':<{indent}}{'':<15}--\n" \
                    f"{'':<{indent + 3}} Data {'':<6}-- {data}\n" \
                    f"{'':<{indent}}>>> {self.output_newline}"

        elif ip_header.proto == 17 and UDP in packet:
            udp_header = packet[UDP]
            udp_source_port = udp_header.sport
            udp_dest_port = udp_header.dport
            udp_length = udp_header.len
            udp_checksum = udp_header.chksum
            data = udp_header.payload

            output += f"{'':<{indent}}>>> UDP packet -- " \
                    f"src port: {udp_source_port} | " \
                    f"dst port: {udp_dest_port} | " \
                    f"header len: {udp_length} | " \
                    f"checksum: {udp_checksum}\n" \
                    f"{'':<{indent}}{'':<15}--\n" \
                    f"{'':<{indent + 3}} Data {'':<6}-- {data}\n" \
                    f"{'':<{indent}}>>> {self.output_newline}"

        else:
            output += f"{'':<{indent}}>>> non-TCP/UDP/ICMP packet of protocol: {ip_header.proto}\n"

        if self.filter_ips:
            if ip_header.src in self.filter_ips:
                print(f"{output}\n")

        output = ""


    def append_to_json(self, sources):
        
        try:
            with open(self.json_file, 'r') as file:
                data = json.load(file)
        except FileNotFoundError:
            data = []

        for source in sources:
            if source not in data:
                data.append(source)

        with open(self.json_file, 'w') as file:
            json.dump(data, file, indent=4)

    def insert_current_host_as_source(self, host_ip):
        geo_location = GeoLocation()
        host_location = geo_location.get_location(host_ip)
        db.insert_current_host_as_source(
            host_ip=host_location["ip"],
            host_city=host_location["city"],
            host_country=host_location["country"],
            host_lat=host_location["lat"],
            host_lon=host_location["lon"]
        )


def start_sniff():
    sniffer = sniff()
    sniffer.insert_current_host_as_source("2.58.74.17")  # Insert current host as source
    sniffer.init()

if __name__ == '__main__':
    try:
        start_sniff()
    except KeyboardInterrupt:
        print("Exiting program..")
    exit(0)
