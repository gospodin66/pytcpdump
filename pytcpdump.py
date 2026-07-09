#!/bin/python3

import argparse
import binascii
import os
import platform
import socket
import struct
import sys

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

def _ensure_supported_platform():
    if platform.system() != "Linux":
        print("This script is Linux-only and must be run on Linux.")
        raise SystemExit(1)


def _get_interface_ips():
    _ensure_supported_platform()
    result = os.popen("ip a").read()
    ips = []

    for line in result.splitlines():
        if "inet " in line and "scope global" in line:
            ip = line.split()[1].split('/')[0].strip()
            ips.append(ip)

    return ips

class Pytcpdump:

    ETH_FRAME_SIZE = 14
    ETH_PROTCOLS = {'IP': 8}
    IP_PROTOCOLS = {'ICMP': 1, 'TCP': 6, 'UDP': 17}
    UDP_HEADER_LENGTH = 8

    def __init__(self, show_payload=False, interface=None):
        self._packet_count = 0
        self._filter_ips = _get_interface_ips()
        self._show_payload = show_payload
        self._interface = interface
        print(f"Filtering IPs: {self._filter_ips}")
        if self._interface:
            print(f"Interface: {self._interface}")

    def _get_mac(self, bytes_mac) -> str:
        bytes_str = map('{:02x}'.format, bytes_mac)
        return ':'.join(bytes_str).upper()


    def _ethernet_frame(self, raw_data) -> tuple:
        dest_mac, src_mac, proto = struct.unpack("!6s6sH", raw_data[:14])
        return self._get_mac(dest_mac), self._get_mac(src_mac), socket.ntohs(proto), raw_data[14:]


    def _icmp_packet(self, raw_data) -> tuple:
        icmp_type, code, checksum = struct.unpack('!BBH', raw_data[:4])
        return icmp_type, code, checksum, raw_data[4:]

    @staticmethod
    def _format_payload(data: bytes) -> str:
        if not data:
            return "(empty)"

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return f"hex:{binascii.hexlify(data).decode('ascii')}"

        if any(ord(ch) < 32 and ch not in "\t\r\n" for ch in text):
            return f"hex:{binascii.hexlify(data).decode('ascii')}"

        return text.replace("\n", "\\n").replace("\r", "\\r")

    def run(self):
        _ensure_supported_platform()
        if not os.environ.get("SUDO_UID") and os.geteuid() != 0:
            print("You need to run this script with sudo or as root.")
            raise SystemExit(1)

        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        if self._interface:
            try:
                s.bind((self._interface, 0))
            except OSError as exc:
                print(f"Unable to bind to interface {self._interface}: {exc}", file=sys.stderr)
                raise SystemExit(1)
        while True:
            # 65535 -- max header len
            packet, _addr = s.recvfrom(65535)
            self._process_packet(packet)

    
    def _process_packet(self, packet):
        self._packet_count += 1
        dest_mac, src_mac, eth_proto, _ = self._ethernet_frame(packet)

        lines = [f"{BOLD}Packet [{self._packet_count}]{END}"]
        lines.append(f"    {B}ETH{END} src={src_mac} dst={dest_mac} | type={eth_proto}")

        if eth_proto != self.ETH_PROTCOLS["IP"]:
            print("\n".join(lines))
            return

        ipheader = packet[self.ETH_FRAME_SIZE:self.ETH_FRAME_SIZE + 20]
        try:
            ip_header = struct.unpack('!BBHHHBBH4s4s', ipheader)
        except struct.error as e:
            print(f"Error unpacking IP frame: {e.args[::-1]} -- IP header len: {len(ipheader)}\r\nIP header: {ipheader}", file=sys.stderr)
            return

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
        ip_frag_off = ip_flags_frag_off & 0x1FFF

        ip_s_addr = socket.inet_ntoa(ip_header[8])
        ip_d_addr = socket.inet_ntoa(ip_header[9])

        protocol_name = {
            self.IP_PROTOCOLS["ICMP"]: "ICMP",
            self.IP_PROTOCOLS["TCP"]: "TCP",
            self.IP_PROTOCOLS["UDP"]: "UDP",
        }.get(ip_protocol, str(ip_protocol))

        lines.append(
            f"    {B}IP{END} {ip_s_addr} -> {ip_d_addr} | ver={ip_version} ihl={ip_h_length} tos={ip_tos} "
            f"ttl={ip_ttl} id={ip_id} flags={ip_flags} frag={ip_frag_off} checksum={ip_checksum} "
            f"proto={B}{protocol_name}{END}"
        )

        if ip_protocol == self.IP_PROTOCOLS["ICMP"]:
            icmp_type, code, checksum, payload = self._icmp_packet(packet[self.ETH_FRAME_SIZE + ip_h_length:])
            lines.append(f"    {G}ICMP{END} type={icmp_type} code={code} checksum={checksum}")
            if self._show_payload:
                lines.append(f"    {P}PAYLOAD{END} {self._format_payload(payload)}")

        elif ip_protocol == self.IP_PROTOCOLS["TCP"]:
            if len(packet) < ip_h_length + self.ETH_FRAME_SIZE + 20:
                print(f"Packet too short for TCP header: {len(packet)} bytes", file=sys.stderr)
                return

            tcp_header = packet[(ip_h_length + self.ETH_FRAME_SIZE):(ip_h_length + self.ETH_FRAME_SIZE) + 20]
            try:
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            except struct.error as e:
                print(f"Error unpacking TCP header: {e}", file=sys.stderr)
                return

            tcp_src_port = tcph[0]
            tcp_dst_port = tcph[1]
            tcp_seq = tcph[2]
            tcp_ack = tcph[3]
            tcp_flags = tcph[5]
            tcp_win_size = tcph[6]
            tcp_checksum = tcph[7]
            tcp_flag_syn = (tcp_flags & 0x002) >> 1
            tcp_flag_ack = (tcp_flags & 0x010) >> 4
            tcp_flag_fin = (tcp_flags & 0x001) >> 0

            lines.append(
                f"    {G}TCP{END} sport={tcp_src_port} dport={tcp_dst_port} | seq={tcp_seq} ack={tcp_ack} "
                f"flags=SYN:{tcp_flag_syn} ACK:{tcp_flag_ack} FIN:{tcp_flag_fin} "
                f"win={tcp_win_size} cksum={tcp_checksum}"
            )
            if self._show_payload:
                payload = packet[(ip_h_length + self.ETH_FRAME_SIZE) + 20:]
                lines.append(f"    {P}PAYLOAD{END} {self._format_payload(payload)}")

        elif ip_protocol == self.IP_PROTOCOLS["UDP"]:
            if len(packet) < ip_h_length + self.ETH_FRAME_SIZE + self.UDP_HEADER_LENGTH:
                print(f"Packet too short for UDP header: {len(packet)} bytes", file=sys.stderr)
                return

            udp_header = packet[(ip_h_length + self.ETH_FRAME_SIZE):(ip_h_length + self.ETH_FRAME_SIZE) + self.UDP_HEADER_LENGTH]
            try:
                udp_h = struct.unpack('!HHHH', udp_header)
            except struct.error as e:
                print(f"Error unpacking UDP header: {e}", file=sys.stderr)
                return

            udp_source_port = udp_h[0]
            udp_dest_port = udp_h[1]
            udp_length = udp_h[2]
            udp_checksum = udp_h[3]
            lines.append(f"    {G}UDP{END} sport={udp_source_port} dport={udp_dest_port} | len={udp_length} checksum={udp_checksum}")
            if self._show_payload:
                payload = packet[(ip_h_length + self.ETH_FRAME_SIZE) + self.UDP_HEADER_LENGTH:]
                lines.append(f"    {P}PAYLOAD{END} {self._format_payload(payload)}")
        else:
            lines.append(f"    {O}OTHER{END} protocol={ip_protocol}")

        if self._filter_ips and ip_s_addr in self._filter_ips:
            print("\n".join(lines))


def _parse_args():
    parser = argparse.ArgumentParser(description="Capture and print network packets")
    parser.add_argument("--payload", action="store_true", help="Show packet payloads in a readable form")
    parser.add_argument("--interface", dest="interface", help="Capture on the specified network interface")
    return parser.parse_args()


if __name__ == '__main__':
    args = _parse_args()
    try:
        Pytcpdump(show_payload=args.payload, interface=args.interface).run()
    except KeyboardInterrupt:
        print("Exiting program..")
    exit(0)