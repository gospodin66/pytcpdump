#!/bin/python3

import argparse
import binascii
import ipaddress
import os
import platform
import re
import struct
import string
import socket
import sys
import time

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
INDENT = " " * 4

# Protocols constants
ICMP = "ICMP"
IP = "IP"
TCP = "TCP"
UDP = "UDP"

# init regex for expresions parser
_EXPR = re.compile(r"""
^\s*
(?P<op>!=|>=|<=|>|<|=)?
\s*
(?P<value>.+?)
\s*$
""", re.X)


def _ensure_supported_platform():
    if platform.system() != "Linux":
        print("This script is Linux-only and must be run on Linux.")
        raise SystemExit(1)
    
    
def parse_filter(expr):
    m = _EXPR.match(expr)
    if not m:
        raise ValueError(f"Invalid filter expression: {expr}")

    op = m.group("op") or "="
    value = m.group("value").strip()

    # Normalize string values (protocol names, etc.)
    if isinstance(value, str):
        value = value.upper()

    # Port range: 1000-2000
    if (
        op == "="
        and value.count("-") == 1
        and all(part.isdigit() for part in value.split("-"))
    ):
        lo, hi = map(int, value.split("-", 1))

        if lo > hi:
            raise ValueError(f"Invalid range: {expr}")

        return ("range", lo, hi)

    # Numeric values
    if value.isdigit():
        value = int(value)

    return (op, value)


def match_expr(value, expr):
    op = expr[0]

    if op == "=":
        return value == expr[1]

    if op == ">":
        return value > expr[1]

    if op == "<":
        return value < expr[1]

    if op == ">=":
        return value >= expr[1]

    if op == "<=":
        return value <= expr[1]

    if op == "range":
        return expr[1] <= value <= expr[2]

    return False


def _parse_args():
    parser = argparse.ArgumentParser(description="Capture and print network packets")

    parser.add_argument(
        "--interface",
        dest="interface",
        help="Capture on the specified network interface"
    )

    parser.add_argument(
        "--ip",
        action="append",
        default=[],
        metavar="EXPR",
        help="IP filter: 192.168.1.10, !=10.0.0.1"
    )

    parser.add_argument(
        "--payload",
        action="store_true",
        help="Show packet payloads in a readable form"
    )

    parser.add_argument(
        "--port",
        action="append",
        default=[],
        metavar="EXPR",
        help="Port filter: 80, !=22, >1024, >=1024, <=53, 1000-2000"
    )

    parser.add_argument(
        "--protocol",
        action="append",
        default=[],
        metavar="EXPR",
        help="Protocol filter: TCP, UDP, ICMP, !=UDP"
    )


    parser.add_argument(
        "--pcap",
        metavar="FILE",
        help="Write captured packets to a PCAP file"
    )
    

    parser.add_argument(
        "--resolve",
        action="store_true",
        help="Resolve IP addresses to hostnames"
    )

    return parser.parse_args()


class Pytcpdump:
    ETH_FRAME_SIZE = 14
    ETH_PROTOCOLS = {IP: 8}
    IP_PROTOCOLS = {ICMP: 1, TCP: 6, UDP: 17}
    UDP_HEADER_LENGTH = 8

    def __init__(
        self,
        show_payload=False,
        interface=None,
        filter_ips=None,
        filter_ports=None,
        filter_protocols=None,
        pcap_file=None,
        resolve_hosts=False,
    ):
        self._dns_cache = {}
        
        self._packet_total = 0
        self._packet_displayed = 0
        self._packet_count = 0
        
        self._pcap = None
        self._pcap_file = pcap_file

        self._resolve_hosts = resolve_hosts
        self._show_payload = show_payload

        self._interface = interface
        if self._interface:
            print(f"Interface: {self._interface}")

        # port filtering
        self._port_include = []
        self._port_exclude = []
        for f in filter_ports or []:
            expr = parse_filter(f)
            if expr[0] == "!=":
                self._port_exclude.append(expr)
            else:
                self._port_include.append(expr)

        # ip filtering
        self._ip_include = []
        self._ip_exclude = []
        for f in filter_ips or []:
            expr = parse_filter(f)
            if expr[0] == "!=":
                self._ip_exclude.append(expr)
            else:
                self._ip_include.append(expr)

        # protocol filtering
        self._proto_include = []
        self._proto_exclude = []
        for f in filter_protocols or []:
            expr = parse_filter(f.upper())
            if expr[0] == "!=":
                self._proto_exclude.append(expr)
            else:
                self._proto_include.append(expr)


    def _get_mac(self, bytes_mac) -> str:
        bytes_str = map('{:02x}'.format, bytes_mac)
        return ':'.join(bytes_str).upper()


    def _ethernet_frame(self, raw_data) -> tuple:
        dest_mac, src_mac, proto = struct.unpack("!6s6sH", raw_data[:14])
        return self._get_mac(dest_mac), self._get_mac(src_mac), socket.ntohs(proto), raw_data[14:]


    def _icmp_packet(self, raw_data) -> tuple:
        icmp_type, code, checksum = struct.unpack('!BBH', raw_data[:4])
        return icmp_type, code, checksum, raw_data[4:]


    def run(self):
        _ensure_supported_platform()

        if not os.environ.get("SUDO_UID") and os.geteuid() != 0:
            print("You need to run this script with sudo or as root.")
            raise SystemExit(1)

        s = None

        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

            if self._interface:
                try:
                    s.bind((self._interface, 0))
                except OSError as exc:
                    print(
                        f"Unable to bind to interface {self._interface}: {exc}",
                        file=sys.stderr
                    )
                    raise SystemExit(1)

            if self._pcap_file:
                self._open_pcap(self._pcap_file)

            while True:
                packet, _addr = s.recvfrom(65535)
                self._process_packet(packet)
                self._write_pcap(packet)

        finally:
            if self._pcap:
                self._pcap.close()

            if s:
                s.close()

    
    def _process_packet(self, packet):
        self._packet_total += 1
        _dest_mac, _src_mac, eth_proto, _ = self._ethernet_frame(packet)

        # Ignore everything except IPv4
        if eth_proto != self.ETH_PROTOCOLS[IP]:
            # =================================================
            # TODO: add support for other protocols:
            # =================================================
            # EtherType	Protocol	Common?
            # 0x0806	ARP	Very common (IP ↔ MAC resolution)
            # 0x86DD	IPv6	Very common on modern networks
            # 0x8100	VLAN tagged frame	Enterprise networks
            # 0x88CC	LLDP	Switch discovery
            # 0x888E	802.1X	Network authentication
            # 0x0842	Wake-on-LAN	Occasionally
            # others	Vendor-specific protocols	Rare
            #
            return

        self._packet_count += 1
        lines = []
        #lines.append(f"{INDENT}{B}ETH{END} src={src_mac} dst={dest_mac} | type={eth_proto}")

        ipheader = packet[self.ETH_FRAME_SIZE:self.ETH_FRAME_SIZE + 20]
        try:
            ip_header = struct.unpack('!BBHHHBBH4s4s', ipheader)
        except struct.error as e:
            print(
                f"Error unpacking IP frame: {e.args[::-1]} -- "
                f"IP header len: {len(ipheader)}\r\nIP header: {ipheader}",
                file=sys.stderr
            )
            return

        ip_version_ihl = ip_header[0]
        ip_tos = ip_header[1]
        _ip_len = ip_header[2]
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

        #protocol_name = {
        #    self.IP_PROTOCOLS[ICMP]: ICMP,
        #    self.IP_PROTOCOLS[TCP]: TCP,
        #    self.IP_PROTOCOLS[UDP]: UDP,
        #}.get(ip_protocol, str(ip_protocol))

        lines.append(
            f"{INDENT}{B}IP{END} "
            f"{self._format_ip(ip_s_addr)} -> "
            f"{self._format_ip(ip_d_addr)} | "
            f"ver={ip_version} "
            f"ihl={ip_h_length} "
            f"tos={ip_tos} "
            f"ttl={ip_ttl} "
            f"id={ip_id} "
            f"flags={ip_flags} "
            f"frag={ip_frag_off} "
            f"checksum={ip_checksum} "
            #f"proto={B}{protocol_name}{END}"
        )

        if ip_protocol == self.IP_PROTOCOLS[ICMP]:

            icmp_type, code, checksum, payload = self._icmp_packet(
                packet[self.ETH_FRAME_SIZE + ip_h_length:]
            )

            if not self._packet_matches_filters(ip_s_addr, ip_d_addr, ICMP):
                return

            lines.append(f"{INDENT}{G}ICMP{END} type={icmp_type} code={code} checksum={checksum}")

            if self._show_payload:
                lines.append(f"{INDENT}{P}PAYLOAD{END} {self._format_payload(payload)}")

        elif ip_protocol == self.IP_PROTOCOLS[TCP]:

            if len(packet) < self.ETH_FRAME_SIZE + ip_h_length + 20:
                print(f"Packet too short for TCP header: {len(packet)} bytes", file=sys.stderr)
                return

            tcp_header = packet[self.ETH_FRAME_SIZE + ip_h_length: self.ETH_FRAME_SIZE + ip_h_length + 20]

            try:
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            except struct.error as e:
                print(f"Error unpacking TCP header: {e}", file=sys.stderr)
                return

            tcp_src_port = tcph[0]
            tcp_dst_port = tcph[1]

            if not self._packet_matches_filters(
                ip_s_addr,
                ip_d_addr,
                TCP,
                tcp_src_port,
                tcp_dst_port
            ):
                return

            tcp_seq = tcph[2]
            tcp_ack = tcph[3]
            tcp_flags = tcph[5]
            tcp_win_size = tcph[6]
            tcp_checksum = tcph[7]

            tcp_flag_syn = (tcp_flags & 0x002) >> 1
            tcp_flag_ack = (tcp_flags & 0x010) >> 4
            tcp_flag_fin = tcp_flags & 0x001

            lines.append(
                f"{INDENT}{G}TCP{END} sport={tcp_src_port} "
                f"dport={tcp_dst_port} | "
                f"seq={tcp_seq} ack={tcp_ack} "
                f"flags=SYN:{tcp_flag_syn} "
                f"ACK:{tcp_flag_ack} FIN:{tcp_flag_fin} "
                f"win={tcp_win_size} cksum={tcp_checksum}"
            )

            if self._show_payload:
                payload = packet[
                    self.ETH_FRAME_SIZE + ip_h_length + 20:
                ]
                lines.append(f"{INDENT}{P}PAYLOAD{END} {self._format_payload(payload)}")

        elif ip_protocol == self.IP_PROTOCOLS[UDP]:

            if len(packet) < self.ETH_FRAME_SIZE + ip_h_length + self.UDP_HEADER_LENGTH:
                print(
                    f"Packet too short for UDP header: {len(packet)} bytes",
                    file=sys.stderr
                )
                return

            udp_header = packet[
                self.ETH_FRAME_SIZE + ip_h_length:
                self.ETH_FRAME_SIZE + ip_h_length + self.UDP_HEADER_LENGTH
            ]

            try:
                udp_h = struct.unpack('!HHHH', udp_header)
            except struct.error as e:
                print(f"Error unpacking UDP header: {e}", file=sys.stderr)
                return

            udp_source_port = udp_h[0]
            udp_dest_port = udp_h[1]

            if not self._packet_matches_filters(
                ip_s_addr,
                ip_d_addr,
                UDP,
                udp_source_port,
                udp_dest_port
            ):
                return

            udp_length = udp_h[2]
            udp_checksum = udp_h[3]

            lines.append(
                f"{INDENT}{G}UDP{END} sport={udp_source_port} "
                f"dport={udp_dest_port} | "
                f"len={udp_length} checksum={udp_checksum}"
            )

            if self._show_payload:
                payload = packet[
                    self.ETH_FRAME_SIZE + ip_h_length + self.UDP_HEADER_LENGTH:
                ]
                lines.append(f"{INDENT}{P}PAYLOAD{END} {self._format_payload(payload)}")

        else:
            lines.append(f"{INDENT}{O}OTHER{END} protocol={ip_protocol}")


        self._packet_displayed += 1

        lines.insert(0, f"{BOLD}Packet [{self._packet_displayed}] ({self._packet_total}){END}")
        print("\n".join(lines), flush=True)


    def _resolve_ip(self, ip):
        """
        Resolve an IP address to a hostname using reverse DNS.
        Results are cached to avoid repeated lookups.
        """
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            return ip
        
        if not self._resolve_hosts:
            return ip

        if ip in self._dns_cache:
            return self._dns_cache[ip]

        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            self._dns_cache[ip] = hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            self._dns_cache[ip] = ip
        except Exception:
            self._dns_cache[ip] = ip

        return self._dns_cache[ip]


    def _format_ip(self, ip):
        """
        Returns:
            8.8.8.8 (dns.google)
        or
            192.168.1.15
        """
        if not self._resolve_hosts:
            return ip

        hostname = self._resolve_ip(ip)

        if hostname == ip:
            return ip

        return f"{ip} ({hostname})"


    def _packet_matches_filters(
        self,
        src_ip,
        dst_ip,
        protocol,
        src_port=None,
        dst_port=None
    ):
        return (
            self._match_protocol(protocol)
            and self._match_ips(src_ip, dst_ip)
            and self._match_ports(src_port, dst_port)
        )
    

    def _match_ports(self, src_port, dst_port):

        # reject excluded ports
        for expr in self._port_exclude:
            if src_port == expr[1] or dst_port == expr[1]:
                return False

        if not self._port_include:
            return True

        for expr in self._port_include:
            if match_expr(src_port, expr):
                return True
            if match_expr(dst_port, expr):
                return True

        return False


    def _match_ips(self, src_ip, dst_ip):

        for expr in self._ip_exclude:
            if src_ip == expr[1] or dst_ip == expr[1]:
                return False

        if not self._ip_include:
            return True

        for expr in self._ip_include:
            if match_expr(src_ip, expr):
                return True
            if match_expr(dst_ip, expr):
                return True

        return False


    def _match_protocol(self, proto):

        proto = proto.upper()

        for expr in self._proto_exclude:
            if proto == expr[1]:
                return False

        if not self._proto_include:
            return True

        for expr in self._proto_include:
            if match_expr(proto, expr):
                return True

        return False


    def _open_pcap(self, filename):
        self._pcap = open(filename, "wb")

        # Global PCAP header
        self._pcap.write(struct.pack(
            "<IHHIIII",
            0xA1B2C3D4,   # magic
            2,            # version major
            4,            # version minor
            0,            # timezone
            0,            # sigfigs
            65535,        # snaplen
            1             # LINKTYPE_ETHERNET
        ))

        
    def _write_pcap(self, packet):
        if self._pcap is None:
            return

        now = time.time()

        sec = int(now)
        usec = int((now - sec) * 1_000_000)

        length = len(packet)

        self._pcap.write(struct.pack(
            "<IIII",
            sec,
            usec,
            length,
            length
        ))

        self._pcap.write(packet)


    @staticmethod
    def _format_payload(data: bytes) -> str:
        if not data:
            return "(empty)"

        hex_data = f"hex:{binascii.hexlify(data).decode('ascii')}"

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return hex_data

        # Reject control characters (except whitespace)
        if any(ord(ch) < 32 and ch not in "\t\r\n" for ch in text):
            return hex_data

        # Require most bytes to be printable ASCII
        printable = sum(ch.isprintable() or ch in "\t\r\n" for ch in text)
        ratio = printable / len(text)

        if ratio <= 0.9:
            return hex_data

        return f'plain: {text.replace("\n", "\\n").replace("\r", "\\r")}'


if __name__ == '__main__':
    args = _parse_args()
    try:
        Pytcpdump(
            show_payload=args.payload,
            interface=args.interface,
            filter_ips=args.ip,
            filter_ports=args.port,
            filter_protocols=args.protocol,
            resolve_hosts=args.resolve,
            pcap_file=args.pcap,
        ).run()
    except KeyboardInterrupt:
        print("Exiting program..")
    exit(0)