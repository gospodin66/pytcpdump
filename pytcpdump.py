#!/bin/python3

import argparse
import binascii
from dataclasses import dataclass
import ipaddress
import os
import platform
import re
import struct
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
ARP = "ARP"
ICMP = "ICMP"
ICMPV6 = "ICMPV6"
TCP = "TCP"
UDP = "UDP"
IPV4 = "IPV4"
IPV6 = "IPV6"
VLAN = "VLAN"
LLDP = "LLDP"
DOT1X = "DOT1X"
WOL = "WOL"

######################
MAX_PACKET_LEN = 65535

# Initialize regex for expresions parser
_EXPR = re.compile(r"""
^\s*
(?P<op>!=|>=|<=|>|<|=)?
\s*
(?P<value>.+?)
\s*$
""", re.X)


#
# Global helpers
#
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
        "--frame",
        action="append",
        default=[],
        metavar="EXPR",
        help="Frame type: ETH2, 802.3, !=802.3"
    )

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





@dataclass
class PacketInfo:
    packet: bytes

    frame: str | None = None

    src_ip: str | None = None
    dst_ip: str | None = None

    src_port: int | None = None
    dst_port: int | None = None

    protocol: str | None = None
    payload: bytes = b""

    layers: list[str] = None

    def __post_init__(self):
        if self.layers is None:
            self.layers = []





@dataclass
class EthernetFrame:
    dst: str
    src: str
    field: int
    payload: bytes
    ethernet2: bool


class PcapError(Exception):
    pass


class Pytcpdump:
    ETH_PROTOCOLS: dict[str, int] = {
        IPV4: 0x0800,
        ARP: 0x0806,
        VLAN: 0x8100,
        IPV6: 0x86DD,
        LLDP: 0x88CC,
        DOT1X: 0x888E,
        WOL: 0x0842,
    }
    IP_PROTOCOLS: dict[str, int] = {
        ICMP: 1, 
        TCP: 6, 
        UDP: 17,
        ICMPV6: 58,
    }


    def __init__(
        self,
        show_payload=False,
        interface=None,
        filter_frames=None,
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

        # frame filtering
        self._frame_include = []
        self._frame_exclude = []
        for f in filter_frames or []:
            expr = parse_filter(f.upper())

            if expr[0] == "!=":
                self._frame_exclude.append(expr)
            else:
                self._frame_include.append(expr)


    def run(self) -> None:
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
                    print(f"Unable to bind to interface {self._interface}: {exc}", file=sys.stderr)
                    raise SystemExit(1)

            if self._pcap_file:
                self._open_pcap(self._pcap_file)

            # Listener loop
            while True:
                packet, _addr = s.recvfrom(MAX_PACKET_LEN)
                self._process_packet(packet)
                self._write_pcap(packet)

        except OSError as exc:
            print(f"I/O error: {exc}", file=sys.stderr)
            raise SystemExit(1)

        except PcapError as exc:
            print(f"PCAP error: {exc}", file=sys.stderr)
            raise SystemExit(1)
            
        finally:
            if self._pcap:
                self._pcap.close()
            if s:
                s.close()


    def _process_packet(self, packet):
        self._packet_total += 1
        info = PacketInfo(packet)
        self._process_ethernet(info)
        self._print_packet(info)


    def _print_packet(self, info):
        if not info.layers:
            return

        self._packet_displayed += 1
        print(f"{BOLD}[{self._packet_displayed}/{self._packet_total}]{END} " + " | ".join(info.layers))


    def _process_802_3(self, info, length, payload):
        info.layers.append(f"{B}802.3{END} len={length}")
        self._process_llc(info, payload)


    def _process_ethernet(self, info):
        try:
            frame = self._ethernet_frame(info.packet)
            frame_name = "ETH2" if frame.ethernet2 else "802.3"
            if not self._match_frame(frame_name):
                return
        except ValueError as exc:
            info.layers.append(f"{R}BAD ETH{END} {exc}")
            return

        #
        # IEEE 802.3 (length field)
        #
        if not frame.ethernet2:
            info.layers.append(f"{C}802.3{END} src={frame.src} dst={frame.dst} len={frame.field}")
            self._process_802_3(info, frame.field, frame.payload)
            return

        #
        # Ethernet II
        #
        ethertype = frame.field
        info.layers.append(f"{B}ETH{END} {frame.src}->{frame.dst} type=0x{ethertype:04x}")

        handlers = {
            self.ETH_PROTOCOLS[IPV4]: self._process_ipv4,
            self.ETH_PROTOCOLS[ARP]: self._process_arp,
            self.ETH_PROTOCOLS[IPV6]: self._process_ipv6,
            self.ETH_PROTOCOLS[VLAN]: self._process_vlan,
            self.ETH_PROTOCOLS[LLDP]: self._process_lldp,
            self.ETH_PROTOCOLS[DOT1X]: self._process_dot1x,
            self.ETH_PROTOCOLS[WOL]: self._process_wol,
        }

        handler = handlers.get(ethertype)

        if handler is None:
            info.layers.append(f"{O}UNKNOWN ETH{END} type=0x{ethertype:04x}")
            return

        handler(info, frame.payload)


    def _ethernet_frame(self, raw_data) -> EthernetFrame:
        if len(raw_data) < 14:
            raise ValueError("short Ethernet frame")

        field = struct.unpack("!H", raw_data[12:14])[0]

        return EthernetFrame(
            dst=self._get_mac(raw_data[:6]),
            src=self._get_mac(raw_data[6:12]),
            field=field,
            payload=raw_data[14:],
            ethernet2=(field >= 0x0600),
        )


    def _match_frame(self, frame):

        frame = frame.upper()

        for expr in self._frame_exclude:
            if frame == expr[1]:
                return False

        if not self._frame_include:
            return True

        for expr in self._frame_include:
            if match_expr(frame, expr):
                return True

        return False


    def _process_transport(self, info, protocol, payload):
        handlers = {
            self.IP_PROTOCOLS.get(TCP): self._process_tcp,
            self.IP_PROTOCOLS.get(UDP): self._process_udp,
            self.IP_PROTOCOLS.get(ICMP): self._process_icmp,
        }
        handler = handlers.get(protocol)

        if handler is None:
            info.layers.append(f"{O}OTHER{END} protocol={protocol}")
            return

        handler(info, payload)




    #
    # ----- Data-link layer (Layer 2) -----
    #
    def _process_arp(self, info, data):
        if len(data) < 28:
            return
        
        (
            hw_type,
            proto_type,
            hw_len,
            proto_len,
            opcode,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip
        ) = struct.unpack(
            "!HHBBH6s4s6s4s",
            data[:28]
        )

        sender_mac = self._get_mac(sender_mac)
        target_mac = self._get_mac(target_mac)

        sender_ip = socket.inet_ntoa(sender_ip)
        target_ip = socket.inet_ntoa(target_ip)

        info.layers.append(f"{C}ARP{END} opcode={opcode} {sender_ip} ({sender_mac}) -> {target_ip} ({target_mac})")


    def _process_vlan(self, info, data):
        if len(data) < 4:
            return

        tci, ethertype = struct.unpack("!HH", data[:4])

        vlan = tci & 0x0FFF
        pcp = (tci >> 13) & 7
        dei = (tci >> 12) & 1

        info.layers.append(
            f"{G}VLAN{END} "
            f"id={vlan} "
            f"pcp={pcp} "
            f"dei={dei}"
        )

        payload = data[4:]
        handlers = {
            self.ETH_PROTOCOLS[IPV4]: self._process_ipv4,
            self.ETH_PROTOCOLS[ARP]: self._process_arp,
            self.ETH_PROTOCOLS[IPV6]: self._process_ipv6,
        }

        handler = handlers.get(ethertype)

        if handler:
            handler(info, payload)
        else:
            info.layers.append(
                f"Unknown VLAN EtherType 0x{ethertype:04x}"
            )


    def _process_snap(self, info, data):
        if len(data) < 5:
            return

        oui = data[:3]
        ethertype = struct.unpack("!H", data[3:5])[0]
        payload = data[5:]

        info.layers.append(
            f"{G}SNAP{END} "
            f"oui={oui.hex(':')} "
            f"type=0x{ethertype:04x}"
        )

        handlers = {
            self.ETH_PROTOCOLS[IPV4]: self._process_ipv4,
            self.ETH_PROTOCOLS[ARP]: self._process_arp,
            self.ETH_PROTOCOLS[IPV6]: self._process_ipv6,
            self.ETH_PROTOCOLS[VLAN]: self._process_vlan,
            self.ETH_PROTOCOLS[LLDP]: self._process_lldp,
            self.ETH_PROTOCOLS[DOT1X]: self._process_dot1x,
            self.ETH_PROTOCOLS[WOL]: self._process_wol,
        }

        handler = handlers.get(ethertype)

        if handler:
            handler(info, payload)
        else:
            info.layers.append(f"Unknown SNAP EtherType 0x{ethertype:04x}")


    def _process_llc(self, info, payload):

        if len(payload) < 3:
            return

        dsap, ssap, ctrl = struct.unpack("!BBB", payload[:3])

        info.layers.append(
            f"LLC "
            f"dsap=0x{dsap:02x} "
            f"ssap=0x{ssap:02x} "
            f"ctrl=0x{ctrl:02x}"
        )

        if (dsap, ssap, ctrl) == (0x42, 0x42, 0x03):
            info.layers.append(f"{G}STP{END}")
            return

        if (dsap, ssap, ctrl) == (0xAA, 0xAA, 0x03):
            self._process_snap(info, payload[3:])
            return

        info.layers.append(
            f"Unknown LLC protocol"
        )


    def _process_lldp(self, info, data):

        info.layers.append(f"{G}LLDP{END}")

        offset = 0

        while offset + 2 <= len(data):

            tlv = struct.unpack("!H", data[offset:offset+2])[0]

            tlv_type = tlv >> 9
            tlv_len = tlv & 0x1FF

            offset += 2

            if offset + tlv_len > len(data):
                break

            value = data[offset:offset+tlv_len]

            if tlv_type == 0:
                break

            elif tlv_type == 1:
                info.layers.append(f"{INDENT*2}Chassis ID")

            elif tlv_type == 2:
                info.layers.append(f"{INDENT*2}Port ID")

            elif tlv_type == 3:
                ttl = struct.unpack("!H", value)[0]
                info.layers.append(f"{INDENT*2}TTL={ttl}")

            elif tlv_type == 5:
                try:
                    info.layers.append(
                        f"{INDENT*2}System={value.decode(errors='ignore')}"
                    )
                except:
                    pass

            offset += tlv_len


    def _process_dot1x(self, info, data):

        if len(data) < 4:
            return

        version, packet_type, length = struct.unpack(
            "!BBH",
            data[:4]
        )

        info.layers.append(
            f"{G}802.1X{END} "
            f"version={version} "
            f"type={packet_type} "
            f"len={length}"
        )


    def _process_wol(self, info, data):

        info.layers.append(f"{G}Wake-on-LAN{END}")

        if data.startswith(b"\xff"*6):
            info.layers.append(f"{INDENT*2}Magic Packet")




    #
    # ----- Network layer (Layer 3) -----
    #
    def _process_ipv4(self, info, data):

        if len(data) < 20:
            return

        header = struct.unpack("!BBHHHBBH4s4s", data[:20])

        version_ihl = header[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0x0f
        header_len = ihl * 4
        total_length = header[2]

        if len(data) < header_len:
            return
        
        if version != 4:
            return

        if ihl < 5:
            return

        src = socket.inet_ntoa(header[8])
        dst = socket.inet_ntoa(header[9])

        flags_fragment = header[4]
        protocol = header[6]
        proto_name = self.IP_PROTOCOLS.get(protocol, protocol)

        info.src_ip = src
        info.dst_ip = dst

        info.layers.append(f"{C}IPv4{END} {self._format_ip(src)}->{self._format_ip(dst)} ttl={header[5]} id={header[3]} proto={proto_name}")

        if total_length > len(data):
            return

        payload = data[header_len:total_length]
        
        flags = flags_fragment >> 13
        fragment_offset = flags_fragment & 0x1FFF
        more_fragments = bool(flags & 0x1)

        if fragment_offset or more_fragments:
            info.layers.append(f"IPv4 fragmented")
            return

        self._process_transport(info, protocol, payload)


    def _process_icmp(self, info, payload):
        if len(payload) < 4:
            return

        icmp_type, code, checksum = struct.unpack("!BBH", payload[:4])
        info.protocol = ICMP

        if not self._packet_matches_filters(info.src_ip, info.dst_ip, info.protocol):
            info.layers.clear()
            return

        info.layers.append(f"{G}ICMP{END} type={icmp_type} code={code} checksum={checksum}")

        if self._show_payload:
            info.layers.append(f"{P}PAYLOAD{END} {self._format_payload(payload[4:])}")


    def _process_ipv6(self, info, data):
        if len(data) < 40:
            return

        (
            version_tc_fl,
            payload_length,
            next_header,
            hop_limit,
            src,
            dst,
        ) = struct.unpack("!IHBB16s16s", data[:40])

        version = version_tc_fl >> 28
        if version != 6:
            return

        src_ip = socket.inet_ntop(socket.AF_INET6, src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, dst)

        info.src_ip = src_ip
        info.dst_ip = dst_ip

        info.layers.append(
            f"{C}IPv6{END} "
            f"{self._format_ip(src_ip)} -> "
            f"{self._format_ip(dst_ip)} "
            f"hop={hop_limit} "
            f"next={next_header}"
        )

        if len(data) < 40 + payload_length:
            return

        payload = data[40:40 + payload_length]

        #
        # Common extension headers
        #
        extension_headers = {
            0,   # Hop-by-Hop
            43,  # Routing
            44,  # Fragment
            50,  # ESP
            51,  # AH
            60,  # Destination Options
        }

        while next_header in extension_headers:

            if len(payload) < 2:
                return

            new_next = payload[0]
            hdr_len = (payload[1] + 1) * 8

            if len(payload) < hdr_len:
                return

            next_header = new_next
            payload = payload[hdr_len:]

        if next_header == 58:
            self._process_icmpv6(info, payload)
        else:
            self._process_transport(info, next_header, payload)


    def _process_icmpv6(self, info, payload):
        if len(payload) < 4:
            return

        icmp_type, code, checksum = struct.unpack("!BBH", payload[:4])

        info.protocol = "ICMPV6"

        if not self._packet_matches_filters(
            info.src_ip,
            info.dst_ip,
            info.protocol
        ):
            info.layers.clear()
            return

        names = {
            1: "Destination Unreachable",
            2: "Packet Too Big",
            3: "Time Exceeded",
            4: "Parameter Problem",

            128: "Echo Request",
            129: "Echo Reply",

            133: "Router Solicitation",
            134: "Router Advertisement",
            135: "Neighbor Solicitation",
            136: "Neighbor Advertisement",
            137: "Redirect",
        }

        info.layers.append(
            f"{G}ICMPv6{END} "
            f"type={icmp_type}"
            f" ({names.get(icmp_type, 'Unknown')}) "
            f"code={code} "
            f"checksum=0x{checksum:04x}"
        )

        if self._show_payload:
            info.layers.append(
                f"{P}PAYLOAD{END} "
                f"{self._format_payload(payload[4:])}"
            )



    #
    # ----- Transport layer (Layer 4) -----
    #
    def _process_tcp(self, info, payload):
        if len(payload) < 20:
            return

        tcph = struct.unpack(
            "!HHLLBBHHH",
            payload[:20]
        )

        src_port = tcph[0]
        dst_port = tcph[1]

        info.src_port = src_port
        info.dst_port = dst_port
        info.protocol = TCP

        if not self._packet_matches_filters(
            info.src_ip,
            info.dst_ip,
            info.protocol,
            src_port,
            dst_port
        ):
            info.layers.clear()
            return

        flags = tcph[5]

        names = (
            (0x01, "FIN"),
            (0x02, "SYN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x10, "ACK"),
            (0x20, "URG"),
            (0x40, "ECE"),
            (0x80, "CWR"),
        )

        flag_str = ",".join(name for bit, name in names if flags & bit)

        if not flag_str:
            flag_str = "NONE"

        info.layers.append(
            f"{G}TCP{END} "
            f"{src_port}->{dst_port} "
            f"seq={tcph[2]} "
            f"ack={tcph[3]} "
            f"{flag_str}"
        )

        data_offset = (tcph[4] >> 4) * 4
        if data_offset < 20 or data_offset > len(payload):
            return
        
        app = payload[data_offset:]

        if self._show_payload:
            info.layers.append(f"{P}PAYLOAD{END} {self._format_payload(app)}")

        self._process_application(info, app)


    def _process_udp(self, info, payload):
        if len(payload) < 8:
            return

        src_port, dst_port, length, checksum = struct.unpack("!HHHH", payload[:8])

        info.src_port = src_port
        info.dst_port = dst_port
        info.protocol = UDP

        if not self._packet_matches_filters(
            info.src_ip,
            info.dst_ip,
            info.protocol,
            src_port,
            dst_port
        ):
            info.layers.clear()
            return

        info.layers.append(
            f"{G}UDP{END} "
            f"{src_port}->{dst_port} "
            f"len={length}"
        )

        app = payload[8:]

        if self._show_payload:
            info.layers.append(
                f"{P}PAYLOAD{END} "
                f"{self._format_payload(app)}"
            )

        self._process_application(info, app)



    # ----- Application layer (Layer 7) -----
    def _process_application(self, info, payload):
        if not payload:
            return

        if info.protocol == TCP:
            handlers = {
                80: self._process_http,
                443: self._process_tls,
                22: self._process_ssh,
                25: self._process_smtp,
            }
        elif info.protocol == UDP:
            handlers = {
                53: self._process_dns,
                67: self._process_dhcp,
                68: self._process_dhcp,
                123: self._process_ntp,
                443: self._process_tls,
            }
        else:
            return

        handler = handlers.get(info.dst_port) or handlers.get(info.src_port)

        if handler:
            handler(info, payload)


    def _process_dns(self, info, payload):
        if len(payload) < 12:
            return

        info.layers.append(f"{O}DNS{END}")


    def _process_http(self, info, payload):
        if payload.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")):
            line = payload.split(b"\r\n", 1)[0]
            info.layers.append(
                f"{R}HTTP{END} "
                f"{line.decode(errors='replace')}"
            )


    def _process_tls(self, info, payload):
        # TLS record header is 5 bytes
        if len(payload) < 5:
            return

        content_type = payload[0]

        if content_type not in (20,21,22,23,24):
            return

        record_types = {
            20: "ChangeCipherSpec",
            21: "Alert",
            22: "Handshake",
            23: "ApplicationData",
            24: "Heartbeat",
        }

        record_type = payload[0]

        if record_type not in record_types:
            return

        versions = {
            b"\x03\x00": "SSL 3.0",
            b"\x03\x01": "TLS 1.0",
            b"\x03\x02": "TLS 1.1",
            b"\x03\x03": "TLS 1.2",
            b"\x03\x04": "TLS 1.3",
        }

        version = versions.get(payload[1:3], f"0x{payload[1:3].hex()}")
        length = struct.unpack("!H", payload[3:5])[0]

        info.layers.append(f"{O}TLS{END} {record_types[record_type]} {version} len={length}")


    def _process_dhcp(self, info, payload):

        # BOOTP header is 236 bytes
        if len(payload) < 240:
            return

        (
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr
        ) = struct.unpack(
            "!BBBBIHH4s4s4s4s16s",
            payload[:44]
        )

        # DHCP magic cookie
        if payload[236:240] != b"\x63\x82\x53\x63":
            return

        client_mac = self._get_mac(chaddr[:hlen])

        info.layers.append(
            f"{G}DHCP{END} "
            f"xid=0x{xid:08x} "
            f"client={client_mac}"
        )

        # Parse options
        i = 240

        while i < len(payload):
            option = payload[i]

            if option == 255:
                break

            if option == 0:
                i += 1
                continue

            if i + 2 > len(payload):
                break

            length = payload[i + 1]

            if i + 2 + length > len(payload):
                break

            value = payload[i + 2:i + 2 + length]

            if option == 53 and length == 1:
                names = {
                    1: "DISCOVER",
                    2: "OFFER",
                    3: "REQUEST",
                    4: "DECLINE",
                    5: "ACK",
                    6: "NAK",
                    7: "RELEASE",
                    8: "INFORM",
                }

                info.layers.append(
                    f"type={names.get(value[0], value[0])}"
                )

            i += 2 + length


    def _process_ntp(self, info, payload):
        if len(payload) < 48:
            return

        version = (payload[0] >> 3) & 0x07

        info.layers.append(
            f"{G}NTP{END} version={version}"
        )


    def _process_ssh(self, info, payload):
        if payload.startswith(b"SSH-"):
            info.layers.append(
                f"{G}SSH{END} "
                f"{payload.decode(errors='replace').strip()}"
            )


    def _process_smtp(self, info, payload):
        if not payload:
            return

        try:
            text = payload.decode("ascii")
        except UnicodeDecodeError:
            return

        first = text.split("\r\n", 1)[0]

        info.layers.append(
            f"{G}SMTP{END} {first}"
        )



    
    # ----- Helpers
    def _get_mac(self, bytes_mac) -> str:
        bytes_str = map('{:02x}'.format, bytes_mac)
        return ':'.join(bytes_str).upper()
    

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

        if src_port is None and dst_port is None:
            return not self._port_include
    
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

        proto = str(proto).upper()

        for expr in self._proto_exclude:
            if proto == expr[1]:
                return False

        if not self._proto_include:
            return True

        for expr in self._proto_include:
            if match_expr(proto, expr):
                return True

        return False


    @staticmethod
    def _format_payload(data: bytes) -> str:
        if not data:
            return "(empty)"

        hex_data = f"hex:{binascii.hexlify(data).decode('ascii')}"

        try:
            text = data.decode("utf-8", errors="strict")
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
    

    # ----- pcap
    def _open_pcap(self, filename) -> None:
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

        
    def _write_pcap(self, packet) -> None:
        if self._pcap is None:
            return

        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1_000_000)
        length = len(packet)
        self._pcap.write(struct.pack("<IIII", sec, usec, length, length))
        self._pcap.write(packet)



if __name__ == '__main__':
    args = _parse_args()
    try:
        Pytcpdump(
            show_payload=args.payload,
            interface=args.interface,
            filter_frames=args.frame,
            filter_ips=args.ip,
            filter_ports=args.port,
            filter_protocols=args.protocol,
            resolve_hosts=args.resolve,
            pcap_file=args.pcap,
        ).run()
    except KeyboardInterrupt:
        print("Exiting program..")
    exit(0)