

import socket
import struct

def make_ip(proto, srcip, dstip, ident=54321):
    saddr = socket.inet_aton(srcip)
    daddr = socket.inet_aton(dstip)
    ihl_ver = (4 << 4) | 5
    return struct.pack('!BBHHHBBH4s4s', ihl_ver, 0, 0, ident, 0, 255, proto, 0, saddr, daddr)

def make_tcp(srcport,
             dstport,
             payload,
             seq=123,
             ackseq=0,
             fin=False, syn=True, rst=False, psh=False, ack=False, urg=False,
             window=5840):
    offset_res = (5 << 4) | 0
    flags = (fin | (syn << 1) | (rst << 2) | (psh << 3) | (ack << 4) | (urg << 5))
    return struct.pack('!HHLLBBHHH', srcport, dstport, seq, ackseq, offset_res, flags, window, 0, 0)

if __name__ == '__main__':
    srcip, dstip = ('127.0.10.10', '127.0.15.15')
    srcport, dstport = 11001, 11000
    payload = '[TESTING]\r\n'.encode('utf-8')

    ip = make_ip(socket.IPPROTO_TCP, srcip, dstip)
    tcp = make_tcp(srcport, dstport, payload)

    print(ip, tcp, payload)

    packet = ip + tcp + payload

    # to use socket.IPPROTO_RAW) -- remove s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    #                            -- IPPROTO_RAW already implies IP_HDRINCL
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    s.sendto(packet, (dstip, 0))
    response, addr = s.recvfrom(65535)
    response_id = struct.unpack('!H', response[4:6])
    print(response_id)