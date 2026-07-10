## pytcpdump

A lightweight Linux packet tcpdump.


```bash
sudo python3 pytcpdump.py 

# --payload: include payload data when available
# --interface <net_iface>: bind capture to a specific interface name
```

### Packet format

```text
Packet [1]
    ETH src=aa:bb:cc:dd:ee:ff dst=00:11:22:33:44:55 | type=8
    FRAME len=98 bytes
    IP 192.168.1.10 -> 8.8.8.8 | ver=4 ihl=20 tos=0 ttl=64 id=1234 flags=0 frag=0 checksum=12345 proto=TCP
    TCP sport=443 dport=53210 | seq=123456789 ack=987654321 flags=SYN:1 ACK:0 FIN:0 win=64240 cksum=12345
    (PAYLOAD)
```

```text
Packet [2]
    ETH src=aa:bb:cc:dd:ee:ff dst=00:11:22:33:44:55 | type=8
    FRAME len=64 bytes
    IP 10.0.0.2 -> 10.0.0.3 | ver=4 ihl=20 tos=0 ttl=64 id=5678 flags=0 frag=0 checksum=54321 proto=UDP
    UDP sport=53 dport=12345 | len=32 checksum=0
    (PAYLOAD)
```

```text
Packet [3]
    ETH src=aa:bb:cc:dd:ee:ff dst=00:11:22:33:44:55 | type=8
    FRAME len=42 bytes
    IP 10.0.0.2 -> 10.0.0.3 | ver=4 ihl=20 tos=0 ttl=64 id=9101 flags=0 frag=0 checksum=11111 proto=ICMP
    ICMP type=8 code=0 checksum=22222
```
