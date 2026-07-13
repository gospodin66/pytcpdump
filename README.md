# pytcpdump

A lightweight Python packet sniffer inspired by `tcpdump`.

`pytcpdump` captures raw Ethernet frames using Linux raw sockets, decodes IPv4, TCP, UDP and ICMP packets, and displays them in a compact, human-readable format. It also supports packet filtering, payload inspection, reverse DNS resolution, and saving captures to PCAP files.

## Features

- Capture packets from any network interface
- IPv4 packet decoding
- TCP, UDP and ICMP protocol support
- Filter by:
  - IP address
  - Port
  - Protocol
- Optional reverse DNS hostname resolution
- Optional payload display (text or hexadecimal)
- Save captures in PCAP format

## Requirements

- Linux
- Python 3.8+
- Root privileges (`sudo`)

## Usage

```bash
sudo ./pytcpdump.py [OPTIONS]
```

## Options

| Option | Description |
|--------|-------------|
| `--interface IFACE` | Capture on a specific interface |
| `--ip EXPR` | Filter by IP address (`192.168.1.10`, `!=8.8.8.8`) |
| `--port EXPR` | Filter by port (`80`, `!=22`, `>1024`, `1000-2000`) |
| `--protocol EXPR` | Filter by protocol (`TCP`, `UDP`, `ICMP`) |
| `--payload` | Display packet payload |
| `--resolve` | Resolve public IP addresses to hostnames |
| `--pcap FILE` | Save captured packets to a PCAP file |

## Examples

Capture all packets:

```bash
sudo ./pytcpdump.py
```

Capture on a specific interface:

```bash
sudo ./pytcpdump.py --interface eth0
```

Show only TCP traffic:

```bash
sudo ./pytcpdump.py --protocol TCP
```

Capture HTTP/HTTPS traffic:

```bash
sudo ./pytcpdump.py --port 80 --port 443
```

Exclude SSH traffic:

```bash
sudo ./pytcpdump.py --port '!=22'
```

Display packet payloads:

```bash
sudo ./pytcpdump.py --payload
```

Resolve public IP addresses:

```bash
sudo ./pytcpdump.py --resolve
```

Save packets to a PCAP file:

```bash
sudo ./pytcpdump.py --pcap capture.pcap
```

## Notes

- Only IPv4 packets are currently decoded.
- Private IP addresses are not resolved via DNS.
- PCAP files can be opened with Wireshark or read using `tcpdump -r`.
