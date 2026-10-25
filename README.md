
# CodeAlpha_NetworkSniffer

Basic network sniffer in Python, built for the CodeAlpha Cyber Security Internship (Task 1).

It captures live packets with scapy and shows source and destination IPs, protocol, ports, TCP flags and a payload preview.

## Setup

```bash
pip install scapy
```

On Windows, install [Npcap](https://npcap.com) first.

## Usage

Needs admin rights to capture packets.

```bash
# Capture until Ctrl+C
sudo python3 sniffer.py

# Capture 20 packets
sudo python3 sniffer.py -c 20

# Only web traffic
sudo python3 sniffer.py -f "tcp port 80 or tcp port 443"

# Only DNS, on a specific interface
sudo python3 sniffer.py -i wlan0 -f "udp port 53"

# Save to a pcap file you can open in Wireshark
sudo python3 sniffer.py -c 100 -s capture.pcap
```

## Options

| Flag | What it does |
| --- | --- |
| `-i` | Interface to sniff on |
| `-c` | Number of packets (0 means keep going) |
| `-f` | BPF filter |
| `-s` | Save packets to a pcap file |
| `--payload-bytes` | How many payload bytes to preview |
| `--no-payload` | Hide payloads |

## Example output

```
[09:41:12] #1 TCP | 74 bytes
  192.168.1.20:51514 -> 142.250.185.78:443 (HTTPS)
  Flags: SYN | Seq: 3141592653 | TTL: 64
```

## What I learned

- Every packet is wrapped in layers: Ethernet, then IP, then TCP or UDP, then the data.
- TCP flags (SYN, ACK, FIN) show how a connection starts and ends.
- Most modern traffic is encrypted (HTTPS), so the payload usually looks like random bytes. Plain HTTP, DNS and Telnet are readable.
- ARP and ICMP show up constantly on a home network.

## Legal note

Only capture traffic on networks you own or have permission to monitor.
