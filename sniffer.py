#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship
Task 1: Basic Network Sniffer

Captures live packets with scapy and prints the useful bits:
source and destination IPs, protocol, ports, flags and a payload preview.

Run with admin rights (sudo on Linux/macOS, Administrator on Windows).
Only use this on networks you own or have permission to test.
"""

import argparse
import sys
from collections import Counter
from datetime import datetime

from scapy.all import sniff, wrpcap
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

# Common ports so the output is easier to read
PORT_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-alt",
}

TCP_FLAGS = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
}

stats = Counter()
captured = []
args = None


def port_label(port):
    name = PORT_NAMES.get(port)
    return f"{port} ({name})" if name else str(port)


def payload_preview(packet, limit):
    """Return a printable preview of the raw payload, if there is one."""
    if not packet.haslayer(Raw):
        return None
    data = bytes(packet[Raw].load)
    if not data:
        return None
    chunk = data[:limit]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    extra = f" ... (+{len(data) - limit} bytes)" if len(data) > limit else ""
    return f"{text}{extra}"


def describe_flags(flag_value):
    flags = str(flag_value)
    return ",".join(TCP_FLAGS.get(f, f) for f in flags) or "none"


def handle_packet(packet):
    stats["total"] += 1
    if args.save:
        captured.append(packet)

    now = datetime.now().strftime("%H:%M:%S")
    size = len(packet)
    lines = []

    if packet.haslayer(IP):
        ip = packet[IP]
        src, dst = ip.src, ip.dst
        if packet.haslayer(TCP):
            proto = "TCP"
            l4 = packet[TCP]
            lines.append(
                f"  {src}:{port_label(l4.sport)} -> {dst}:{port_label(l4.dport)}"
            )
            lines.append(
                f"  Flags: {describe_flags(l4.flags)} | Seq: {l4.seq} | TTL: {ip.ttl}"
            )
        elif packet.haslayer(UDP):
            proto = "UDP"
            l4 = packet[UDP]
            lines.append(
                f"  {src}:{port_label(l4.sport)} -> {dst}:{port_label(l4.dport)}"
            )
            lines.append(f"  Length: {l4.len} | TTL: {ip.ttl}")
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            l4 = packet[ICMP]
            lines.append(f"  {src} -> {dst}")
            lines.append(f"  Type: {l4.type} | Code: {l4.code} | TTL: {ip.ttl}")
        else:
            proto = f"IP proto {ip.proto}"
            lines.append(f"  {src} -> {dst}")
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        proto = "IPv6"
        lines.append(f"  {ip6.src} -> {ip6.dst}")
        lines.append(f"  Next header: {ip6.nh} | Hop limit: {ip6.hlim}")
    elif packet.haslayer(ARP):
        arp = packet[ARP]
        proto = "ARP"
        kind = "request" if arp.op == 1 else "reply" if arp.op == 2 else f"op {arp.op}"
        lines.append(f"  {arp.psrc} ({arp.hwsrc}) -> {arp.pdst} ({arp.hwdst})")
        lines.append(f"  ARP {kind}")
    elif packet.haslayer(Ether):
        eth = packet[Ether]
        proto = f"Ethernet 0x{eth.type:04x}"
        lines.append(f"  {eth.src} -> {eth.dst}")
    else:
        proto = "Other"
        lines.append("  Unknown packet type")

    stats[proto.split()[0]] += 1

    preview = payload_preview(packet, args.payload_bytes)
    if preview and not args.no_payload:
        lines.append(f"  Payload: {preview}")

    print(f"[{now}] #{stats['total']} {proto} | {size} bytes")
    print("\n".join(lines))
    print()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Basic network sniffer built with scapy."
    )
    parser.add_argument("-i", "--interface", help="Interface to sniff on (default: scapy picks one)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (default: 0, runs until Ctrl+C)")
    parser.add_argument("-f", "--filter", default="",
                        help='BPF filter, for example "tcp port 80" or "udp" or "host 192.168.1.1"')
    parser.add_argument("-s", "--save", metavar="FILE.pcap",
                        help="Save captured packets to a pcap file (open it in Wireshark)")
    parser.add_argument("--payload-bytes", type=int, default=64,
                        help="How many payload bytes to preview (default: 64)")
    parser.add_argument("--no-payload", action="store_true",
                        help="Hide payload previews")
    return parser.parse_args()


def print_summary():
    print("=" * 40)
    print("Capture summary")
    print("=" * 40)
    print(f"Total packets: {stats['total']}")
    for name, count in stats.most_common():
        if name != "total":
            print(f"  {name}: {count}")


def main():
    global args
    args = parse_args()

    print("Starting sniffer. Press Ctrl+C to stop.")
    if args.filter:
        print(f"Filter: {args.filter}")
    print()

    try:
        sniff(
            iface=args.interface,
            filter=args.filter or None,
            prn=handle_packet,
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("Permission denied. Run with sudo (Linux/macOS) or as Administrator (Windows).")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except OSError as err:
        print(f"Could not start capture: {err}")
        print("On Windows, make sure Npcap is installed.")
        sys.exit(1)

    print_summary()

    if args.save and captured:
        wrpcap(args.save, captured)
        print(f"\nSaved {len(captured)} packets to {args.save}")


if __name__ == "__main__":
    main()
