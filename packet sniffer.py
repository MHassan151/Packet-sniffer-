import argparse
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import sniff, wrpcap, get_if_list
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw
except ImportError:
    sys.exit("Scapy not installed. Run: pip install scapy")

stats = Counter()
captured = []


def show_payload(pkt):
    if pkt.haslayer(Raw):
        data = bytes(pkt[Raw].load)[:60]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        print(f"   Payload ({len(pkt[Raw].load)} bytes): {text}")


def process_packet(pkt):
    stats["total"] += 1
    captured.append(pkt)
    now = datetime.now().strftime("%H:%M:%S")
    print(f"\n[{stats['total']}] {now}  size={len(pkt)} bytes")

    if pkt.haslayer(ARP):
        stats["ARP"] += 1
        print(f"   ARP : {pkt[ARP].psrc} -> {pkt[ARP].pdst}")
        return

    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        stats["OTHER"] += 1
        print("   (non-IP packet)")
        return

    print(f"   IP  : {src} -> {dst}")

    if pkt.haslayer(TCP):
        stats["TCP"] += 1
        t = pkt[TCP]
        print(f"   TCP : port {t.sport} -> {t.dport}  flags={t.flags}")
    elif pkt.haslayer(UDP):
        stats["UDP"] += 1
        u = pkt[UDP]
        print(f"   UDP : port {u.sport} -> {u.dport}")
    elif pkt.haslayer(ICMP):
        stats["ICMP"] += 1
        print(f"   ICMP: type {pkt[ICMP].type}")
    else:
        stats["OTHER"] += 1

    if pkt.haslayer(DNSQR):
        stats["DNS"] += 1
        print(f"   DNS : {pkt[DNSQR].qname.decode(errors='ignore')}")

    show_payload(pkt)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("-i", "--iface", help="interface name")
    p.add_argument("-c", "--count", type=int, default=0, help="packets to capture")
    p.add_argument("-f", "--filter", default="", help="BPF filter e.g. tcp")
    p.add_argument("-o", "--output", help="save to .pcap file")
    p.add_argument("--list-ifaces", action="store_true")
    args = p.parse_args()

    if args.list_ifaces:
        print("Available interfaces:")
        for name in get_if_list():
            print(" -", name)
        return

    print("=" * 50)
    print(" Basic Network Sniffer - CodeAlpha")
    print("=" * 50)
    print(f" Interface: {args.iface or 'default'}")
    print(f" Filter   : {args.filter or 'none'}")
    print(f" Count    : {args.count or 'unlimited'}")
    print(" Press Ctrl+C to stop.")

    try:
        sniff(iface=args.iface, filter=args.filter or None,
              prn=process_packet, count=args.count, store=False)
    except PermissionError:
        sys.exit("Permission denied. Run as Administrator / root.")
    except OSError as e:
        sys.exit(f"Capture error: {e}\nWindows: install Npcap from https://npcap.com")
    except KeyboardInterrupt:
        pass

    print("\n" + "=" * 50)
    print(" SUMMARY")
    print("=" * 50)
    for key in ("total", "TCP", "UDP", "ICMP", "ARP", "DNS", "OTHER"):
        if stats[key]:
            print(f" {key:<6}: {stats[key]}")

    if args.output and captured:
        wrpcap(args.output, captured)
        print(f" Saved to {args.output}")


if __name__ == "__main__":
    main()