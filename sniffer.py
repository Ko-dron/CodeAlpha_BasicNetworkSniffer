#!/usr/bin/env python3
"""
CodeAlpha Task 1 - Basic Network Sniffer
Captures live network traffic and displays packet details including
source/destination IPs, protocols, ports, DNS queries, and statistics.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from collections import Counter
from datetime import datetime
import sys

# Statistics counters
stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "DNS": 0,
    "Other": 0,
    "Total": 0
}

# Track top talkers (most active IP addresses)
ip_counter = Counter()


def process_packet(packet):
    """Called for every captured packet. Extracts and prints info."""
    stats["Total"] += 1
    
    # Skip packets without an IP layer (rare, but exists)
    if IP not in packet:
        return
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # Track who's talking the most
    ip_counter[src_ip] += 1
    ip_counter[dst_ip] += 1
    
    # Handle DNS specifically (most interesting protocol to watch!)
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        stats["DNS"] += 1
        # qname is the domain being looked up, like b'google.com.'
        domain = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
        print(f"[{timestamp}] [DNS]  {src_ip} -> {dst_ip} | Query: {domain}")
        return
    
    # Handle TCP
    if TCP in packet:
        stats["TCP"] += 1
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        size = len(packet)
        print(f"[{timestamp}] [TCP]  {src_ip}:{sport} -> {dst_ip}:{dport} | Flags: {flags} | Size: {size}B")
        return
    
    # Handle UDP
    if UDP in packet:
        stats["UDP"] += 1
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        size = len(packet)
        # Special note for QUIC (UDP port 443)
        protocol_label = "QUIC" if dport == 443 or sport == 443 else "UDP"
        print(f"[{timestamp}] [{protocol_label}] {src_ip}:{sport} -> {dst_ip}:{dport} | Size: {size}B")
        return
    
    # Handle ICMP (ping)
    if ICMP in packet:
        stats["ICMP"] += 1
        print(f"[{timestamp}] [ICMP] {src_ip} -> {dst_ip} | Type: {packet[ICMP].type}")
        return
    
    # Anything else
    stats["Other"] += 1
    print(f"[{timestamp}] [????] {src_ip} -> {dst_ip} | Protocol: {packet[IP].proto}")


def print_summary():
    """Print statistics when the user stops the sniffer."""
    print("\n" + "=" * 60)
    print("CAPTURE SUMMARY")
    print("=" * 60)
    print(f"Total packets captured: {stats['Total']}")
    print(f"  TCP:   {stats['TCP']}")
    print(f"  UDP:   {stats['UDP']}")
    print(f"  DNS:   {stats['DNS']}")
    print(f"  ICMP:  {stats['ICMP']}")
    print(f"  Other: {stats['Other']}")
    
    print("\nTop 5 most active IP addresses:")
    for ip, count in ip_counter.most_common(5):
        print(f"  {ip:20s} {count} packets")
    print("=" * 60)


def main():
    print("=" * 60)
    print("CodeAlpha Network Sniffer")
    print("=" * 60)
    print("Capturing on interface: eth0")
    print("Press Ctrl+C to stop and see summary.\n")
    
    try:
        sniff(iface="eth0", prn=process_packet, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        print_summary()


if __name__ == "__main__":
    main()
