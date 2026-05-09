# CodeAlpha — Basic Network Sniffer

A Python-based network packet sniffer built as part of the CodeAlpha Cybersecurity Internship (Task 1). The tool captures live network traffic on a chosen interface, identifies protocols, decodes DNS queries, distinguishes modern QUIC traffic from regular UDP, and prints a statistical summary when stopped.

## Features

- Real-time packet capture using Scapy
- Protocol identification: TCP, UDP, ICMP, DNS, and QUIC (HTTP/3)
- Decodes DNS queries to show the actual domain name being looked up
- Displays source/destination IPs, ports, packet size, and TCP flags
- Tracks the most active IP addresses ("top talkers")
- Clean summary report on exit (Ctrl+C)
- Timestamped output for each packet

## Concepts Demonstrated

- The OSI/TCP-IP protocol stack (Ethernet → IP → TCP/UDP → application)
- The TCP three-way handshake (SYN → SYN-ACK → ACK)
- DNS resolution as the first step of any web request
- Difference between TCP (reliable) and UDP (fast) transport
- Modern HTTPS over QUIC (UDP port 443)
- Why payloads of HTTPS traffic appear as random bytes (encryption)

## Requirements

- Python 3.8+
- Linux operating system (tested on Kali Linux)
- Root/sudo privileges (required for raw packet capture)
- Scapy library

## Installation

Install Scapy on Kali/Debian-based systems:

```bash
sudo apt install python3-scapy -y
```

Or via pip:

```bash
pip install scapy
```

## Usage

Find your network interface name:

```bash
ip addr
```

Common interface names: `eth0`, `wlan0`, `ens33`. Edit the `iface` parameter in `sniffer.py` if yours is different.

Run the sniffer with sudo:

```bash
sudo python3 sniffer.py
```

Press `Ctrl+C` to stop and view the summary report.

## Sample Output

```
[18:17:59] [TCP]  10.0.2.15:52560 -> 108.139.200.120:443 | Flags: S | Size: 74B
[18:17:59] [TCP]  108.139.200.120:443 -> 10.0.2.15:52560 | Flags: SA | Size: 60B
[18:17:59] [TCP]  10.0.2.15:52560 -> 108.139.200.120:443 | Flags: A | Size: 54B
[18:17:59] [DNS]  10.0.2.15 -> 192.168.100.1 | Query: ep2.adtrafficquality.google
[18:17:59] [QUIC] 10.0.2.15:34504 -> 142.251.216.34:443 | Size: 74B
```

The sequence above shows a complete TCP three-way handshake to an Amazon CloudFront server, a DNS query for a Google ad-tracking domain, and a parallel QUIC connection to a Google service.

## Legal and Ethical Notice

This tool is for educational use only. Capturing network traffic on networks you do not own or do not have explicit permission to monitor is illegal in most jurisdictions. In Ghana, unauthorized network interception is prohibited under the Cybersecurity Act 2020. Always test on your own network or in an isolated lab environment.

## Author

Built by Ko-dron  for the CodeAlpha Cybersecurity Internship, 2026.

## License

MIT License — free to use, modify, and learn from.
