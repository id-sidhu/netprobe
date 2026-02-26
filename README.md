# NetProbe 🔬

A low-level network analysis and attack simulation toolkit built from scratch in Python.

Implements IPv4, TCP, and UDP protocol headers manually using raw sockets and Python's `struct` module — no Scapy, no high-level abstractions. Every byte, every checksum, every flag is built and understood from first principles.

---

## Why I Built This

I tried learning TCP/UDP/IP from several sources before starting this — YouTube videos, documentation, forums, AI tools for quick questions. Every resource explained the same surface-level differences: TCP is reliable, UDP is fast, use TCP when you can't miss data. I thought I understood it. I felt confident.

Then I opened Wireshark, searched google.com, and expected to see TCP everywhere. Instead I saw mostly UDP — and a wall of hexadecimal I couldn't make sense of. That moment broke my confidence completely. I realized I knew *about* TCP and UDP but had no idea what was actually happening on the wire.

That's what started this project. I wanted to go all the way down — not just read about headers but actually build them byte by byte, understand why each field exists, and see the results live in captured traffic.

One thing that helped more than I expected: my college background in binary arithmetic, logic gates, and number systems. Understanding one's complement, bitwise AND, bit shifting — not just "convert this hex to binary using Google" but actually knowing how the calculation works — made the checksum algorithm and flag manipulation click in ways they wouldn't have otherwise.

I already had years of Python experience but `socket` and `struct` were completely new to me. I learned them entirely through this project. The whole thing took about two weeks, averaging 1.5-2 hours a day — roughly 20-30 hours of focused work on concepts I thought I already knew.

Now when I run `nmap -sS` or `ping` or look at Wireshark output, my brain works differently. I know what's happening behind each flag, each TTL value, each handshake. I can choose the right tool and the right options because I understand what they actually do — not just that they work.

---

## What It Does

| Tool | Description |
|---|---|
| `sniffer.py` | Captures and parses live network traffic at the Ethernet layer |
| `port_scanner.py` | TCP SYN (half-open) port scanner with threading |
| `handshake_monitor.py` | Detects TCP three-way handshakes in real time |
| `packet_crafter.py` | Interactive tool to craft and send custom TCP/UDP packets |
| `syn_flood.py` | TCP SYN flood simulation (authorized testing only) |
| `udp_flood.py` | UDP flood simulation (authorized testing only) |

---

## Requirements

- Python 3.8+
- Linux (raw sockets require Linux or macOS)
- Root privileges (`sudo`) — required for all tools
- No external dependencies — built entirely from Python stdlib

---

## Installation

```bash
git clone https://github.com/id-sidhu/netprobe.git
cd netprobe
```

That's it. No pip install, no virtualenv. Pure stdlib.

---

## Usage

### Packet Sniffer

Captures all TCP and UDP traffic on an interface.

```bash
sudo python3 tools/sniffer.py
```

With filters:

```bash
sudo python3 tools/sniffer.py --port 53           # DNS traffic only
sudo python3 tools/sniffer.py --ip 142.251.45.131 # specific IP only
sudo python3 tools/sniffer.py --protocol TCP       # TCP only
sudo python3 tools/sniffer.py --interface wlan0    # wireless interface
```

Example output:

```
────────────────────────────────────────────────────────────
  Protocol : TCP
  Ethernet : aa:bb:cc:dd:ee:ff → 11:22:33:44:55:66
  IP       : 192.168.1.100:54321 → 142.251.45.131:443
  TTL      : 64  |  Length: 40 bytes  |  Checksum: 0x9307
  Flags    : SYN
  Seq      : 2847293847  |  Ack: 0
  Window   : 65535 bytes
```

---

### Port Scanner

TCP SYN scan of ports 1-1024 on a target machine.

```bash
sudo python3 tools/port_scanner.py
```

Example output:

```
[*] Starting SYN scan on 192.168.1.1
[*] Scanning ports 1-1024

[*] Scan complete
[*] Found 3 open port(s):

  Port 22/tcp   open
  Port 80/tcp   open
  Port 443/tcp  open
```

---

### Handshake Monitor

Watches live traffic and prints every new TCP connection as it's established.

```bash
sudo python3 tools/handshake_monitor.py
```

Example output:

```
[*] Sniffer started on interface: eth0
[*] Press Ctrl+C to stop

[+] HANDSHAKE COMPLETE
    192.168.1.100:54321 → 142.251.45.131:443
    Time: 14:23:07
```

---

### Packet Crafter

Interactive tool for crafting custom packets with full field control.

```bash
sudo python3 tools/packet_crafter.py
```

```
==================================================
  NetProbe Packet Crafter
==================================================
Source IP [default: your IP]:
Destination IP: 192.168.1.1
Protocol [TCP/UDP, default: TCP]:
TTL [default: 64]:
Source port [default: random]:
Destination port [default: 80]:
Flags [default: SYN]: RST

[*] Sending packet...
    192.168.1.100:61234 → 192.168.1.1:80
    Flags: RST  TTL: 64  Seq: 3421987234
[*] Packet sent (40 bytes)

[+] Response received!
    192.168.1.1:80 → 192.168.1.100:61234
    Flags: ACK  TTL: 64
```

---

### Attack Modules

> ⚠️ **For authorized testing only. Only use against machines you own or have explicit written permission to test. Unauthorized use is illegal.**

```bash
sudo python3 attacks/syn_flood.py
sudo python3 attacks/udp_flood.py
```

Both take a target IP and port interactively and print a packet counter every 1000 packets.

---

## Project Structure

```
netprobe/
├── core/
│   ├── ip_header.py          # IPv4 header — manual struct packing, RFC 791
│   ├── tcp_header.py         # TCP header — pseudo-header checksum, RFC 793
│   └── udp_header.py         # UDP header — datagram construction, RFC 768
├── tools/
│   ├── sniffer.py            # AF_PACKET raw socket, promiscuous mode
│   ├── port_scanner.py       # Half-open SYN scan, ThreadPoolExecutor
│   ├── handshake_monitor.py  # State machine, 4-tuple connection tracking
│   └── packet_crafter.py     # Interactive packet builder, spoofing support
├── attacks/
│   ├── syn_flood.py          # Randomized source IP, 500 threads
│   └── udp_flood.py          # UDP datagram flood, randomized source IP
└── docs/
    └── protocol_notes.md     # Detailed writeup of every concept implemented
```

---

## How It's Built

Everything in `core/` is hand-rolled from RFC specifications:

**IP Header construction:**
```python
# version and IHL packed into one byte using bit shifting
ver_ihl = (self.version << 4) | self.ihl

# RFC 1071 one's complement checksum
def _calculate_checksum(self, data):
    s = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        s += word
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF
```

**TCP pseudo-header for checksum:**
```python
# TCP checksum covers IP addresses — binds TCP checksum to the IP layer
# so misrouted packets are detected even if IP header looks valid
pseudo_header = struct.pack("!4s4sBBH",
    socket.inet_aton(src_ip),
    socket.inet_aton(dst_ip),
    0,
    6,           # TCP protocol number
    tcp_length
)
```

No third-party libraries. No abstractions. Just bytes.

---

## Key Technical Concepts

- **Struct packing** — converting Python values to raw bytes using format strings (`!BBHHHBBH4s4s`)
- **Bit manipulation** — packing multiple fields into single bytes with `<<`, `>>`, `&`, `|`
- **RFC 1071 checksums** — one's complement sum with carry folding
- **Raw sockets** — `AF_PACKET` for Ethernet-layer capture, `IPPROTO_RAW` for sending
- **Promiscuous mode** — capturing all traffic regardless of destination MAC
- **Half-open scanning** — SYN without final ACK to detect open ports
- **Threading** — `ThreadPoolExecutor` for concurrent port scanning
- **State machines** — tracking TCP handshake state across multiple packets

---

## The Wireshark Moment

One thing worth noting for anyone starting a similar project — when I first opened Wireshark after learning "TCP is reliable, use it when data matters," I expected to see TCP everywhere on a Google search. Instead I saw mostly UDP on port 443.

That's QUIC (HTTP/3) — Google rebuilt reliability on top of UDP with their own custom rules, because it's faster than TCP for modern web traffic. No three-way handshake delay, no head-of-line blocking. The surface-level explanation of TCP vs UDP completely missed this.

Building this project from the byte level up is what made that make sense. You can't fully understand *why* modern protocols make the choices they do until you understand what they're working around.

---

## Detailed Documentation

For a full writeup of every protocol concept, implementation decision, and challenge faced during this project, see [`docs/protocol_notes.md`](docs/protocol_notes.md).

---

## Disclaimer

This toolkit is for educational purposes and authorized security testing only. The attack modules simulate real DoS attacks and must only be used against systems you own or have explicit written permission to test.

Unauthorized use is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws in other jurisdictions.

---

## License

MIT License — use freely, learn deeply.
