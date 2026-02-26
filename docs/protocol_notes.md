# NetProbe — Protocol Notes & Project Documentation

## What Is NetProbe

NetProbe is a low-level network analysis and attack simulation toolkit built entirely from scratch in Python. It implements IPv4, TCP, and UDP protocol headers manually using raw sockets and Python's `struct` module — without relying on high-level libraries like Scapy.

The goal was not to build the fastest or most feature-rich tool, but to understand exactly what happens at the byte level when two machines communicate. Every field, every bit, every checksum is implemented and understood from first principles.

---

## Project Structure

```
netprobe/
├── core/
│   ├── ip_header.py          # IPv4 header construction
│   ├── tcp_header.py         # TCP header construction
│   └── udp_header.py         # UDP header construction
├── tools/
│   ├── sniffer.py            # Raw packet capture and parsing
│   ├── port_scanner.py       # TCP SYN port scanner
│   ├── handshake_monitor.py  # TCP handshake detection
│   └── packet_crafter.py    # Interactive packet builder
├── attacks/
│   ├── syn_flood.py          # TCP SYN flood simulation
│   └── udp_flood.py          # UDP flood simulation
└── docs/
    └── protocol_notes.md     # This file
```

---

## What I Learned

### 1. How Packets Are Actually Structured

Every packet on the internet is just bytes. When you visit a website, your browser's "GET /" request gets wrapped in layers — first TCP, then IP, then Ethernet. Each layer adds its own header in front of the data from the layer above. This is called **encapsulation**.

```
Ethernet header (14 bytes)
└── IP header (20 bytes)
    └── TCP header (20 bytes)
        └── Your data ("GET / HTTP/1.1...")
```

To read or build a packet from scratch, you need to know exactly how many bytes each field occupies and in what order — because the receiving machine reads them at fixed positions. There is no punctuation, no labels, just raw bytes in a specific sequence that both sides agreed on via the RFC specification.

---

### 2. IP Headers — The Envelope

The IPv4 header is 20 bytes minimum. Every field has a specific size and position defined in RFC 791.

```
Byte 0:      Version (4 bits) + IHL (4 bits)
Byte 1:      Type of Service
Bytes 2-3:   Total Length
Bytes 4-5:   Identification
Bytes 6-7:   Flags (3 bits) + Fragment Offset (13 bits)
Byte 8:      TTL
Byte 9:      Protocol (6=TCP, 17=UDP, 1=ICMP)
Bytes 10-11: Header Checksum
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Key insight — packing multiple fields into one byte:**
Version and IHL both fit in one byte. Version occupies the top 4 bits, IHL the bottom 4. To pack them:
```python
ver_ihl = (version << 4) | ihl   # shift version left, OR with ihl
```
To unpack:
```python
version = ver_ihl >> 4            # shift right to get top 4 bits
ihl     = ver_ihl & 0x0F          # mask bottom 4 bits
```

**TTL as a fingerprinting tool:**
Operating systems set TTL to different starting values:
- Linux/Mac: 64
- Windows: 128
- Network equipment: 255

When you capture a packet and see TTL=62, the packet passed through 2 routers before reaching you (64 - 2 = 62). This helps map network topology without any special tools.

---

### 3. Checksums — RFC 1071

Both IP and TCP use checksums to detect corruption. The algorithm (RFC 1071) works as follows:

1. Split the header into 16-bit words
2. Sum all words as integers
3. Fold any carry bits back in: `(sum & 0xFFFF) + (sum >> 16)`
4. Take the one's complement: `~sum & 0xFFFF`

**Why the checksum field is set to 0 before calculation:**
The checksum covers all header bytes including the checksum field itself. Since you can't include the answer in its own calculation, you set it to 0 first, compute, then replace it with the real value.

**Verification:** A receiver sums all words including the checksum field. If the result is `0xFFFF`, the packet is intact. If not, it was corrupted in transit.

---

### 4. TCP — Reliability Over IP

TCP adds reliability on top of IP, which provides none. IP just tries to deliver packets — it doesn't guarantee delivery, order, or integrity. TCP fixes all of this.

**The Three-Way Handshake:**
```
Client → Server:  SYN              (I want to connect, my seq starts at X)
Server → Client:  SYN + ACK        (OK, my seq starts at Y, I got your X)
Client → Server:  ACK              (Got it, connection established)
```
After this exchange, both sides know each other's starting sequence numbers and the connection is established.

**Why Sequence Numbers Are Random:**
If sequence numbers were predictable (starting at 0 every time), an attacker who could observe traffic patterns could inject packets into an existing connection without seeing the actual traffic — a TCP hijacking attack. Kevin Mitnick exploited predictable sequence numbers in 1994. Modern OSes use cryptographically random starting values.

**TCP Flags:**
```
SYN   (0x02)  — Synchronize, initiate connection
ACK   (0x10)  — Acknowledge received data
RST   (0x04)  — Reset, abort connection immediately
FIN   (0x01)  — Finish, gracefully close one direction
PSH   (0x08)  — Push data immediately, don't buffer
URG   (0x20)  — Urgent pointer is valid
```
Flags are packed into 6 bits of a single byte. To check if SYN is set: `flags & 0x02`. To set multiple flags: `SYN | ACK = 0x02 | 0x10 = 0x12`.

**TCP Pseudo-Header:**
TCP's checksum doesn't just cover the TCP header — it also covers a 12-byte "pseudo-header" containing source IP, destination IP, protocol, and TCP length. This pseudo-header is never transmitted — it exists only for checksum calculation. The reason: it binds the TCP checksum to the IP addresses, so a misrouted packet (valid IP header, wrong destination) will fail the TCP checksum check.

---

### 5. UDP — Speed Over Reliability

UDP is the opposite philosophy from TCP. No handshake, no acknowledgments, no ordering, no retransmission. Just send and forget.

The entire UDP header is 8 bytes:
```
Bytes 0-1: Source Port
Bytes 2-3: Destination Port
Bytes 4-5: Length
Bytes 6-7: Checksum
```

**Why UDP has a Length field but TCP doesn't:**
TCP is a stream protocol — sequence numbers track every byte's position, so the receiver always knows where it is. UDP is a datagram protocol — each packet is independent with no sequence tracking. The length field explicitly states how big each datagram is.

**When to use UDP over TCP:**
- DNS lookups — small request, small response, speed matters
- VoIP and video — a dropped frame is better than a delayed one
- Gaming — latency matters more than reliability
- HTTP/3 (QUIC) — Google rebuilt reliability on top of UDP with custom rules, faster than TCP for modern web traffic

The Google search capture showed this in practice — the vast majority of traffic was UDP on port 443, which is QUIC/HTTP3, not traditional HTTPS over TCP.

---

### 6. Raw Sockets

Normal sockets (the kind every application uses) let the OS handle all headers automatically. Your application only sees the data.

Raw sockets bypass this. You receive complete packets including all headers, and you can send packets where you built every header yourself. This is how Wireshark works — it uses raw sockets to see everything on the wire.

**Why root is required:**
Raw sockets give you access to all network traffic — including packets not addressed to you. Combined with the ability to spoof source IP addresses, this is a powerful capability that the OS restricts to root only.

**AF_PACKET vs AF_INET:**
```
AF_INET   — captures at IP layer, Ethernet header already stripped
             byte positions start at IP header (byte 0)

AF_PACKET — captures at Ethernet layer, complete frames
             byte positions: Ethernet (0-13), IP (14-33), TCP (34+)
```
The sniffer uses `AF_PACKET` to capture everything including MAC addresses. The port scanner and packet crafter use `AF_INET` for simpler byte positions.

---

### 7. Threading — Concurrent Port Scanning

Scanning 1024 ports sequentially, waiting 2 seconds per port = up to 34 minutes worst case. With threading, 100 ports scan simultaneously.

**Why order doesn't matter:**
Each port scan is completely independent. Whether port 80 finishes before port 443 is irrelevant — we collect all results and sort them at the end.

**Race conditions:**
When multiple threads write to the same list simultaneously, the list can get corrupted — operations that look atomic in Python aren't always atomic at the CPU level. The fix is a `threading.Lock()` — only one thread can hold the lock at a time, preventing simultaneous writes.

```python
with lock:
    open_ports.append(port)   # only one thread here at a time
```

**ThreadPoolExecutor:**
Instead of creating 1024 threads simultaneously (which would overwhelm the network), `ThreadPoolExecutor(max_workers=100)` maintains a pool of 100 threads. When one finishes, it picks up the next port from the queue automatically.

---

## How Each Tool Works

### sniffer.py
Creates a raw `AF_PACKET` socket in promiscuous mode — the network card accepts all frames regardless of destination MAC. Parses each frame sequentially: Ethernet header (14 bytes) → IP header (20 bytes) → TCP or UDP header. Supports filtering by IP, port, and protocol via command-line arguments. Demonstrated capturing 244 packets from a single Google search, including DNS queries, QUIC/HTTP3 traffic, and background Microsoft telemetry.

### port_scanner.py
Implements a TCP SYN (half-open) scan. For each port, crafts a raw SYN packet with a random source port and sends it. Listens for responses: SYN|ACK means open, RST means closed, timeout means filtered. Uses `ThreadPoolExecutor` with 100 workers to scan all 1024 ports concurrently instead of sequentially. The "half-open" name comes from never sending the final ACK — the connection is never fully established.

### handshake_monitor.py
Watches live traffic and tracks TCP connection state across multiple packets. Uses a dictionary keyed by the 4-tuple `(src_ip, src_port, dst_ip, dst_port)` to store in-progress handshakes. Implements a three-state machine: `SYN_SENT` → `SYN_RECEIVED` → `ESTABLISHED`. The "reversed key" handles the fact that SYN|ACK arrives with src and dst addresses swapped compared to the original SYN.

### packet_crafter.py
Interactive tool for crafting custom packets. Takes user input for every field — source IP (can be spoofed), destination IP/port, TTL, protocol, TCP flags, sequence number, window size — all with sensible defaults. Builds the packet using the core/ header classes, sends it, and waits up to 3 seconds for a response. Supports both TCP and UDP. Useful for testing firewall behavior, probing specific flag combinations, and simulating connection stages.

### syn_flood.py
Simulates a TCP SYN flood DoS attack. Sends SYN packets as fast as possible to a target IP and port, each with a randomly spoofed source IP and source port. The target allocates memory for each half-open connection waiting for an ACK that never arrives. When the connection table fills up, legitimate connections are rejected. Uses 500 threads for maximum throughput. **Only use against machines you own or have explicit permission to test.**

### udp_flood.py
Simulates a UDP flood DoS attack. Identical structure to the SYN flood but uses UDP headers instead of TCP. Particularly effective against UDP services (DNS on port 53, game servers) since UDP has no connection state — the target must process every packet. Uses randomly spoofed source IPs to prevent simple IP-based blocking. **Only use against machines you own or have explicit permission to test.**

---

## Key Concepts Quick Reference

| Concept | Value |
|---|---|
| IP header size | 20 bytes (minimum) |
| TCP header size | 20 bytes (minimum) |
| UDP header size | 8 bytes (fixed) |
| Ethernet header size | 14 bytes |
| Linux default TTL | 64 |
| Windows default TTL | 128 |
| TCP protocol number | 6 |
| UDP protocol number | 17 |
| ICMP protocol number | 1 |
| Max IP packet size | 65535 bytes |
| Ethernet MTU | 1500 bytes |
| SYN flag value | 0x02 |
| ACK flag value | 0x10 |
| SYN\|ACK value | 0x12 |
| RST flag value | 0x04 |
| FIN flag value | 0x01 |

---

## Challenges Faced

**Binary operations** — understanding bit shifting and masking for packing multiple fields into single bytes was the hardest initial concept. The `ver_ihl` byte that packs version and IHL together required understanding `<<`, `>>`, `&`, and `|` at the bit level.

**Checksum algorithm** — the RFC 1071 one's complement checksum is not intuitive. The carry folding step `(sum & 0xFFFF) + (sum >> 16)` and the reason for setting the checksum field to 0 before calculation took time to fully understand.

**TCP pseudo-header** — discovering that TCP's checksum covers data from the IP layer (source and destination IPs) was unexpected. Understanding why this design decision was made — to detect misrouted packets — made it click.

**Byte positions shifting by 14** — the difference between `AF_PACKET` (includes Ethernet header) and `AF_INET` (starts at IP header) caused off-by-14 errors when parsing response packets. Every field position needs to account for which socket type captured the packet.

**Shared socket race condition** — in the port scanner, 100 threads sharing one receive socket meant any thread could grab any response. The fix — filtering responses by source port — required understanding that the response's source port identifies which port was scanned.

---

## Tools & Technologies

- **Language:** Python 3
- **Key modules:** `socket`, `struct`, `threading`, `concurrent.futures`
- **Platform:** Linux (raw sockets require Linux or macOS)
- **Privileges:** Root required for all tools
- **No external dependencies** — everything built from stdlib only

---

## References

- RFC 791 — Internet Protocol: https://tools.ietf.org/html/rfc791
- RFC 793 — Transmission Control Protocol: https://tools.ietf.org/html/rfc793
- RFC 768 — User Datagram Protocol: https://tools.ietf.org/html/rfc768
- RFC 1071 — Computing the Internet Checksum: https://tools.ietf.org/html/rfc1071
