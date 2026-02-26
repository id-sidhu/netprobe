"""
core/tcp_header.py — TCP Header Construction from Scratch
==========================================================

WHAT IS TCP?
TCP (Transmission Control Protocol) sits on top of IP. While IP handles
routing packets from A to B, TCP handles:
  - Reliability: guarantees delivery via acknowledgments (ACKs)
  - Ordering: reassembles out-of-order segments
  - Flow control: doesn't overwhelm the receiver
  - Connection state: SYN → SYN-ACK → ACK (the "three-way handshake")

THE KEY DIFFERENCE FROM IP CHECKSUM:
TCP's checksum covers not just the TCP header+data, but also a "pseudo-header"
pulled from the IP layer. This means TCP and IP are coupled — the TCP checksum
will change if the source IP changes. This is intentional: it detects misrouted
packets.

RFC 793 is the spec: https://tools.ietf.org/html/rfc793

TCP HEADER STRUCTURE (20 bytes minimum):
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

import socket
import struct
import random


class TCPFlags:
    """
    TCP control flags. These single bits in the header control connection state.

    WHY DO FLAGS MATTER FOR SECURITY TOOLS?
    ----------------------------------------
    - SYN-only:        Starting a connection (SYN flood exploits this)
    - SYN+ACK:         Server's response to SYN
    - ACK-only:        Data acknowledgment
    - FIN:             Graceful close (one direction)
    - RST:             Abrupt close / reject
    - PSH:             "Deliver this immediately" — don't buffer
    - URG:             Urgent data present (rare, often exploited in old attacks)

    Port scanners like nmap send crafted flag combinations and analyze responses
    to fingerprint OSes and detect firewall behavior.
    """
    
    SYN = 0x02  # 0b00000010 — Synchronize (initiate connection)
    ACK = 0x10  # 0b00010000 — Acknowledgment
    FIN = 0x01  # 0b00000001 — Finish
    RST = 0x04  # 0b00000100 — Reset (abort connection)
    PSH = 0x08  # 0b00001000 — Push (don't buffer, deliver now)
    URG = 0x20  # 0b00100000 — Urgent pointer is valid

    # Common combinations
    SYN_ACK = SYN | ACK   # 0x12 — server's handshake response
    FIN_ACK = FIN | ACK   # 0x11 — graceful teardown step

    @staticmethod
    def to_string(flags: int) -> str:
        """Convert a flags byte to a human-readable label like 'SYN|ACK'."""
        names = []
        mapping = [
            (TCPFlags.FIN, "FIN"),
            (TCPFlags.SYN, "SYN"),
            (TCPFlags.RST, "RST"),
            (TCPFlags.PSH, "PSH"),
            (TCPFlags.ACK, "ACK"),
            (TCPFlags.URG, "URG"),
        ]
        for bit, name in mapping:
            if flags & bit:
                names.append(name)
        return "|".join(names) if names else "NONE"

    @staticmethod
    def from_string(flag_str: str) -> int:
        """
        Parse a string like "SYN" or "SYN|ACK" into the integer flags value.
        Useful for building packets from human-readable specifications.
        """
        mapping = {
            "FIN": TCPFlags.FIN,
            "SYN": TCPFlags.SYN,
            "RST": TCPFlags.RST,
            "PSH": TCPFlags.PSH,
            "ACK": TCPFlags.ACK,
            "URG": TCPFlags.URG,
        }
        result = 0
        for part in flag_str.upper().split("|"):
            part = part.strip()
            if part not in mapping:
                raise ValueError(f"Unknown TCP flag: '{part}'. Valid flags: {list(mapping.keys())}")
            result |= mapping[part]
        return result


class TCPHeader:
    """
    Represents and serializes a TCP header.

    Usage:
        tcp = TCPHeader(
            src_port=12345,
            dst_port=80,
            flags=TCPFlags.SYN
        )
        raw_bytes = tcp.build(src_ip="192.168.1.1", dst_ip="10.0.0.1")
    """

    def __init__(
        self,
        src_port: int,
        dst_port: int,
        flags: int = TCPFlags.SYN,
        seq: int = None,
        ack_seq: int = 0,
        window: int = 65535,
        urgent_ptr: int = 0,
        data: bytes = b"",
    ):
        """
        Args:
            src_port   : Source port number (1–65535).
                         For crafted packets, this is often randomized to avoid
                         conflicts with the OS's connection tracking.
            dst_port   : Destination port. 80=HTTP, 443=HTTPS, 22=SSH, etc.
            flags      : Control flags (use TCPFlags constants or | combinations).
            seq        : Sequence number. Tracks which byte of the stream this is.
                         ISN (Initial Sequence Number) should be random for security —
                         predictable ISNs led to TCP hijacking attacks in the 90s.
                         If None, we generate a random 32-bit value.
            ack_seq    : Acknowledgment number. "I've received everything up to
                         this byte, send me the next one." Only meaningful when
                         ACK flag is set.
            window     : Receive window size. Tells the sender how many bytes
                         the receiver can buffer. 65535 is the maximum without
                         window scaling (TCP option we're not implementing here).
            urgent_ptr : Only relevant when URG flag is set. Points to end of
                         urgent data. Rarely used in practice.
            data       : Payload bytes (application data). Usually empty for
                         crafted control packets like SYN.
        """
        self.src_port = src_port
        self.dst_port = dst_port
        self.flags = flags
        self.seq = seq if seq is not None else random.randint(0, 2**32 - 1)
        self.ack_seq = ack_seq
        self.window = window
        self.urgent_ptr = urgent_ptr
        self.data = data

        # Data Offset: indicates where the data begins (i.e., header length).
        # Measured in 32-bit words, just like IP's IHL.
        # Minimum TCP header = 20 bytes = 5 words. We don't use options.
        self.data_offset = 5

    def build(self, src_ip: str, dst_ip: str) -> bytes:
        """
        Serialize the TCP header + data into raw bytes.

        WHY DOES TCP'S build() NEED THE IPs?
        --------------------------------------
        TCP's checksum algorithm requires a "pseudo-header" — a temporary
        12-byte structure containing source IP, destination IP, protocol,
        and TCP segment length. This ties the TCP checksum to the IP
        addresses, so misrouted packets (with correct IP headers but wrong
        TCP payload) will be detected.

        The pseudo-header is ONLY used for checksum calculation.
        It is NOT transmitted on the wire.

        Args:
            src_ip: Source IP (must match the IP header you'll use)
            dst_ip: Destination IP

        Returns:
            TCP header + data as bytes.
        """
        # data_offset is in the HIGH nibble of this byte (top 4 bits).
        # The low 4 bits are reserved (set to 0).
        # So: (5 << 4) | 0 = 0x50
        data_offset_reserved = (self.data_offset << 4) + 0

        # TCP length = header (20 bytes) + data
        tcp_segment_length = 20 + len(self.data)

        # Build the pseudo-header for checksum calculation.
        # Structure (12 bytes):
        #   4s = source IP
        #   4s = destination IP
        #   B  = zero padding (always 0)
        #   B  = protocol (always 6 for TCP)
        #   H  = TCP segment length (header + data)
        pseudo_header = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(src_ip),   # source IP
            socket.inet_aton(dst_ip),   # destination IP
            0,                           # reserved zero byte
            socket.IPPROTO_TCP,          # protocol = 6
            tcp_segment_length,          # TCP length
        )

        # Build the TCP header with checksum = 0 first.
        # Format: "!HHIIHHHH"
        #   H = src_port
        #   H = dst_port
        #   I = seq (32-bit unsigned int)
        #   I = ack_seq (32-bit unsigned int)
        #   H = data_offset(4) + reserved(6) + flags(6) packed into 16 bits
        #   H = window
        #   H = checksum (0 for now)
        #   H = urgent pointer

        # Pack data_offset, reserved, and flags into the same 16-bit field.
        # Structure:
        #   [15:12] = data offset (4 bits)
        #   [11:6]  = reserved   (6 bits, must be 0)
        #   [5:0]   = flags      (6 bits)
        # Formula: (data_offset << 12) | (0 << 6) | flags
        offset_flags = (self.data_offset << 12) | (0 << 6) | self.flags

        tcp_header = struct.pack(
            "!HHIIHHHH",
            self.src_port,      # H: source port
            self.dst_port,      # H: destination port
            self.seq,           # I: sequence number (32-bit)
            self.ack_seq,       # I: acknowledgment number (32-bit)
            offset_flags,       # H: data offset + reserved + flags
            self.window,        # H: window size
            0,                  # H: checksum placeholder
            self.urgent_ptr,    # H: URG Pointer
        )

        # The checksum input = pseudo_header + tcp_header + data.
        # We checksum all of it together.
        checksum_input = pseudo_header + tcp_header + self.data
        checksum = self._calculate_checksum(checksum_input)

        # Rebuild with real checksum.
        tcp_header = struct.pack(
            "!HHIIHHHH",
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack_seq,
            offset_flags,
            self.window,
            checksum,           # ← real checksum
            self.urgent_ptr,
        )

        return tcp_header + self.data

    def _calculate_checksum(self, data: bytes) -> int:
        """
        Same RFC 1071 one's complement checksum as IP.
        (We could inherit from a base class — refactoring opportunity for later!)
        """
        if len(data) % 2 != 0:
            data += b'\x00'

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        return ~checksum & 0xFFFF

    def __repr__(self) -> str:
        return (
            f"TCPHeader(src_port={self.src_port}, dst_port={self.dst_port}, "
            f"flags={TCPFlags.to_string(self.flags)}, seq={self.seq:#010x}, "
            f"ack={self.ack_seq:#010x})"
        )