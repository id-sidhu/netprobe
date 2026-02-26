"""
core/udp_header.py — UDP Header Construction from Scratch
==========================================================

WHAT IS UDP?
UDP (User Datagram Protocol) is TCP's simpler cousin.
It trades reliability for speed:
  - No connection setup (no handshake)
  - No acknowledgments or retransmission
  - No ordering guarantees
  - Minimal header overhead (8 bytes vs TCP's 20)

WHO USES UDP?
  - DNS (port 53): You want fast lookups, not guaranteed delivery
  - DHCP (port 67/68): Network configuration at boot
  - Video streaming (port varies): A dropped frame is better than a late one
  - VoIP / online games: Latency matters more than perfection
  - NTP (port 123): Time sync

WHY DOES UDP MATTER FOR SECURITY?
  - UDP flood attacks: Easy to generate massive volumes with no handshake overhead
  - DNS amplification: Small query → large response, used in DDoS amplification
  - UDP port scanning: Different responses reveal port state

UDP HEADER (just 8 bytes!):
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Data (variable)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

RFC 768: https://tools.ietf.org/html/rfc768
"""

import socket
import struct


class UDPHeader:
    """
    Represents and serializes a UDP header.

    Notice how much simpler this is than TCP. That simplicity is exactly
    why UDP is used for high-throughput applications — and also why it's
    easy to flood.

    Usage:
        udp = UDPHeader(src_port=54321, dst_port=53, data=b"\\x00\\x01...")
        raw_bytes = udp.build(src_ip="192.168.1.1", dst_ip="8.8.8.8")
    """

    def __init__(self, src_port: int, dst_port: int, data: bytes = b""):
        """
        Args:
            src_port : Source port (can be randomized for UDP floods/spoofing).
            dst_port : Destination port. Common targets: 53 (DNS), 123 (NTP),
                       161 (SNMP), 19 (chargen — classic amplification target).
            data     : Payload bytes. Often a DNS query, NTP request, etc.
        """
        self.src_port = src_port
        self.dst_port = dst_port
        self.data = data

    def build(self, src_ip: str, dst_ip: str) -> bytes:
        """
        Serialize UDP header + data into raw bytes.

        NOTE ON UDP CHECKSUM:
        ---------------------
        Unlike TCP where the checksum is mandatory, the UDP checksum is
        technically optional in IPv4 — a value of 0x0000 means "no checksum".
        However, in IPv6, UDP checksum is mandatory (since IPv6 has no IP
        header checksum). We always compute it here for correctness.

        Like TCP, UDP uses the same IP pseudo-header for checksum computation.
        This is defined in RFC 768.

        Args:
            src_ip: Must match the IP header (for checksum correctness).
            dst_ip: Destination IP.

        Returns:
            UDP header (8 bytes) + data.
        """

        # UDP length field = header (8 bytes) + data length.
        # This is different from IP's total_length which includes the IP header.
        udp_length = 8 + len(self.data)

        # Build the pseudo-header (same concept as TCP's).
        # 12 bytes: src_ip, dst_ip, zero, protocol=17, udp_length
        pseudo_header = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
            0,                          # zero padding byte
            socket.IPPROTO_UDP,         # protocol = 17
            udp_length,                 # UDP length (NOT TCP length, not IP length)
        )

        # Build UDP header with checksum = 0 for calculation.
        # Format: "!HHHH"
        #   H = source port
        #   H = destination port
        #   H = length
        #   H = checksum
        udp_header = struct.pack(
            "!HHHH",
            self.src_port,
            self.dst_port,
            udp_length,
            0,              # checksum = 0 initially
        )

        # Checksum covers: pseudo_header + udp_header + data
        checksum_input = pseudo_header + udp_header + self.data
        checksum = self._calculate_checksum(checksum_input)

        # Rebuild with real checksum.
        # Edge case: if checksum computes to 0x0000, we must send 0xFFFF instead.
        # (Because 0x0000 is the "no checksum" sentinel value in UDP.)
        if checksum == 0:
            checksum = 0xFFFF

        udp_header = struct.pack(
            "!HHHH",
            self.src_port,
            self.dst_port,
            udp_length,
            checksum,
        )

        return udp_header + self.data

    def _calculate_checksum(self, data: bytes) -> int:
        """RFC 1071 one's complement checksum — same algorithm as IP and TCP."""
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
            f"UDPHeader(src_port={self.src_port}, dst_port={self.dst_port}, "
            f"data_len={len(self.data)} bytes)"
        )