"""
core/ip_header.py — IPv4 Header Construction from Scratch
==========================================================

WHAT IS AN IP HEADER?
Every packet traveling across the internet begins with an IP header.
It's the envelope — it tells routers where the packet came from,
where it's going, and how to handle it. We're building this byte
by byte, which means we need to understand exactly what each field
means and how big it is.

RFC 791 is the spec: https://tools.ietf.org/html/rfc791
"""

import socket
import struct
import random


class IPHeader:
    """
    Represents and serializes an IPv4 header.

    Usage:
        ip = IPHeader(src="192.168.1.1", dst="10.0.0.1")
        raw_bytes = ip.build(payload_length=20)  # 20 = TCP header size
    """

    # Protocol numbers are standardized by IANA.
    # When the IP layer receives a packet, it looks at this field
    # to know which module should handle the payload.
    PROTO_TCP = socket.IPPROTO_TCP   # 6
    PROTO_UDP = socket.IPPROTO_UDP   # 17
    PROTO_ICMP = socket.IPPROTO_ICMP # 1

    def __init__(
        self,
        src: str,
        dst: str,
        protocol: int = PROTO_TCP,
        ttl: int = 64,
        flags: int = 0,
        frag_offset: int = 0,
        tos: int = 0,
    ):
        """
        Args:
            src          : Source IP as dotted-decimal string e.g. "192.168.1.1"
            dst          : Destination IP as dotted-decimal string
            protocol     : What's inside the payload? TCP=6, UDP=17, ICMP=1
            ttl          : Time To Live — each router decrements this by 1.
                           When it hits 0, the packet is dropped and an ICMP
                           "Time Exceeded" is sent back. Prevents infinite loops.
                           Linux default is 64, Windows is 128.
            flags        : 3-bit field.
                           Bit 0: Reserved, must be 0
                           Bit 1: DF (Don't Fragment) — routers must not split packet
                           Bit 2: MF (More Fragments) — more fragments follow this one
            frag_offset  : If a large packet was fragmented, this tells the receiver
                           where in the original datagram this fragment belongs.
                           Unit is 8-byte blocks (so multiply by 8 to get byte offset).
            tos          : Type of Service — used for QoS (Quality of Service).
                           Modern networks use DSCP instead, but this byte remains.
        """
        self.src = src
        self.dst = dst
        self.protocol = protocol
        self.ttl = ttl
        self.flags = flags
        self.frag_offset = frag_offset
        self.tos = tos

        # IP header version. We're always IPv4 here.
        self.version = 4

        # IHL = Internet Header Length, measured in 32-bit words (4-byte units).
        # A standard header with no options = 20 bytes = 5 words.
        # Options can extend this up to 60 bytes (15 words), but we won't use them.
        self.ihl = 5

        # Identification: a 16-bit ID assigned by the sender.
        # If a packet is fragmented, all fragments share the same ID so the
        # receiver can reassemble them. We randomize it for each instance.
        self.identification = random.randint(1, 65535)

    def build(self, payload_length: int = 0) -> bytes:
        """
        Serialize the IP header into raw bytes ready to send.

        STRUCT FORMAT STRING EXPLAINED: "!BBHHHBBH4s4s"
        -----------------------------------------------
        '!'  = Network byte order (Big-Endian). The internet standard.
               x86 CPUs are Little-Endian, so struct handles the flip for us.
               CRITICAL: Without this, your checksums and lengths will be wrong.

        'B'  = unsigned char  = 1 byte  (8 bits)
        'H'  = unsigned short = 2 bytes (16 bits)
        '4s' = 4-byte string  (used for packed IP addresses)

        Field by field:
          B  = version(4) + ihl(4) packed into 1 byte  ← we do this manually below
          B  = tos
          H  = total_length (header + payload)
          H  = identification
          H  = flags(3 bits) + frag_offset(13 bits) packed into 2 bytes
          B  = ttl
          B  = protocol
          H  = checksum (0 during calculation, then replaced)
          4s = source IP as 4 packed bytes
          4s = destination IP as 4 packed bytes

        Args:
            payload_length: Size of the payload (e.g., TCP header + data) in bytes.

        Returns:
            20-byte IP header as bytes object.
        """

        # Total length = IP header (20 bytes) + everything after it
        total_length = (self.ihl * 4) + payload_length

        # Pack version and IHL into a single byte.
        # version=4 goes in the HIGH nibble, ihl=5 in the LOW nibble.
        # Visually: 0100 0101 = 0x45
        # (4 << 4) shifts 4 into position: 0100_0000
        # | 5 sets the lower bits:         0100_0101
        ver_ihl = (self.version << 4) | self.ihl

        # Pack flags and fragment offset into a 16-bit field.
        # flags occupy the top 3 bits, frag_offset the bottom 13.
        # (flags << 13) | frag_offset
        flags_frag = (self.flags << 13) | self.frag_offset

        # Convert dotted-decimal IPs to 4-byte packed binary.
        # "192.168.1.1" → b'\xc0\xa8\x01\x01'
        # socket.inet_aton does exactly this conversion.
        src_bytes = socket.inet_aton(self.src)
        dst_bytes = socket.inet_aton(self.dst)

        # First pass: build the header with checksum = 0.
        # We MUST set checksum to 0 before computing it — the algorithm
        # treats the checksum field as 0 during computation.
        header = struct.pack(
            "!BBHHHBBH4s4s",
            ver_ihl,           # B: version + IHL
            self.tos,          # B: type of service
            total_length,      # H: total packet length
            self.identification,# H: packet ID
            flags_frag,        # H: flags + fragment offset
            self.ttl,          # B: time to live
            self.protocol,     # B: next-layer protocol
            0,                 # H: checksum placeholder — MUST be 0 first
            src_bytes,         # 4s: source address
            dst_bytes,         # 4s: destination address
        )

        # Second pass: compute the real checksum and rebuild.
        checksum = self._calculate_checksum(header)

        # Rebuild with the actual checksum slotted in.
        header = struct.pack(
            "!BBHHHBBH4s4s",
            ver_ihl,
            self.tos,
            total_length,
            self.identification,
            flags_frag,
            self.ttl,
            self.protocol,
            checksum,          # ← real checksum now
            src_bytes,
            dst_bytes,
        )

        return header

    def _calculate_checksum(self, data: bytes) -> int:
        """
        RFC 1071 Internet Checksum Algorithm.

        WHY DO WE NEED A CHECKSUM?
        --------------------------
        Network hardware can corrupt bits. The checksum lets the receiver
        detect this. If the received checksum doesn't match, the packet
        is silently discarded.

        HOW IT WORKS (One's Complement Sum):
        -------------------------------------
        1. Split the header into 16-bit (2-byte) words.
        2. Add all the words together. If any addition overflows 16 bits,
           wrap the overflow back into the sum (one's complement addition).
        3. Take the bitwise complement (flip all bits) of the result.
        4. That's your checksum.

        VERIFICATION (how the receiver checks it):
        -------------------------------------------
        The receiver runs the same algorithm on the received header
        INCLUDING the checksum field. If everything is intact, the result
        will be 0xFFFF (all ones), which in one's complement means "valid".

        Args:
            data: The raw bytes to checksum (header with checksum field = 0).

        Returns:
            16-bit checksum as an integer.
        """
        # If data length is odd, pad with a zero byte.
        # The algorithm works on 16-bit pairs, so we need even length.
        if len(data) % 2 != 0:
            data += b'\x00'

        checksum = 0

        # Iterate over 2 bytes at a time.
        # range(0, len, 2) gives us indices: 0, 2, 4, 6, ...
        for i in range(0, len(data), 2):
            # Combine two adjacent bytes into a 16-bit word.
            # data[i] is the HIGH byte, data[i+1] is the LOW byte.
            # (high << 8) shifts it 8 bits left to make room for low.
            # Example: 0x45 and 0x00 → 0x4500
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        # Handle overflow: if the sum exceeded 16 bits, the upper bits
        # (the "carry") need to be folded back in.
        # (checksum >> 16) extracts the carry (bits above position 15).
        # We keep doing this until there's no carry left.
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        # One's complement: flip every bit.
        # ~checksum in Python gives a negative number because Python integers
        # are arbitrary-precision, so we AND with 0xFFFF to keep only 16 bits.
        return ~checksum & 0xFFFF

    def __repr__(self) -> str:
        return (
            f"IPHeader(src={self.src}, dst={self.dst}, "
            f"proto={self.protocol}, ttl={self.ttl}, id={self.identification:#06x})"
        )