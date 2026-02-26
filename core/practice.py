import socket
import struct
import random

class IPHeader:

    PROTO_TCP = socket.IPPROTO_TCP   
    PROTO_UDP = socket.IPPROTO_UDP   
    PROTO_ICMP = socket.IPPROTO_ICMP 

    def __init__(
            self,
            src: str,
            dst: str,
            flags: int = 0,
            frag_offset: int = 0,
            ttl: int = 64,
            protocol: int = PROTO_TCP,
            tos: int=0,
    ):
        self.src = src
        self.dst = dst
        self.protocol = protocol
        self.ttl = ttl
        self.flags = flags
        self.frag_offset = frag_offset
        self.tos = tos

        self.version = 4
        self.ihl = 5

        self.identification = random.randint(1,65535)

    def build(self, payload_length:int = 0) -> bytes:
        ver_ihl = (self.version << 4) | self.ihl
        total_length = (self.ihl * 4) + payload_length
        flags_fragoffset = (self.flags << 13) | self.frag_offset

        src_ip = socket.inet_aton(self.src)
        dst_ip = socket.inet_aton(self.dst)

        header = struct.pack(
            "!BBHHHBB4s4s",
            ver_ihl,
            self.tos,
            total_length,
            self.identification,
            flags_fragoffset,
            self.protocol,
            0,
            src_ip,
            dst_ip,
        )
        checksum = self._calculate_checksum(header)

        header = struct.pack(
            "!BBHHHBB4s4s",
            ver_ihl,
            self.tos,
            total_length,
            self.identification,
            flags_fragoffset,
            self.protocol,
            checksum,
            src_ip,
            dst_ip,
        )

        return header

    def _calculate_checksum(self, data: bytes) -> int:
        
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
            f"IPHeader(src={self.src}, dst={self.dst}, "
            f"proto={self.protocol}, ttl={self.ttl}, id={self.identification:#06x})"
        )
    

    '''
    
    h - src p 
    h - dst p
    I - seq
    I - ack seq
    h - offset 4 , reserved 6 bits, flags 6 
    h - window
    h - 16 bit
    h - urg pointer
    '''