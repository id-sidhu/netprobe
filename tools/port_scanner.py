"""
tools/port_scanner.py — TCP SYN Port Scanner
=============================================

WHAT THIS FILE DOES:
Scans a target machine to discover which TCP ports are open,
closed, or filtered — exactly like nmap's -sS (SYN scan) mode,
but built from scratch.

HOW IT WORKS:
For each port we want to scan:
  1. Craft a raw TCP SYN packet using our IPHeader and TCPHeader classes
  2. Send it to the target port
  3. Wait for a response
  4. Analyze the response flags:
     SYN|ACK  → port is OPEN   (someone is listening)
     RST      → port is CLOSED (nothing listening, rejected)
     timeout  → port is FILTERED (firewall dropped our packet silently)

WHY IT'S CALLED A "HALF-OPEN" SCAN:
Normal TCP connection = SYN → SYN|ACK → ACK (three steps)
SYN scan            = SYN → SYN|ACK        (two steps, never completes)

We get the information we need (open or closed) without ever
completing the handshake. This is faster and stealthier than
a full connection scan.

WHY THREADING:
Scanning 1024 ports one by one, each waiting 2 seconds for a
response = potentially 2048 seconds (34 minutes) worst case.
With 100 threads running simultaneously, worst case drops to
~20 seconds. Order doesn't matter so parallel execution is safe.

WHY ROOT IS REQUIRED:
Crafting raw packets with custom IP/TCP headers requires root.
The OS won't let normal users bypass the network stack.
Run with: sudo python3 tools/port_scanner.py
"""

import os
import random
import socket
import struct
import sys
import threading

# ─────────────────────────────────────────────────────────────
# PATH SETUP
# ─────────────────────────────────────────────────────────────

# Add project root to Python's module search path.
# Without this, 'from core.ip_header import IPHeader' fails
# because Python only looks in the script's own directory (tools/)
# not the parent directory where core/ lives.
#
# os.path.abspath(__file__)        = full path to this file
# os.path.dirname(...)             = directory containing this file (tools/)
# os.path.dirname(...again...)     = parent directory (netprobe/)
# sys.path.insert(0, ...)          = add netprobe/ to search path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from concurrent.futures import ThreadPoolExecutor
from core.ip_header import IPHeader
from core.tcp_header import TCPFlags, TCPHeader


# ─────────────────────────────────────────────────────────────
# SHARED STATE
# ─────────────────────────────────────────────────────────────

# Shared list where threads store discovered open ports.
# All 100 threads write to this same list.
open_ports = []

# Threading lock to prevent race conditions on open_ports.
#
# WHAT IS A RACE CONDITION?
# -------------------------
# Two threads try to append to the list at the exact same moment.
# Internally, append() is not atomic — it involves multiple CPU
# instructions. If two threads interleave those instructions,
# the list can get corrupted — items lost or duplicated.
#
# A lock (mutex) prevents this by allowing only ONE thread to
# execute the protected block at a time. Other threads wait.
#
# Usage:
#   with lock:
#       open_ports.append(port)   # only one thread here at a time
lock = threading.Lock()


# ─────────────────────────────────────────────────────────────
# CORE SCAN FUNCTION
# ─────────────────────────────────────────────────────────────

def scan_port(target_ip: str, port: int, src_ip: str,
              send_sock: socket.socket, recv_sock: socket.socket) -> None:
    """
    Scan a single TCP port on the target machine.

    This function runs in its own thread — 100 copies of this
    function run simultaneously, each scanning a different port.

    THE SEND SIDE:
    --------------
    We build a complete IP + TCP packet from scratch using the
    classes we built in core/. The packet has:
      - IP header: src/dst IP, protocol=TCP, TTL=64
      - TCP header: random src port, target dst port, SYN flag set

    WHY RANDOM SOURCE PORT?
    -----------------------
    Each scan_port call uses a different random source port
    (50000-65535). This serves two purposes:
      1. Avoids conflicts with the OS's own connections
      2. Helps match responses back to the correct thread
         (the response's dst_port = our random src_port)

    THE RECEIVE SIDE:
    -----------------
    recv_sock is shared across all 100 threads. When a response
    arrives, any thread might grab it. We filter by checking if
    the response's SOURCE PORT matches the port we scanned.

    If it doesn't match, we loop and wait for the next packet.
    The timeout ensures we don't wait forever.

    BYTE POSITIONS IN RESPONSE (AF_INET — no Ethernet header):
    -----------------------------------------------------------
    Bytes 0-19:  IP header
    Bytes 20-39: TCP header
      Bytes 20-21: source port  ← which port replied
      Bytes 22-23: dest port    ← our random source port
      Bytes 32-33: offset+flags ← contains SYN, ACK, RST bits

    Args:
        target_ip  : IP address of the machine being scanned
        port       : Port number to scan (1-1024)
        src_ip     : Our own IP address (for IP header source field)
        send_sock  : Raw socket for sending crafted packets
        recv_sock  : Raw socket for capturing responses
    """

    # ── Build TCP header first ────────────────────────────────
    # TCP must be built before IP because IP's build() needs
    # to know the payload length (= TCP header size = 20 bytes)
    #
    # src_port: random high port to avoid OS conflicts
    # dst_port: the port we're probing
    # flags:    SYN only — we're initiating, not completing
    tcp_obj = TCPHeader(
        src_port=random.randint(50000, 65535),
        dst_port=port
        # flags defaults to TCPFlags.SYN — defined in TCPHeader.__init__
    )
    tcp_header = tcp_obj.build(src_ip, target_ip)

    # ── Build IP header second ────────────────────────────────
    # Now we know tcp_header is 20 bytes, so payload_length=20
    # protocol defaults to PROTO_TCP (6) in IPHeader.__init__
    ip_obj = IPHeader(src_ip, target_ip)
    ip_header = ip_obj.build(payload_length=len(tcp_header))

    # ── Combine into complete raw packet ──────────────────────
    # This is the complete packet that goes on the wire:
    # [IP header 20 bytes][TCP header 20 bytes] = 40 bytes total
    syn_packet = ip_header + tcp_header

    # ── Send the packet ───────────────────────────────────────
    # sendto() requires a destination tuple (ip, port).
    # The port here is 0 — for raw sockets the destination port
    # is embedded in the packet itself (TCP header), not here.
    send_sock.sendto(syn_packet, (target_ip, 0))

    # ── Wait for and process response ─────────────────────────
    try:
        while True:
            # Block here until a packet arrives or timeout fires.
            # recv_sock.settimeout(2) is set in main() —
            # if no packet arrives in 2 seconds, raises socket.timeout
            response, addr = recv_sock.recvfrom(65535)

            # RESPONSE FILTERING:
            # This recv_sock is shared by all 100 threads.
            # The response we just grabbed might be for port 443
            # while we're scanning port 80.
            # We check: does the response's source port match
            # the port we're currently scanning?
            #
            # response[20:22] = first 2 bytes of TCP header = source port
            # struct.unpack("!H", ...) converts 2 bytes to integer
            # [0] extracts the single value from the returned tuple
            resp_src_port = struct.unpack("!H", response[20:22])[0]

            if resp_src_port != port:
                continue   # not our response — loop and grab next packet

            # ── This response is ours — check the flags ───────
            # response[32:34] = bytes 12-13 of TCP header (offset from TCP start)
            # These 2 bytes contain: data_offset(4) + reserved(6) + flags(6)
            # & 0x3F masks out everything except the bottom 6 flag bits
            #
            # 0x3F = 0011 1111 — keeps only the 6 flag bits
            offset_flags = struct.unpack("!H", response[32:34])[0]
            flags = offset_flags & 0x3F

            if flags == 0x12:
                # 0x12 = 0001 0010 = SYN(0x02) | ACK(0x10)
                # Port is OPEN — someone is listening and responded
                # with lock ensures only one thread appends at a time
                with lock:
                    open_ports.append(port)

            elif flags == 0x04:
                # 0x04 = 0000 0100 = RST
                # Port is CLOSED — machine responded but nothing listening
                # We don't store closed ports — just move on
                pass

            # Got our response (open or closed) — exit the while loop
            break

    except socket.timeout:
        # No response within 2 seconds.
        # Port is FILTERED — firewall silently dropped our SYN.
        # We can't tell if the port is open or closed.
        # We don't store filtered ports — just move on silently.
        pass


# ─────────────────────────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────────────────────────

def main() -> None:
    """
    Entry point. Sets up sockets, launches threads, prints results.

    TWO SOCKETS — WHY?
    ------------------
    send_sock (AF_INET, IPPROTO_RAW):
        For sending crafted packets. IPPROTO_RAW tells the OS
        "I'm providing a complete IP header, send these bytes as-is."
        AF_INET means we work at the IP layer.

    recv_sock (AF_INET, IPPROTO_TCP):
        For capturing TCP responses. AF_INET means responses start
        at the IP header (no Ethernet header — simpler byte positions).
        IPPROTO_TCP means only capture TCP packets — filters out
        UDP, ICMP, and other noise automatically.

    We need two separate sockets because:
        send_sock needs IPPROTO_RAW to send with custom headers
        recv_sock needs IPPROTO_TCP to filter only TCP responses
    You can't do both with one socket.

    THREADPOOLEXECUTOR:
    -------------------
    Instead of creating 1024 individual threads (which would
    overwhelm the network), ThreadPoolExecutor maintains a pool
    of exactly max_workers=100 threads.

    executor.submit(scan_port, arg1, arg2, ...) adds a job to
    the queue. When a thread is free it picks up the next job.
    The 'with' block waits for ALL jobs to complete before
    continuing to the print statement.

    WHY src_ip IS FETCHED ONCE HERE:
    ---------------------------------
    socket.gethostbyname(socket.gethostname()) makes a system
    call to resolve your hostname to an IP. Calling this 1024
    times inside scan_port would be wasteful — it's the same
    answer every time. Fetch it once, pass it to every thread.
    """

    # Hardcoded for now — later we'll add argparse like the sniffer
    src_ip = '192.168.192.145'
    target_ip = '192.168.192.20'

    print(f"[*] Starting SYN scan on {target_ip}")
    print(f"[*] Scanning ports 1-1024")
    print(f"[*] Source IP: {src_ip}\n")

    # ── Create sending socket ─────────────────────────────────
    # AF_INET       = IP layer (we handle IP header ourselves)
    # SOCK_RAW      = raw socket, no kernel header processing
    # IPPROTO_RAW   = we provide complete IP header in each packet
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # Tell the OS we're including our own IP header.
    # Without this, the OS might add another IP header on top of ours.
    # IP_HDRINCL = "IP Header Included" — we built it ourselves
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # ── Create receiving socket ───────────────────────────────
    # AF_INET        = IP layer (response starts at IP header, no Ethernet)
    # SOCK_RAW       = raw socket, gives us complete packets
    # IPPROTO_TCP    = only capture TCP responses, filter out everything else
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # Set timeout — if no response in 2 seconds, port is filtered.
    # Without this, threads waiting on closed/filtered ports would
    # block forever and the scan would never complete.
    recv_sock.settimeout(2)

    # ── Launch threads ────────────────────────────────────────
    # max_workers=100 means at most 100 ports scanned simultaneously.
    # The 'with' block automatically waits for all jobs to finish
    # before moving to the results printing below.
    with ThreadPoolExecutor(max_workers=100) as executor:
        for i in range(1, 1025):
            # Submit one scan_port job per port.
            # executor manages which thread runs which job.
            executor.submit(scan_port, target_ip, i, src_ip, send_sock, recv_sock)

    # ── Print results ─────────────────────────────────────────
    # We reach here only after ALL 1024 ports have been scanned.
    # sorted() ensures ports print in numerical order regardless
    # of which thread finished first.
    print("\n[*] Scan complete")
    if open_ports:
        print(f"[*] Found {len(open_ports)} open port(s):\n")
        for port in sorted(open_ports):
            print(f"  Port {port}/tcp  open")
    else:
        print("[*] No open ports found (target may be down or all ports filtered)")

    # Clean up — close both sockets properly
    send_sock.close()
    recv_sock.close()


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    main()