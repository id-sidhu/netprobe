"""
tools/handshake_monitor.py — TCP Handshake Monitor
====================================================

WHAT THIS FILE DOES:
Watches live network traffic and detects whenever a complete
TCP three-way handshake occurs — meaning a new connection was
successfully established between two machines.

Every time your browser opens a new connection, every time an
app connects to a server, every time SSH starts — this tool
sees it happen in real time.

HOW IT WORKS:
Captures every TCP packet using the same raw socket approach
as sniffer.py, but instead of just printing packets, it tracks
connection STATE across multiple packets using a dictionary.

THE THREE-WAY HANDSHAKE (reminder):
------------------------------------
  Packet 1: Client → Server   SYN          "I want to connect"
  Packet 2: Server → Client   SYN|ACK      "OK, I'm ready"
  Packet 3: Client → Server   ACK          "Great, let's go"

These three packets don't arrive together — they're mixed in
with hundreds of other packets. We track them by storing
connection state in a dictionary between packets.

THE STATE MACHINE:
------------------
Each connection moves through states:

  (no entry)   → see SYN      → "SYN_SENT"
  SYN_SENT     → see SYN|ACK  → "SYN_RECEIVED"
  SYN_RECEIVED → see ACK      → COMPLETE → print and remove

If a connection gets stuck (server never responds), it stays
in the dictionary indefinitely. A production tool would add
a cleanup timer — something to add as an improvement.

WHAT'S REUSED FROM SNIFFER:
----------------------------
This tool imports and reuses sniffer.py's parsing functions
directly — create_socket, parse_ethernet_header, parse_ip_header,
parse_tcp_header. No code duplication. This is why we built
those as separate functions rather than inline code.
"""

import os
import sys
import socket
import struct
import time

# ─────────────────────────────────────────────────────────────
# PATH SETUP
# ─────────────────────────────────────────────────────────────

# Add project root to Python's module search path so we can
# import from both tools/ and core/ directories.
# Same pattern used in port_scanner.py.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import parsing functions directly from sniffer.
# We don't need to rewrite any of this — the sniffer already
# handles all raw socket creation and packet parsing correctly.
from tools.sniffer import (create_socket, parse_ethernet_header,
                            parse_ip_header, parse_tcp_header)


# ─────────────────────────────────────────────────────────────
# SOCKET SETUP
# ─────────────────────────────────────────────────────────────

# Create a raw socket at the Ethernet layer, bound to eth0.
# AF_PACKET captures complete frames including Ethernet header.
# Same socket as the sniffer — we're just using the frames
# differently (tracking state instead of printing everything).
# Change 'eth0' to 'wlan0' if on wireless.
recv_sock = create_socket('eth0')


# ─────────────────────────────────────────────────────────────
# CONNECTION STATE TRACKER
# ─────────────────────────────────────────────────────────────

# Dictionary storing in-progress TCP handshakes.
#
# KEY: 4-tuple identifying a unique connection
#   (src_ip, src_port, dst_ip, dst_port)
#   Example: ('192.168.1.1', 54321, '10.0.0.1', 80)
#
# VALUE: dictionary with connection state and timestamp
#   {
#       'state':     'SYN_SENT' or 'SYN_RECEIVED',
#       'timestamp': time.time() when SYN was first seen
#   }
#
# WHY OUTSIDE THE LOOP:
# This MUST be defined before the while loop — not inside it.
# If defined inside the loop, it resets to {} on every packet,
# destroying all tracked connections. Handshakes span multiple
# packets so state must persist between loop iterations.
connections = {}


# ─────────────────────────────────────────────────────────────
# MAIN CAPTURE LOOP
# ─────────────────────────────────────────────────────────────

try:
    while True:

        # ── Capture one raw Ethernet frame ───────────────────
        # Blocks here until a packet arrives on the interface.
        # raw_frame = complete Ethernet frame as bytes
        # addr = (interface, protocol, ...) — not used here
        raw_frame, addr = recv_sock.recvfrom(65535)

        # ── Parse Ethernet header ─────────────────────────────
        # Strips the 14-byte Ethernet header and returns:
        # dst_m, src_m  = destination and source MAC addresses
        # ethertype     = protocol inside (0x0800 = IPv4)
        # ip_payload    = everything after Ethernet header
        dst_m, src_m, ethertype, ip_payload = parse_ethernet_header(raw_frame)

        # ── Parse IP header ───────────────────────────────────
        # Extracts all IP header fields into a dictionary.
        # We need ip_dict['protocol'] to filter TCP only,
        # and ip_dict['src_ip']/['dst_ip'] for the connection key.
        ip_dict = parse_ip_header(ip_payload=ip_payload)

        # ── Filter: only process TCP packets ─────────────────
        # Protocol 6 = TCP. We skip UDP (17), ICMP (1), etc.
        # Handshakes only happen in TCP — UDP has no connection state.
        if ip_dict['protocol'] == 6:

            # ── Parse TCP header ──────────────────────────────
            # Extracts ports, sequence numbers, flags etc.
            # header_length_raw tells parse_tcp_header where TCP starts
            # (IP header size varies if IP options are present)
            tcp_dict = parse_tcp_header(
                ip_payload,
                ip_header_length=ip_dict['header_length_raw']
            )

            # ── Build the connection key ───────────────────────
            # A 4-tuple uniquely identifies one TCP connection.
            # Two browser tabs to the same server have different
            # src_ports so they get different keys — no mixing up.
            #
            # key = as seen in THIS packet (src → dst)
            key = (
                ip_dict['src_ip'], tcp_dict['src_port'],
                ip_dict['dst_ip'], tcp_dict['dst_port']
            )

            # reversed_key = same connection but from the OTHER direction
            #
            # WHY WE NEED THIS:
            # The SYN|ACK response comes back with src and dst SWAPPED:
            #
            #   SYN:     src=192.168.1.1:54321  dst=10.0.0.1:80
            #   SYN|ACK: src=10.0.0.1:80        dst=192.168.1.1:54321
            #
            # When SYN|ACK arrives, its 'key' would be:
            #   ('10.0.0.1', 80, '192.168.1.1', 54321)
            # But we stored the SYN under:
            #   ('192.168.1.1', 54321, '10.0.0.1', 80)
            #
            # reversed_key lets us look up the original SYN entry
            # using the flipped addresses from the response packet.
            reversed_key = (
                ip_dict['dst_ip'], tcp_dict['dst_port'],
                ip_dict['src_ip'], tcp_dict['src_port']
            )

            # ── STATE MACHINE ─────────────────────────────────

            if tcp_dict['flags']['SYN'] and not tcp_dict['flags']['ACK']:
                # ── SYN only → new connection starting ────────
                # Client is initiating a connection.
                # Store it with state SYN_SENT and record when
                # we first saw it (for future timeout cleanup).
                #
                # 'key' here = (client_ip, client_port, server_ip, server_port)
                # This is the canonical key for this connection.
                connections[key] = {
                    'state': 'SYN_SENT',
                    'timestamp': time.time()
                }

            elif tcp_dict['flags']['SYN'] and tcp_dict['flags']['ACK']:
                # ── SYN|ACK → server responded ────────────────
                # Server accepted the connection request.
                # We look up using reversed_key because this packet's
                # src/dst are swapped compared to the original SYN.
                #
                # If we find the matching SYN entry, advance its state.
                # If not found — we missed the SYN (started monitoring
                # mid-connection) — silently ignore.
                if reversed_key in connections:
                    connections[reversed_key]['state'] = 'SYN_RECEIVED'

            elif tcp_dict['flags']['ACK'] and not tcp_dict['flags']['SYN']:
                # ── ACK only → potential handshake completion ──
                # This could be:
                #   a) The final ACK completing a handshake — we want this
                #   b) A normal data acknowledgment mid-connection — ignore
                #
                # We distinguish by checking if reversed_key exists in
                # connections AND is in state SYN_RECEIVED.
                # Only a handshake-completing ACK satisfies both conditions.
                if reversed_key in connections and \
                        connections[reversed_key]['state'] == 'SYN_RECEIVED':

                    # Handshake complete — new connection established
                    # key here = (client_ip, client_port, server_ip, server_port)
                    src_ip, src_port, dst_ip, dst_port = key
                    print(f"[+] HANDSHAKE COMPLETE")
                    print(f"    {src_ip}:{src_port} → {dst_ip}:{dst_port}")
                    print(f"    Time: {time.strftime('%H:%M:%S')}\n")

                    # Remove from dictionary — handshake is done,
                    # no need to track this connection anymore
                    del connections[reversed_key]

except KeyboardInterrupt:
    # User pressed Ctrl+C — shut down cleanly
    print(f"\n[*] Monitor stopped.")
    print(f"[*] Connections still in progress: {len(connections)}")
    recv_sock.close()