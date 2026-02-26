"""
tools/packet_crafter.py — Interactive Packet Crafter
=====================================================

WHAT THIS FILE DOES:
Lets you manually craft and send any TCP or UDP packet with
full control over every field — source IP, destination IP,
ports, TTL, TCP flags, sequence numbers, window size.

This is the most flexible tool in NetProbe. Unlike the port
scanner which sends the same SYN to every port automatically,
the packet crafter lets YOU decide exactly what gets sent.

USE CASES:
- Test how a target responds to unusual flag combinations
  (e.g. RST to abort a connection, FIN to close one gracefully)
- Send packets with a spoofed source IP to test firewall rules
- Test how targets handle low TTL values
- Craft malformed or unexpected packets to probe IDS/firewall behavior
- Manually simulate specific stages of the TCP handshake

HOW IT WORKS:
1. Ask user for all packet fields with sensible defaults
2. Build IP + TCP (or UDP) headers using our core/ classes
3. Send via raw socket
4. Wait up to 3 seconds for a response
5. Parse and display the response flags, IPs, ports
6. Ask if user wants to send another packet

WHAT'S NEW COMPARED TO PORT SCANNER:
- Interactive input instead of hardcoded values
- Supports both TCP and UDP
- Displays detailed response information
- Loop to send multiple packets in one session
"""

import os
import sys
import socket
import struct
import random

# ─────────────────────────────────────────────────────────────
# PATH SETUP
# ─────────────────────────────────────────────────────────────

# Add project root to Python's path so imports from core/ work
# regardless of which directory you run this script from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ip_header import IPHeader
from core.tcp_header import TCPFlags, TCPHeader
from core.udp_header import UDPHeader


# ─────────────────────────────────────────────────────────────
# USER INPUT
# ─────────────────────────────────────────────────────────────

def get_user_input() -> dict:
    """
    Interactively collect all packet fields from the user.

    DESIGN PRINCIPLE — SENSIBLE DEFAULTS:
    Every field has a default so the user only needs to type
    what they want to change. Pressing Enter accepts the default.

    This pattern is used everywhere in CLI tools:
        value = input("Field [default: X]: ").strip()
        value = int(value) if value else X

    If the user typed something → use it (converted to correct type)
    If the user pressed Enter  → use the default

    PROTOCOL CHOICE AFFECTS LATER FIELDS:
    TCP has flags, sequence numbers, and window size.
    UDP has none of these — it's just ports and data.
    So we only ask for TCP-specific fields if protocol is TCP.

    Returns:
        Dictionary containing all packet fields ready to use
        in craft_and_send()
    """

    print("\n" + "=" * 50)
    print("  NetProbe Packet Crafter")
    print("=" * 50)

    # ── Source IP ─────────────────────────────────────────────
    # Defaults to your real IP via gethostbyname/gethostname.
    # User can override with any IP — including a spoofed one.
    # Spoofed source IPs are useful for testing firewall rules
    # but responses will go to the spoofed IP, not back to you.
    src_ip = input("Source IP [default: your IP]: ").strip()
    if not src_ip:
        src_ip = socket.gethostbyname(socket.gethostname())

    # ── Destination IP ────────────────────────────────────────
    # Required — no sensible default for where to send the packet.
    # Loop until user provides a value.
    dst_ip = input("Destination IP: ").strip()
    while not dst_ip:
        print("  Destination IP is required.")
        dst_ip = input("Destination IP: ").strip()

    # ── Protocol ──────────────────────────────────────────────
    # TCP (6) or UDP (17). Determines which transport header
    # we build and which fields we ask for next.
    # Anything other than "UDP" defaults to TCP.
    protocol_input = input("Protocol [TCP/UDP, default: TCP]: ").strip().upper()
    if protocol_input == "UDP":
        protocol = 17
    else:
        protocol = 6

    # ── TTL ───────────────────────────────────────────────────
    # Time To Live — each router decrements by 1.
    # Default 64 = Linux standard. Windows uses 128.
    # Set to 1 to see which first-hop router drops it.
    # Set to 255 to maximize reach across many hops.
    ttl_input = input("TTL [default: 64]: ").strip()
    ttl = int(ttl_input) if ttl_input else 64

    # ── Source Port ───────────────────────────────────────────
    # Random high port by default (50000-65535 = ephemeral range).
    # The target's response will come back to this port.
    # If you spoof the source IP, responses won't reach you anyway.
    src_port_input = input("Source port [default: random]: ").strip()
    src_port = int(src_port_input) if src_port_input else random.randint(50000, 65535)

    # ── Destination Port ──────────────────────────────────────
    # Which service to target. Common ports:
    # 22=SSH, 80=HTTP, 443=HTTPS, 53=DNS, 3389=RDP
    dst_port_input = input("Destination port [default: 80]: ").strip()
    dst_port = int(dst_port_input) if dst_port_input else 80

    # ── TCP-specific fields ───────────────────────────────────
    # Only asked if protocol is TCP. UDP has no flags, sequence
    # numbers, or window — those are TCP-only concepts.
    if protocol == 6:

        # Flags — the most powerful field in a packet crafter.
        # Controls connection behavior:
        #   SYN         = initiate connection (port scanner uses this)
        #   RST         = forcefully abort any existing connection
        #   FIN         = gracefully close connection
        #   ACK         = acknowledge received data
        #   SYN|ACK     = server's response to SYN (handshake step 2)
        #   PSH         = push data immediately, don't buffer
        #   URG         = urgent pointer is valid
        #
        # TCPFlags.from_string() handles parsing "SYN|ACK" style input
        # by splitting on | and OR-ing the individual flag values.
        print("  Flags: SYN, ACK, RST, FIN, PSH, URG, SYN|ACK, FIN|ACK")
        flag_input = input("Flags [default: SYN]: ").strip().upper()
        flags = TCPFlags.from_string(flag_input) if flag_input else TCPFlags.SYN

        # Sequence number — identifies position in the byte stream.
        # Random by default (mirrors real OS behavior and prevents
        # TCP hijacking as we discussed when building tcp_header.py).
        # Override with a specific value for advanced testing.
        seq_input = input("Sequence number [default: random]: ").strip()
        seq = int(seq_input) if seq_input else random.randint(0, 2**32 - 1)

        # Window size — advertises how much buffer space we have.
        # 65535 = maximum for non-scaled connections.
        # Setting this to 0 is a valid test — it tells the target
        # to stop sending (window probe scenario).
        window_input = input("Window size [default: 65535]: ").strip()
        window = int(window_input) if window_input else 65535

    else:
        # UDP doesn't use these fields — set to None
        flags = None
        seq = None
        window = None

    # Return all collected values as a single dictionary.
    # craft_and_send() receives this dict and uses each value.
    return {
        "src_ip":   src_ip,
        "dst_ip":   dst_ip,
        "protocol": protocol,
        "ttl":      ttl,
        "src_port": src_port,
        "dst_port": dst_port,
        "flags":    flags,
        "seq":      seq,
        "window":   window,
    }


# ─────────────────────────────────────────────────────────────
# PACKET BUILDING AND SENDING
# ─────────────────────────────────────────────────────────────

def craft_and_send(params: dict) -> None:
    """
    Build the packet from user params, send it, and display response.

    TWO SOCKETS — SAME PATTERN AS PORT SCANNER:
    --------------------------------------------
    send_sock (IPPROTO_RAW):
        For sending our crafted packet with custom IP header.
        IP_HDRINCL tells OS we're providing the IP header ourselves.

    recv_sock (IPPROTO_TCP or IPPROTO_UDP):
        For capturing the response. Protocol must match what we sent
        so we only capture relevant responses and ignore other traffic.

    WHY WE SWAP recv_sock FOR UDP:
    If we sent UDP, we need recv_sock to capture UDP responses.
    The initial recv_sock is TCP — we close it and open a UDP one.
    This ensures we don't miss UDP responses or capture wrong packets.

    Args:
        params: Dictionary from get_user_input() containing all fields
    """

    # ── Create sockets ────────────────────────────────────────
    # Sending socket — same for both TCP and UDP
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # IP_HDRINCL = "IP Header Included"
    # Tells the OS: don't add your own IP header, I've built mine.
    # Without this the OS would prepend another IP header, creating
    # a malformed double-header packet.
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Receiving socket — start with TCP, swap to UDP if needed
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    recv_sock.settimeout(3)   # wait max 3 seconds for a response

    # ── Build transport header ────────────────────────────────
    if params["protocol"] == 6:
        # TCP packet — build with all user-specified fields
        tcp_obj = TCPHeader(
            src_port=params["src_port"],
            dst_port=params["dst_port"],
            flags=params["flags"],
            seq=params["seq"],
            window=params["window"],
        )
        # build() calculates checksum using pseudo-header
        # (requires src and dst IPs — that's why we pass them here)
        transport_header = tcp_obj.build(params["src_ip"], params["dst_ip"])

    else:
        # UDP packet — simpler, just ports and checksum
        udp_obj = UDPHeader(
            src_port=params["src_port"],
            dst_port=params["dst_port"],
        )
        transport_header = udp_obj.build(params["src_ip"], params["dst_ip"])

        # Swap recv_sock to UDP so we capture UDP responses.
        # The TCP recv_sock would miss UDP packets entirely.
        recv_sock.close()
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        recv_sock.settimeout(3)

    # ── Build IP header ───────────────────────────────────────
    # Built AFTER transport header because we need len(transport_header)
    # for the IP total length field. Same order as port_scanner.py.
    ip_obj = IPHeader(
        src=params["src_ip"],
        dst=params["dst_ip"],
        protocol=params["protocol"],
        ttl=params["ttl"],
    )
    ip_header = ip_obj.build(payload_length=len(transport_header))

    # ── Combine into complete raw packet ──────────────────────
    # Final packet = IP header (20 bytes) + transport header (20 or 8 bytes)
    # This is exactly what goes on the wire.
    packet = ip_header + transport_header

    # ── Print send summary ────────────────────────────────────
    print(f"\n[*] Sending packet...")
    print(f"    {params['src_ip']}:{params['src_port']} → "
          f"{params['dst_ip']}:{params['dst_port']}")
    if params["protocol"] == 6:
        print(f"    Flags: {TCPFlags.to_string(params['flags'])}  "
              f"TTL: {params['ttl']}  "
              f"Seq: {params['seq']}")
    else:
        print(f"    Protocol: UDP  TTL: {params['ttl']}")

    # ── Send the packet ───────────────────────────────────────
    # sendto() requires (data, (dst_ip, port)) tuple.
    # Port is 0 for raw sockets — destination port is already
    # embedded inside the transport header we crafted.
    send_sock.sendto(packet, (params["dst_ip"], 0))
    print(f"[*] Packet sent ({len(packet)} bytes)")

    # ── Wait for response ─────────────────────────────────────
    print(f"[*] Waiting for response (3s timeout)...")

    try:
        while True:
            # Block until packet arrives or 3 second timeout fires.
            # We loop because recv_sock captures ALL TCP/UDP traffic —
            # we might grab packets unrelated to our probe first.
            response, addr = recv_sock.recvfrom(65535)

            # RESPONSE FILTERING:
            # Check if this response is actually for our packet.
            # The response's source port should match the port we targeted.
            # response[20:22] = first 2 bytes of TCP header = source port
            resp_src_port = struct.unpack("!H", response[20:22])[0]
            if resp_src_port != params["dst_port"]:
                continue   # not our response, grab next packet

            # ── Parse the response ────────────────────────────
            # Extract useful fields to display to the user.
            # All positions assume no Ethernet header (AF_INET socket).

            # IP header fields
            resp_src_ip  = socket.inet_ntoa(response[12:16])  # bytes 12-15
            resp_dst_ip  = socket.inet_ntoa(response[16:20])  # bytes 16-19
            resp_ttl     = response[8]                         # byte 8

            # TCP header fields
            resp_dst_port = struct.unpack("!H", response[22:24])[0]  # bytes 22-23
            offset_flags  = struct.unpack("!H", response[32:34])[0]  # bytes 32-33
            resp_flags    = offset_flags & 0x3F  # bottom 6 bits = flags

            # Display response summary
            print(f"\n[+] Response received!")
            print(f"    {resp_src_ip}:{resp_src_port} → {resp_dst_ip}:{resp_dst_port}")
            print(f"    Flags: {TCPFlags.to_string(resp_flags)}  TTL: {resp_ttl}")
            break   # got our response — exit the while loop

    except socket.timeout:
        # No response in 3 seconds.
        # Possible reasons:
        # - Port is filtered (firewall dropped our packet)
        # - Source IP was spoofed (response went elsewhere)
        # - Target is down
        print(f"[-] No response received (timeout)")

    # ── Clean up ──────────────────────────────────────────────
    # Always close sockets when done — releases OS resources
    send_sock.close()
    recv_sock.close()


# ─────────────────────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────────────────────

def main() -> None:
    """
    Entry point. Runs the packet crafter in a loop.

    WHY A LOOP:
    Unlike the sniffer (runs until Ctrl+C) or port scanner
    (scans a fixed range), the packet crafter is interactive —
    you craft one packet, see the result, then decide whether
    to craft another. The loop supports this workflow naturally.

    DEFAULT TO NO:
    The "send another?" prompt defaults to No (user must type 'y').
    This prevents accidental repeated packet sending — important
    when crafting RST or flood-style packets.
    """

    print("[*] NetProbe Packet Crafter")
    print("[*] Craft and send custom TCP/UDP packets")
    print("[*] Run with sudo — raw sockets require root\n")

    while True:
        # Collect inputs, build and send packet, show response
        params = get_user_input()
        craft_and_send(params)

        # Ask if user wants to send another packet.
        # Default is No — user must explicitly type 'y' to continue.
        again = input("\nSend another packet? [y/N]: ").strip().lower()
        if again != 'y':
            print("[*] Exiting packet crafter.")
            break


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    main()