"""
tools/sniffer.py — Raw Packet Sniffer
======================================

WHAT THIS FILE DOES:
Captures every packet passing through a network interface and
decodes it into human readable fields — exactly like Wireshark,
but built from scratch.

HOW IT WORKS AT A HIGH LEVEL:
1. Create a raw socket at the Ethernet layer
2. Put the network card in promiscuous mode (capture ALL traffic)
3. Loop forever receiving raw bytes
4. Parse those bytes using everything we know about IP/TCP/UDP headers
5. Print the results in a readable format
6. Stop cleanly when user presses Ctrl+C

WHY ROOT IS REQUIRED:
Raw sockets and promiscuous mode give you access to ALL network
traffic — including packets not addressed to you. This is a
powerful and potentially dangerous capability so the OS restricts
it to root only. Run with: sudo python3 sniffer.py
"""

import argparse
import socket
import struct


# ─────────────────────────────────────────────────────────────
# SOCKET CREATION
# ─────────────────────────────────────────────────────────────

def create_socket(interface: str) -> socket.socket:
    """
    Creates a raw socket and binds it to a network interface.

    WHAT IS AF_PACKET?
    ------------------
    Remember AF_INET operates at the IP layer — the Ethernet header
    is already stripped before you see the packet.

    AF_PACKET operates one layer lower — at the Ethernet layer.
    You see the COMPLETE raw frame including:
      - Ethernet header (14 bytes): src MAC, dst MAC, ethertype
      - IP header (20 bytes)
      - TCP/UDP header (20/8 bytes)
      - Data

    This is what Wireshark uses. It gives us the most complete
    view of what's actually on the wire.

    WHAT IS SOCK_RAW?
    -----------------
    Tells the OS: don't process this packet, give it to me raw.
    No stripping headers, no checksums, no port routing.
    Just raw bytes exactly as they arrived.

    WHAT IS ntohs(0x0003)?
    ----------------------
    The third argument is the Ethernet protocol filter.
    0x0003 is a special value meaning "capture ALL protocols"
    — IPv4, IPv6, ARP, everything.

    ntohs = Network To Host Short
    Converts the 2-byte value from network byte order (big-endian)
    to your CPU's byte order (little-endian on most systems).
    We do this because we're passing the value directly to the
    socket constructor without going through struct.pack.

    PROMISCUOUS MODE:
    -----------------
    By default your network card silently discards packets not
    addressed to your MAC address. You never see them.

    Promiscuous mode turns off that filter. Your card now accepts
    and passes up EVERY packet it sees on the network segment —
    traffic between other machines, broadcast traffic, everything.

    We enable it by setting a socket option:
      socket.SOL_SOCKET  = socket options level (general socket options)
      socket.SO_PROMISC  = the specific option to toggle promisc mode
      1                  = enable (0 would disable)

    Args:
        interface: Network interface name e.g. "eth0", "wlan0"

    Returns:
        Configured raw socket ready to capture packets
    """

    # Create the raw socket at Ethernet layer
    # AF_PACKET = Ethernet layer (lower than AF_INET which is IP layer)
    # SOCK_RAW  = give us complete raw packets
    # ntohs(0x0003) = capture all protocol types
    sock = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(0x0003)
    )

    # Bind to the specific network interface
    # The second argument 0 means "any protocol" — consistent with 0x0003 above
    # Without binding, we'd capture from all interfaces at once
    sock.bind((interface, 0))

    print(f"[*] Sniffer started on interface: {interface}")
    print(f"[*] Press Ctrl+C to stop\n")

    return sock


# ─────────────────────────────────────────────────────────────
# ETHERNET HEADER PARSING
# ─────────────────────────────────────────────────────────────

def parse_ethernet_header(raw_frame: bytes) -> tuple:
    """
    Parse the Ethernet header — the outermost layer of a raw frame.

    ETHERNET HEADER STRUCTURE (14 bytes):
    ----------------------------------------
    | Destination MAC (6 bytes) |
    | Source MAC      (6 bytes) |
    | EtherType       (2 bytes) |
    ----------------------------------------

    WHAT IS A MAC ADDRESS?
    ----------------------
    While IP addresses identify machines logically (and can change),
    MAC addresses identify network hardware physically. Every network
    card in the world has a unique MAC address burned in at manufacture.

    Format: 6 bytes written as aa:bb:cc:dd:ee:ff

    WHAT IS ETHERTYPE?
    ------------------
    Tells us what protocol is inside the Ethernet frame:
      0x0800 = IPv4
      0x0806 = ARP (Address Resolution Protocol)
      0x86DD = IPv6

    We only process 0x0800 (IPv4) in this sniffer.

    STRUCT FORMAT "!6s6sH":
    -----------------------
    ! = big endian (network byte order)
    6s = 6-byte string (destination MAC)
    6s = 6-byte string (source MAC)
    H  = unsigned short 2 bytes (EtherType)

    Args:
        raw_frame: Complete raw Ethernet frame bytes

    Returns:
        Tuple of (dst_mac, src_mac, ethertype, ip_payload)
        ip_payload = everything after the 14-byte Ethernet header
    """

    # Unpack the first 14 bytes as the Ethernet header
    # [0:14] = first 14 bytes
    dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", raw_frame[0:14])

    # Convert the 6 raw MAC bytes to readable "aa:bb:cc:dd:ee:ff" format
    # bytes_to_mac() is defined below
    dst_mac_str = bytes_to_mac(dst_mac)
    src_mac_str = bytes_to_mac(src_mac)

    # Everything after the 14-byte Ethernet header is the payload
    # For IPv4 packets this will be the IP header + TCP/UDP + data
    ip_payload = raw_frame[14:]

    return dst_mac_str, src_mac_str, ethertype, ip_payload


def bytes_to_mac(mac_bytes: bytes) -> str:
    """
    Convert 6 raw bytes into human readable MAC address string.

    Example:
        b'\\xaa\\xbb\\xcc\\xdd\\xee\\xff' → "aa:bb:cc:dd:ee:ff"

    HOW IT WORKS:
    -------------
    mac_bytes is a 6-byte sequence. We iterate over each byte,
    format it as a 2-digit hex string with :02x
      02 = pad with zeros to at least 2 digits
      x  = hexadecimal format
    Then join all 6 with colons.

    Args:
        mac_bytes: 6 bytes representing a MAC address

    Returns:
        Human readable MAC string e.g. "aa:bb:cc:dd:ee:ff"
    """
    # f"{b:02x}" formats each byte as 2-digit hex
    # ":".join() puts colons between them
    return ":".join(f"{b:02x}" for b in mac_bytes)


# ─────────────────────────────────────────────────────────────
# IP HEADER PARSING
# ─────────────────────────────────────────────────────────────

def parse_ip_header(ip_payload: bytes) -> tuple:
    """
    Parse the IPv4 header from raw bytes.

    You built this header from scratch in ip_header.py.
    Now we're doing the exact reverse — taking raw bytes and
    extracting each field back out using struct.unpack.

    STRUCT FORMAT "!BBHHHBBH4s4s":
    --------------------------------
    This is the EXACT same format string from ip_header.py
    but used with unpack instead of pack.

    pack   → Python values  → raw bytes   (sending)
    unpack → raw bytes      → Python values (receiving/parsing)

    IP HEADER BYTE MAP (reminder):
    --------------------------------
    Byte 0:      version(4bits) + IHL(4bits)
    Byte 1:      TOS
    Bytes 2-3:   Total Length
    Bytes 4-5:   Identification
    Bytes 6-7:   Flags + Fragment Offset
    Byte 8:      TTL
    Byte 9:      Protocol
    Bytes 10-11: Checksum
    Bytes 12-15: Source IP
    Bytes 16-19: Destination IP

    Args:
        ip_payload: Raw bytes starting at the IP header

    Returns:
        Dictionary containing all parsed IP header fields
    """

    # Unpack exactly 20 bytes (minimum IP header size)
    # We use [0:20] to take only the header, not the payload after it
    (ver_ihl, tos, total_length, identification,
     flags_frag, ttl, protocol, checksum,
     src_ip_raw, dst_ip_raw) = struct.unpack("!BBHHHBBH4s4s", ip_payload[0:20])

    # Remember version and IHL are packed into one byte
    # version is in the HIGH nibble (top 4 bits) → shift right by 4
    # ihl is in the LOW nibble (bottom 4 bits) → AND with 0x0F to mask top bits
    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F

    # IHL is in 4-byte words. Multiply by 4 to get actual byte count.
    # Standard header = IHL 5 = 20 bytes
    # If IHL > 5, there are IP options present (rare but possible)
    header_length = ihl * 4

    # flags are in top 3 bits of the 16-bit flags_frag field
    # frag_offset is in the bottom 13 bits
    flags = flags_frag >> 13
    frag_offset = flags_frag & 0x1FFF

    # Convert 4 raw bytes to dotted decimal IP string
    # inet_ntoa is the opposite of inet_aton
    # b'\xc0\xa8\x01\x01' → "192.168.1.1"
    src_ip = socket.inet_ntoa(src_ip_raw)
    dst_ip = socket.inet_ntoa(dst_ip_raw)

    return {
        "version": version,
        "header_length": header_length,  # in bytes
        "tos": tos,
        "total_length": total_length,
        "identification": identification,
        "flags": flags,
        "frag_offset": frag_offset,
        "ttl": ttl,
        "protocol": protocol,
        "checksum": checksum,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "header_length_raw": header_length,  # needed to find where TCP/UDP starts
    }


# ─────────────────────────────────────────────────────────────
# TCP HEADER PARSING
# ─────────────────────────────────────────────────────────────

def parse_tcp_header(ip_payload: bytes, ip_header_length: int) -> dict:
    """
    Parse the TCP header from raw bytes.

    WHERE DOES TCP START?
    ---------------------
    The TCP header starts immediately after the IP header.
    ip_header_length tells us how many bytes the IP header was.
    Standard = 20 bytes. With options = more.

    So TCP starts at: ip_payload[ip_header_length]

    TCP HEADER BYTE MAP (reminder):
    -------------------------------
    Bytes 0-1:   Source Port
    Bytes 2-3:   Destination Port
    Bytes 4-7:   Sequence Number (32-bit)
    Bytes 8-11:  Acknowledgment Number (32-bit)
    Bytes 12-13: Data Offset + Reserved + Flags
    Bytes 14-15: Window Size
    Bytes 16-17: Checksum
    Bytes 18-19: Urgent Pointer

    STRUCT FORMAT "!HHIIHHHH":
    -------------------------------
    ! = big endian
    H = unsigned short 2 bytes (ports, offset+flags, window, checksum, urgent)
    I = unsigned int   4 bytes (sequence number, ack number)

    Args:
        ip_payload:       Raw bytes starting at IP header
        ip_header_length: How many bytes the IP header was (usually 20)

    Returns:
        Dictionary containing all parsed TCP header fields
    """

    # TCP starts right after the IP header
    tcp_start = ip_header_length
    tcp_raw = ip_payload[tcp_start:tcp_start + 20]

    (src_port, dst_port, seq, ack_seq,
     offset_flags, window, checksum,
     urgent_ptr) = struct.unpack("!HHIIHHHH", tcp_raw)

    # Data offset is in the top 4 bits of the 16-bit offset_flags field
    # Shift right by 12 to move those 4 bits to the bottom
    data_offset = (offset_flags >> 12) * 4  # multiply by 4 = bytes

    # Flags are in the bottom 6 bits
    # AND with 0x3F (0b00111111) to keep only those 6 bits
    flags_raw = offset_flags & 0x3F

    # Decode individual flags by checking each bit
    # We AND with each flag's bit position to see if it's set
    flags = {
        "FIN": bool(flags_raw & 0x01),  # bit 0
        "SYN": bool(flags_raw & 0x02),  # bit 1
        "RST": bool(flags_raw & 0x04),  # bit 2
        "PSH": bool(flags_raw & 0x08),  # bit 3
        "ACK": bool(flags_raw & 0x10),  # bit 4
        "URG": bool(flags_raw & 0x20),  # bit 5
    }

    # Build a readable flag string like "SYN" or "SYN|ACK"
    # Only include flags that are set (True)
    flag_str = "|".join(name for name, val in flags.items() if val) or "NONE"

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack_seq": ack_seq,
        "data_offset": data_offset,
        "flags": flags,
        "flag_str": flag_str,
        "window": window,
        "checksum": checksum,
        "urgent_ptr": urgent_ptr,
    }


# ─────────────────────────────────────────────────────────────
# UDP HEADER PARSING
# ─────────────────────────────────────────────────────────────

def parse_udp_header(ip_payload: bytes, ip_header_length: int) -> dict:
    """
    Parse the UDP header from raw bytes.

    Much simpler than TCP — only 4 fields, 8 bytes total.

    UDP HEADER BYTE MAP:
    --------------------
    Bytes 0-1: Source Port
    Bytes 2-3: Destination Port
    Bytes 4-5: Length (header + data)
    Bytes 6-7: Checksum

    STRUCT FORMAT "!HHHH":
    ----------------------
    Four 2-byte unsigned shorts. That's it.

    Args:
        ip_payload:       Raw bytes starting at IP header
        ip_header_length: How many bytes the IP header was (usually 20)

    Returns:
        Dictionary containing all parsed UDP header fields
    """

    # UDP starts right after the IP header, same as TCP
    udp_start = ip_header_length
    udp_raw = ip_payload[udp_start:udp_start + 8]

    src_port, dst_port, length, checksum = struct.unpack("!HHHH", udp_raw)

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum,
    }


# ─────────────────────────────────────────────────────────────
# DISPLAY FUNCTIONS
# ─────────────────────────────────────────────────────────────

def display_packet(eth: dict, ip: dict, transport: dict, proto_name: str) -> None:
    """
    Print a clean, readable summary of a captured packet.

    We display the most useful fields for network analysis:
    - Protocol type
    - Source and destination with ports
    - Key IP fields (TTL tells us about the OS, flags tell us about fragmentation)
    - TCP specific fields if applicable (flags, sequence numbers, window)
    """

    print(f"{'─' * 60}")
    print(f"  Protocol : {proto_name}")
    print(f"  Ethernet : {eth['src_mac']} → {eth['dst_mac']}")
    print(f"  IP       : {ip['src_ip']}:{transport['src_port']} "
          f"→ {ip['dst_ip']}:{transport['dst_port']}")
    print(f"  TTL      : {ip['ttl']}  |  "
          f"Length: {ip['total_length']} bytes  |  "
          f"Checksum: {ip['checksum']:#06x}")

    # TCP has extra fields worth showing
    if proto_name == "TCP":
        print(f"  Flags    : {transport['flag_str']}")
        print(f"  Seq      : {transport['seq']}  |  "
              f"Ack: {transport['ack_seq']}")
        print(f"  Window   : {transport['window']} bytes")

    # UDP just shows the datagram length
    elif proto_name == "UDP":
        print(f"  UDP Len  : {transport['length']} bytes")


# ─────────────────────────────────────────────────────────────
# CLI FILTERING
# ─────────────────────────────────────────────────────────────

def matches_filter(ip: dict, transport: dict, args) -> bool:
    # If port filter set — check both src and dst port
    if args.port is not None:
        if transport["src_port"] != args.port and \
           transport["dst_port"] != args.port:
            return False

    # If IP filter set — check both src and dst IP
    if args.ip is not None:
        if ip["src_ip"] != args.ip and \
           ip["dst_ip"] != args.ip:
            return False

    # If protocol filter set
    if args.protocol is not None:
        if args.protocol.upper() == "TCP" and ip["protocol"] != 6:
            return False
        if args.protocol.upper() == "UDP" and ip["protocol"] != 17:
            return False

    return True   # passed all filters
# ─────────────────────────────────────────────────────────────
# MAIN SNIFFER LOOP
# ─────────────────────────────────────────────────────────────

def start_sniffing(interface: str = "eth0", args=None) -> None:
    """
    Main capture loop. Creates the socket and processes packets forever.

    THE CAPTURE LOOP:
    -----------------
    sock.recvfrom(65535) blocks — it pauses here and waits until
    a packet arrives. 65535 is the maximum IP packet size so we
    never truncate a packet.

    When a packet arrives:
      1. recvfrom returns (raw_bytes, address_info)
      2. We parse the Ethernet header first
      3. Check EtherType — only process IPv4 (0x0800)
      4. Parse IP header
      5. Check protocol field (byte 9) — TCP=6 or UDP=17
      6. Parse the appropriate transport header
      7. Display the results
      8. Go back to waiting

    PACKET COUNTER:
    ---------------
    We keep a simple counter to show how many packets were captured.
    Printed when the user stops the sniffer with Ctrl+C.

    KEYBOARDINTERRUPT:
    ------------------
    When you press Ctrl+C, Python raises a KeyboardInterrupt exception.
    Without the try/except, this would crash the program with an ugly
    traceback and leave the socket open.

    We catch it, print a summary, close the socket cleanly, and exit.

    Args:
        interface: Network interface to listen on (default "eth0")
                   Change to "wlan0" for wireless
    """
    sock = create_socket(interface)
    packet_count = 0

    try:
        while True:
            # Block here until a packet arrives
            # raw_frame = complete Ethernet frame as bytes
            # addr = (interface_name, protocol, ...) — we don't use this
            raw_frame, addr = sock.recvfrom(65535)

            # ── Step 1: Parse Ethernet header ──────────────────────
            dst_mac, src_mac, ethertype, ip_payload = parse_ethernet_header(raw_frame)

            eth_info = {"src_mac": src_mac, "dst_mac": dst_mac}

            # Only process IPv4 packets (EtherType 0x0800)
            # Ignore ARP (0x0806), IPv6 (0x86DD), etc.
            if ethertype != 0x0800:
                continue   # skip this packet, go back to waiting

            # ── Step 2: Parse IP header ─────────────────────────────
            ip_info = parse_ip_header(ip_payload)
            protocol = ip_info["protocol"]
            ip_header_len = ip_info["header_length"]

            # ── Step 3: Parse transport layer ──────────────────────
            # Protocol 6 = TCP, Protocol 17 = UDP
            # Anything else (ICMP etc.) we skip for now
            if protocol == 6:
                transport_info = parse_tcp_header(ip_payload, ip_header_len)
                proto_name = "TCP"

            elif protocol == 17:
                transport_info = parse_udp_header(ip_payload, ip_header_len)
                proto_name = "UDP"

            else:
                # ICMP, IGMP, and others — not handled yet
                continue

            if args is not None and not matches_filter(ip_info, transport_info, args):
                continue

            # ── Step 4: Display results ─────────────────────────────
            packet_count += 1
            display_packet(eth_info, ip_info, transport_info, proto_name)

    except KeyboardInterrupt:
        # User pressed Ctrl+C — clean up and exit gracefully
        print(f"\n\n[*] Sniffer stopped.")
        print(f"[*] Total packets captured: {packet_count}")
        sock.close()


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """
    WHAT IS if __name__ == "__main__"?
    ------------------------------------
    Every Python file has a built-in variable called __name__.

    When you RUN a file directly:
        python3 sniffer.py
        → __name__ is set to "__main__"
        → this block executes

    When you IMPORT a file from another file:
        import sniffer
        → __name__ is set to "sniffer" (the module name)
        → this block does NOT execute

    This lets the same file work both as a standalone script
    AND as a module that other files can import safely without
    accidentally starting the sniffer on import.

    CHANGE "eth0" TO YOUR INTERFACE:
    ---------------------------------
    Run 'ip link show' or 'ifconfig' in your terminal to see
    your available interfaces. Common ones:
        eth0  = wired ethernet
        wlan0 = wireless
        lo    = loopback (127.0.0.1, local only)
    """
    parser = argparse.ArgumentParser(description="NetProbe Sniffer")
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--port", type=int)
    parser.add_argument("--ip")
    parser.add_argument("--protocol")
    args = parser.parse_args()

    start_sniffing(interface=args.interface, args=args)