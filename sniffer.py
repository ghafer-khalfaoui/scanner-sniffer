import socket
import struct
import time
from shared import open_ports, scanned_ports, scan_activity

def start_sniffing(filter_ip=None):
    print("[*] Sniffer started")

    try:
        sniffer = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(0x0003)
        )
    except PermissionError:
        print("[-] Run with sudo")
        return

    while True:
        try:
            raw_data, _ = sniffer.recvfrom(65535)
        except OSError:
            continue

        if len(raw_data) < 34:
            continue

        # Unpack Ethernet Header
        eth_header = raw_data[:14]
        eth_proto = struct.unpack("!H", eth_header[12:14])[0]

        # IPv4 only (0x0800)
        if eth_proto != 0x0800:
            continue

        # Unpack IP Header
        ihl = (raw_data[14] & 0x0F) * 4
        ip_header = raw_data[14:14 + ihl]
        
        # Unpack IP fields
        proto = ip_header[9]
        src_ip = socket.inet_ntoa(ip_header[12:16])
        dst_ip = socket.inet_ntoa(ip_header[16:20])

        # TCP only (Protocol 6)
        if proto != 6:
            continue

        # Filter IP if set
        if filter_ip and src_ip != filter_ip and dst_ip != filter_ip:
            continue

        # Unpack TCP Header
        tcp_start = 14 + ihl
        tcp_header = raw_data[tcp_start:tcp_start + 20]
        src_port, dst_port = struct.unpack("!HH", tcp_header[:4])
        flags = tcp_header[13]

        # --- THE FIX IS HERE ---
        # Only check ports we are actually scanning
        if dst_port not in scanned_ports and src_port not in scanned_ports:
            continue

        # Check specifically for SYN-ACK (0x12) 
        # We assume if we receive a SYN-ACK, the src_port is the open one on the target
        if flags == 0x12:
            if src_port not in open_ports:
                open_ports.add(src_port)
                print(f"[SNIFFER CONFIRM] Port {src_port} is OPEN!")
