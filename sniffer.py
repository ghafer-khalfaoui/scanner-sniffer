import socket
import struct
from shared import scanned_ports


def get_mac_addr(raw_data):
    bytes = map('{:02x}'.format, raw_data)
    return ':'.join(bytes).upper()


def start_sniffing(filter_ip=None):
    print("[*] Starting packet sniffer")

    try:
        sniffer = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(0x0003)
        )
    except PermissionError:
        print("[-] Run as root (sudo)")
        return

    while True:
        raw_data, _ = sniffer.recvfrom(65535)

        # Ethernet
        dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', raw_data[:14])
        eth_proto = socket.htons(eth_proto)

        # IPv4 only
        if eth_proto != 8:
            continue

        # IP header
        ihl = (raw_data[14] & 0x0F) * 4
        ip_header = raw_data[14:14 + ihl]

        ttl, proto, src, dst = struct.unpack(
            '! 8x B B 2x 4s 4s',
            ip_header
        )

        # TCP only
        if proto != 6:
            continue

        src_ip = socket.inet_ntoa(src)
        dst_ip = socket.inet_ntoa(dst)

        if filter_ip:
            if src_ip != filter_ip and dst_ip != filter_ip:
                continue

        
        tcp_start = 14 + ihl
        tcp_header = raw_data[tcp_start:tcp_start + 20]

        src_port, dst_port = struct.unpack('!HH', tcp_header[:4])

        
        if src_port not in scanned_ports and dst_port not in scanned_ports:
            continue

        flags = tcp_header[13]

        if flags & 0x12:
            state = "OPEN (SYN-ACK)"
        elif flags & 0x04:
            state = "CLOSED (RST)"
        elif flags & 0x02:
            state = "SYN"
        else:
            state = "OTHER"

        print(f"[SNIFFER] {state} | {src_ip}:{src_port} → {dst_ip}:{dst_port}")
