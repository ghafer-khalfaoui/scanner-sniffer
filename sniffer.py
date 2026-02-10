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
        raw_data, _ = sniffer.recvfrom(65535)
        if len(raw_data) < 34:
            continue

        _, _, eth_proto = struct.unpack("!6s6sH", raw_data[:14])

        # IPv4 only
        if eth_proto != 0x0800:
            continue

        ihl = (raw_data[14] & 0x0F) * 4
        ip_header = raw_data[14:14 + ihl]

        ttl, proto, src, dst = struct.unpack(
            "!8xBB2x4s4s", ip_header
        )

        # TCP only
        if proto != 6:
            continue

        src_ip = socket.inet_ntoa(src)
        dst_ip = socket.inet_ntoa(dst)

        if filter_ip and src_ip != filter_ip and dst_ip != filter_ip:
            continue

        tcp_start = 14 + ihl
        tcp_header = raw_data[tcp_start:tcp_start + 20]

        src_port, dst_port = struct.unpack("!HH", tcp_header[:4])
        flags = tcp_header[13]

        if dst_port not in scanned_ports:
            continue

        now = time.time()
        activity = scan_activity.get(src_ip, {"ports": set(), "time": now})

        if flags & 0x12:  # SYN-ACK
            open_ports.add(dst_port)
            activity["ports"].add(dst_port)

        if now - activity["time"] > 5:
            activity = {"ports": set([dst_port]), "time": now}

        scan_activity[src_ip] = activity

        if len(activity["ports"]) > 10:
            print(f"[ALERT] Port scan detected from {src_ip}")

        print(f"[TCP] {src_ip}:{src_port} → {dst_ip}:{dst_port}")
