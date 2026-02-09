import socket
import concurrent.futures
from shared import scanned_ports


def scan_port(ip, port):
    # Register the port as being scanned
    scanned_ports.add(port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"[SCANNER] OPEN {ip}:{port}")
    except:
        pass

    sock.close()


def runner(target, ports):
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(scan_port, [target] * len(ports), ports)
