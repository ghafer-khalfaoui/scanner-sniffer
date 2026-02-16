import socket
import concurrent.futures
from shared import scanned_ports, open_ports

def scan_port(ip, port):
   
    scanned_ports.add(port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.5) 
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.add(port) 
            print(f"[SCANNER] {ip}:{port} is OPEN")
    except Exception:
        pass
    finally:
        sock.close()

def runner(target, ports):
    print(f"[*] Scanning {target}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(scan_port, [target]*len(ports), ports)
    print("[*] Scan finished.")

