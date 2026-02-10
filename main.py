import threading
import time
from sniffer import start_sniffing
from port_scanner import runner

def main():
    sniff_thread = threading.Thread(
        target=start_sniffing,
        daemon=True
    )
    sniff_thread.start()

    runner("127.0.0.1", range(1, 1024))

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
