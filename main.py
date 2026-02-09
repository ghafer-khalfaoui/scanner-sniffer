import threading
import time
from sniffer import start_sniffing
from port_scanner import runner


def main():
    # Start sniffer in background
    sniffer_thread = threading.Thread(
        target=start_sniffing,
        args=("127.0.0.1",),
        daemon=True
    )
    sniffer_thread.start()

    # Run port scanner
    runner("127.0.0.1", range(1, 1024))

    # Keep main alive
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
