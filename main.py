import threading
import time
from sniffer import start_sniffing
from port_scanner import runner
from shared import open_ports


def main():
    sniffer_thread = threading.Thread(target=start_sniffing,args=("127.0.0.1",),daemon=True
    )
    sniffer_thread.start()
    runner("127.0.0.1", range(1, 1024))
    while True:
        time.sleep(1)
        for port in sorted(open_ports):
            print(f"open port : {port}")
        print ("="*50)



if __name__ == "__main__":
    main()
