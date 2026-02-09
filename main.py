import threading
from sniffer import start_sniffing
from port_scanner import runner
import time 

def main() :
    thread = threading.Thread(target = start_sniffing,daemon=True )
    thread.start()
    runner("127.0.0.1", range(1, 1024))
    while (True):
        time.sleep(1)
        
    

if __name__ == "__main__":
    main()
