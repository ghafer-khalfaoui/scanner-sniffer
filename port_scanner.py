import socket
import concurrent.futures
import itertools
    
    	
def scan_port(ip,port):
	target = ip
	
	sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM )
	sock.settimeout(1)
	try:
		result = sock.connect_ex((target,port))
		if result == 0:
            		print(f"port is open {port} ip : {target}")
            		try:
            			banner = sock.recv(1024)
            			banner = banner.decode().strip()
            			print(f"open port : {port} service {banner}")
            		except:
            			print(f"open port : {port} service unknown")
            			
        
	except Exception as e:
		print(f"error scanning port {port}: {e}")
	sock.close()
	
	
def runner(targets,ports):
     

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    	executor.map(scan_port, itertools.repeat(targets),ports)







