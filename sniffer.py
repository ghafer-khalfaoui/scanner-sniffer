import socket 
import struct 
def get_mac_addr (raw_data) :
	bytes=map('{:02x}'.format , raw_data)
	return ':'.join(bytes).upper() 	

def start_sniffing (filter_ip = None , filter_port=None) :
	print ("setting up sockets ")
	try:
		sniffer = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
	except AttributeError:
		print(" no packets found might be os issue")
		return
	except PermissionError:
		print("permission denied run with sudo ")
		return
	except Exception as e:
		print (f"ERRROR : {e}")
		return
	print("socket created")
	try:
		while(True) :
			raw_data , adress = sniffer.recvfrom(65535)
			print (f"data captured : {len(raw_data)} bytes")
			dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', raw_data[:14])
			dest = get_mac_addr(dest_mac)
			src = get_mac_addr(src_mac)
			eth_proto = socket.htons(eth_proto)
			print (f"destination : {dest} \nsource : {src} \nprotocol : {eth_proto}")
			if eth_proto == 8:
				
				ip_header = raw_data[14:34]
				# ! = Network Byte Order
				# 8x = Skip the first 8 bytes (Version, TOS, Length, ID, Fragment)
				# B  = TTL (1 byte)
				# B  = Protocol (1 byte) 
				# 2x = Skip header checksum (2 bytes)
				# 4s = Source IP (4 bytes)
				# 4s = Destination IP (4 bytes)
				ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', ip_header)
				src_ip = socket.inet_ntoa(src)
				target_ip = socket.inet_ntoa(target)
				if filter_ip is not None :
					if filter_ip != src_ip and target_ip != filter_ip:
						continue
				print(f"[+] IPv4 Packet | TTL: {ttl} | Protocol: {proto}")
				print(f"    Source: {src_ip} -> Destination: {target_ip}")
				print("-" * 50)
			else :
				print(f"a non ipv4 packet | protocol id {eth_proto}")
					     
					     		
	except KeyboardInterrupt:
		print ("sniffing stopped  ")
	
	
		
			
