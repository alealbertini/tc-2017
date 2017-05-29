import logging
import argparse
import os
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *

args = None
	
def toString(pkt):
	return pkt.summary()
			
def main(): 
	global args
	parser = argparse.ArgumentParser(description='tdc tp2 parte 1')
	parser.add_argument('--dest', default='mit.edu', help = 'destino')
	parser.add_argument('--timeout', default='1', help = 'timeout')
	args = vars(parser.parse_args())
    
	ttl = 1
	max_hops = 50
	while max_hops > 0:
		pid =  100+ttl
		ans = sr1(IP(dst=args.get('dest'), ttl=ttl) / ICMP(id = pid), verbose=False, timeout=float(args.get('timeout')))
		if ans is None:
			print "???"
		else:	
			print toString(ans)
			if ans[ICMP].type == 0:
				break
		ttl = ttl + 1
		max_hops = max_hops - 1
			

if __name__ == '__main__':
    main()
