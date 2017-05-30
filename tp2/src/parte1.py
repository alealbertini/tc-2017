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
	parser.add_argument('--timeout', default=1.0, help = 'timeout')
	parser.add_argument('--maxhops', default=50, help = 'maximo numero de saltos')
	args = vars(parser.parse_args())
    
	ttl = 1
	hops = int(args.get('maxhops'))
	while hops > 0:
		print "TTL=", "%3d" % ttl,
		sys.stdout.flush()
		pid =  100+ttl
		ans, unans = sr(IP(dst=args.get('dest'), ttl=ttl) / ICMP(id = pid), verbose=False, timeout=float(args.get('timeout')))
		
		if len(ans) > 0:
			(req, res) = ans[0]
			print "->", "\t", toString(res), (res.time-req.sent_time) 
			if res[ICMP].type == 0:
				break # llegamos
		else:
			print "->", "\t", "Timeout"
		sys.stdout.flush()
		ttl = ttl + 1
		hops = hops - 1


if __name__ == '__main__':
    main()
