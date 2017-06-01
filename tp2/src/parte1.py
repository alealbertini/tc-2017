import logging
import argparse
import os
import numpy as np
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *

args = None
ECHO_REPLY = 0
TIME_EXCEEDED = 11
IPS = 0
RTTS = 1
SRC = 0
INFO = 1
	
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
	pid =  100+ttl
	hops = int(args.get('maxhops'))
	replay = False

	while hops > 0:
		print "TTL=", "%3d" % ttl,
		sys.stdout.flush()

		respuestas=[[[],[]],[]] #[ips],[info] // rtt

		for x in range(0,30):
			pid+=x
			ans, unans = sr(IP(dst=args.get('dest'), ttl=ttl) / ICMP(id = pid), verbose=False, timeout=float(args.get('timeout')))
		
			if len(ans) > 0:
				(snd, rcv) = ans[0]
				if rcv[ICMP].type in [TIME_EXCEEDED,ECHO_REPLY] and rcv.src not in respuestas[IPS][SRC]:
					respuestas[IPS][SRC].append(rcv.src)
					respuestas[IPS][INFO].append(rcv)
					respuestas[RTTS].append((rcv.time-snd.sent_time)*1000)	
				#print "->", "\t", toString(rcv), (rcv.time-snd.sent_time)*1000 
					if rcv[ICMP].type == ECHO_REPLY:
						replay = True
						break # llegamos

		if not respuestas[IPS][SRC]: #Si nadie me respondio, no se cual es el hop.
			print "->", "\t", "Timeout"
		else:
			for res in respuestas[IPS][INFO]: 
				print "->", "\t", toString(res), "\n"
				#print res+" "
			print "RTT Promedio: ",str(np.mean(respuestas[RTTS]))

		if replay:
			break

		#else:
		#	print "->", "\t", "Timeout"
		sys.stdout.flush()

		ttl = ttl + 1
		hops = hops - 1


if __name__ == '__main__':
    main()
