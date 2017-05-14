import logging
import argparse
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *

args = None
pkt_broadcast = 0
pkt_unicast = 0

def monitorear():
	sniff(prn = colector, store = 0)
	#sniff(prn=colector, filter="arp",  store=0)

def esBroadcast(pkt):
    return pkt.fields['dst'] == 'ff:ff:ff:ff:ff:ff'
    
def toString(pkt):
	return pkt.summary()
		
def frecuencia(cant, total):
	return round(float(cant) / float(total), 2)
	
def informacion(freq):
	if freq == 0:
		return Infinite
	if freq == 1:
		return 0
	return round(-math.log(freq, 2), 2)

def entropia(freq_b, freq_u):
	return freq_b * informacion(freq_b) + freq_u * informacion(freq_u)

def colector(pkt):
	global pkt_broadcast, pkt_unicast,
	
	print toString(pkt)
	if args.get('output'):
		file = PcapWriter(args.get('output'), append=True, sync=True)
		file.write(pkt)
			
	if esBroadcast(pkt):
		pkt_broadcast += 1
	else:
		pkt_unicast += 1
		
	pb = frecuencia(pkt_broadcast, pkt_broadcast+pkt_unicast)
	pu = frecuencia(pkt_unicast, pkt_broadcast+pkt_unicast)
	ib = informacion(pb)
	iu = informacion(pu) 
	h = entropia(pb, pu)
	print "Broadcast =", str(pb), "/", str(ib)
	print "Unicast =", str(pu), "/", str(iu)
	print "Entropia = " + str(h), "(max 1)"
		
def main(): 
	global args
	parser = argparse.ArgumentParser(description='tdc parte 1')
	parser.add_argument('--output', default='p1_output.pcap', \
		help = 'archivo donde guardar datos')
	parser.add_argument('--input', help = 'archivo donde leer datos')
	args = vars(parser.parse_args())
    
	if not args.get('input'):
		monitorear()
	else:
		a = rdpcap(args.get('input'))
		for pkt in a:
			colector(pkt)
        
if __name__ == '__main__':
    main()
