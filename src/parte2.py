import logging
import argparse
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *	
import matplotlib.pyplot as plt
import pydot;

args = None
vistos = {} # key es la direccion, value la cantidad

def monitorear():
	sniff(prn=colector, store=0)

def dest(pkt):
    return pkt[ARP].pdst
    
def toString(pkt):
	return pkt.summary()
		
def frecuencia(cant, total):
	return round(float(cant) / float(total), 4)
	
def informacion(freq):
	if freq == 0:
		return Infinite 
	if freq == 1:
		return 0
	return round((-1)*math.log(freq, 2), 4)

def entropia(freq, info):
	h = 0
	for e in vistos:
		h += freq[e] * info[e]
	return h

def mostrar_sumario():
	freq, info, h = analisis()
	
	for e in vistos:
		print "%16s" % e, "\t", str(freq[e]), "/", str(info[e]), "*Destacado*" if info[e] < h else "";
	print "Entropia = ", str(h)
	
def analisis():
	global vistos
	freq = {}
	total = sum(vistos.values())
	for e in vistos:
		freq[e] =  frecuencia(vistos[e], total)
	info = {}
	for e in freq:
		info[e] = informacion(freq[e])
	
	h = entropia(freq, info)
	return freq, info, h

def graficarInfo():
	freq, info, h = analisis()
	by_info = sorted(info, key=info.get)
	ind = range(len(info))
	fig, ax = plt.subplots()
	ax.bar(ind, [info[x] for x in by_info], 0.75)
	entrop=plt.axhline(y=h, label='Entropia', color='red', ls='--')
	plt.legend(handles=[entrop])
	plt.xticks(list(map(lambda x: x-0.4, ind)), [x for x in by_info], rotation=45)
	ax.set_title("Informacion para cada simbolo de la fuente")
	plt.tight_layout()
	#plt.savefig('info_entropia.png')
	plt.show()
	
def colector(pkt):
	global vistos
	# scapy no es un experto en filtros
	if not ARP in pkt:
		return 
		
	print toString(pkt)
	if args.get('output'):
		file = PcapWriter(args.get('output'), append=True, sync=True)
		file.write(pkt)
	d = dest(pkt)
	vistos[d] = 1 if not d in vistos else vistos[d] + 1
	mostrar_sumario()
	
def replay(pkt):
	global vistos
	# scapy no es un experto en filtros
	if not ARP in pkt:
		return 
		
	d = dest(pkt)
	vistos[d] = 1 if not d in vistos else vistos[d] + 1
		
def main(): 
	global args
	parser = argparse.ArgumentParser(description='tdc parte 2')
	parser.add_argument('--output', default='p2_output.pcap', help = 'archivo donde guardar datos')
	parser.add_argument('--input', help = 'archivo donde leer datos')
	args = vars(parser.parse_args())
    
	if not args.get('input'):
		monitorear()
	else:
		a = rdpcap(args.get('input'))
		for pkt in a:
			replay(pkt)
		mostrar_sumario()
		graficarInfo()
		
if __name__ == '__main__':
    main()
