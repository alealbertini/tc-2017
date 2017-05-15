import logging
import argparse
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *	
import matplotlib.pyplot as plt
import networkx as nx

args = None
vistos = {} # key es la direccion, value la cantidad
ejes = []

def monitorear():
	sniff(prn=colector, store=0)

def dest(pkt):
    return pkt[ARP].pdst

def src(pkt):
    return pkt[ARP].psrc
    
def toString(pkt):
	return pkt.summary()
		
def frecuencia(cant, total):
	return round(float(cant) / float(total), 4)
	
def informacion(freq):
	if freq == 0:
		return 10000 
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

def graficarRed():
	freq, info, h = analisis()
	G = nx.DiGraph()
	G.add_edges_from(ejes)
	values = ['yellow' if info.get(node, 10000) < h else 'red'  for node in G.nodes()]
	labels = {}
	for u,v,d in G.edges(data=True):
		eje = (u,v)
		d['weight'] = ejes.count(eje)
		labels[eje] = ejes.count(eje)
		
		
	pos = nx.spring_layout(G, k = 1)
	nx.draw_networkx_edge_labels(G,pos,edge_labels=labels)
	nx.draw_networkx_labels(G,pos,font_size=15, font_weigth='bold')
	nx.draw(G, pos, cmap = plt.get_cmap('jet'), node_color = values, node_size=1200, with_labels=False)
	plt.show()
  
def procesar(pkt):
	global vistos,ejes
	# scapy no es un experto en filtros
	if not ARP in pkt:
		return 	
	s = src(pkt)
	d = dest(pkt)
	vistos[d] = 1 if not d in vistos else vistos[d] + 1
	ejes.append((s, d))
	
def colector(pkt):
	print toString(pkt)
	if args.get('output'):
		file = PcapWriter(args.get('output'), append=True, sync=True)
		file.write(pkt)
	procesar(pkt)
	mostrar_sumario()
	
def replay(pkt):	
	procesar(pkt)
		
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
		graficarRed()
if __name__ == '__main__':
    main()
