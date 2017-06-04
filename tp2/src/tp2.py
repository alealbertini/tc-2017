import logging
import argparse
import os
import numpy as np
import bisect
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *
import requests
import webbrowser

args = None
ECHO_REPLY = 0
TIME_EXCEEDED = 11
IPS = 0
RTTS = 1

SRC = 0

DELTA = 0
INDICE_IP = 1

#arranca en 3
tau = [
 	    1.1511 ,	
 	    1.4250 	,	
 	    1.5712 	,
 	    1.6563 	 ,	
	    1.7110 	 ,
	    1.7491 	 ,	
	    1.7770 	,	
 	    1.7984 	,	
	    1.8153 ,
	    1.8290 	,
	    1.8403 	 ,
	    1.8498 	,
	    1.8579 	 ,
	    1.8649 ,
	    1.8710 	,
 	    1.8764 	,	
	    1.8811 	,
	    1.8853 	,
	   	1.8891 ,
	   	1.8926 ,
	   	1.8957 ,
	   	1.8985,
	   	1.9011,
	   	1.9035,
	   	1.9057 ,
	   	1.9078 ,
	   	1.9096 ,
	   	1.9114 ,
	   	1.9130,
	   	1.9146 ,
	   	1.9160,
	   	1.9174 ,
	   	1.9186 	,
	   	1.9198,
	   	1.9209,
	   	1.9220 	 		
]	

class Hop():
	def __init__(self, ip, rtt):
		self._ip = ip
		self._rtt = float(rtt)
		self._outlier  = False
		self._coords = None
		
	def IP(self):
		return self._ip
	def Coord(self):
		if self._coords is None:
			r = requests.get("http://freegeoip.net/json/"+self._ip)
			resp = r.json()
			lt = float(resp['latitude'])
			ln = float(resp['longitude'])
			if not (lt == 0 and ln == 0): 
				self._coords = (lt,ln)
		return self._coords
		
	def RTT(self):
		return self._rtt
	def setOutlier(self, outlier = True):
		self._outlier = outlier
	def isOutlier(self):
		return self._outlier 
	
def toString(pkt):
	return pkt.summary()
	
def main(): 
	global args
	parser = argparse.ArgumentParser(description='tdc tp2 parte 1')
	parser.add_argument('--dest', default='mit.edu', help = 'destino')
	parser.add_argument('--timeout', default=1.0, help = 'timeout')
	parser.add_argument('--maxhops', default=31, help = 'maximo numero de saltos')
	parser.add_argument('--maxiter', default=30, help = 'maximo numero iteraciones en una rafaga')
	parser.add_argument('--graficar-rutas', dest='graficar-rutas', action='store_true', default=False, help = 'Graficar rutas')
	parser.add_argument('--graficar-rtts', dest='graficar-rtts', action='store_true', default=False, help = 'Graficar rtts')
	args = vars(parser.parse_args())
    
	ttl = 1
	pid =  100+ttl
	hops = int(args.get('maxhops'))
	iteraciones = int(args.get('maxiter'))
	reply = False
	saltos = [] # Hop[]
	esta = [] # si la ip iesima esta considerada en el calculo de los delta. SI lo esta
	#contiene al indice del arreglo rttsDelta. Si no, -1.
	rttsZ = []
	rttsDelta = [] # (Delta RTT, indice en saltos[IP])

	while hops > 0:
	
		respuestas=[[],[]] #[ips del ttl], [[rtts de esa ip]]]
		

		for x in range(0, iteraciones):
			pid+=x
			ans, unans = sr(IP(dst=args.get('dest'), ttl=ttl) / ICMP(id = pid), verbose=False, timeout=float(args.get('timeout')))
		
			if len(ans) > 0:
				(snd, rcv) = ans[0]
				if rcv[ICMP].type in [ECHO_REPLY,TIME_EXCEEDED]:
					if  rcv.src not in respuestas[IPS]:
						respuestas[IPS].append(rcv.src)
						respuestas[RTTS].append([(rcv.time-snd.sent_time)*1000]) # ms
					else:
						indice = respuestas[IPS].index(rcv.src)
						respuestas[RTTS][indice].append((rcv.time-snd.sent_time)*1000)	
			
					if rcv[ICMP].type == ECHO_REPLY:
						reply = True
						break # llegamos

		if not respuestas[IPS]: #Si nadie me respondio, no se cual es el hop.
				respuestas[IPS].append(-1)
				respuestas[RTTS].append([0])

		#calculo datos del de mayor aparicion.

		max_indice = respuestas[RTTS].index(max(respuestas[RTTS], key=len))
		#print max_indice
		#saco promedio.
		media = np.mean(respuestas[RTTS][max_indice])

		saltos.append(Hop(respuestas[IPS][max_indice], media))
	
		if reply:
			break

		ttl = ttl + 1
		hops = hops - 1

	####### Calculo diferencia entre saltos #####

	max_rtts_Delta = next(x for x in saltos if x.RTT() > 0) # DR: max? primero con valor logico?
	indice_max_rtts_Delta = saltos.index(max_rtts_Delta)
	#rttsDelta.append((max_rtts_Delta, indice_max_rtts_Delta))
	for j in range(0,indice_max_rtts_Delta+1):
		esta.append(-1)
	#esta.append(-1)

	for i in range(indice_max_rtts_Delta+1,len(saltos)):

		if saltos[i].IP() == -1:	#no contestaron.
			esta.append(-1)
			continue
		dif = saltos[i].RTT()-max_rtts_Delta.RTT() #calculo dif entre saltos
		if dif >= 0: #agrego solo si da mayor o igual.
			rttsDelta.append((dif,i))
			esta.append(len(rttsDelta)-1)	#appendeo el indice donde esta la iesima ip en rttsDelta
			max_rtts_Delta = saltos[i]
		else:
			esta.append(-1)	

	rttDeltaPromedio = np.mean(rttsDelta)  #promedio y desvio de los saltos.
	rttDeltaDesvio = np.std(rttsDelta)	

	## Zrtt

	for i in range(0,len(rttsDelta)):
		#if esta[i]:
		rttsZ.append(abs(rttsDelta[i][DELTA]-rttDeltaPromedio)/rttDeltaDesvio)

	#calculo  de outliers
	hay_outlier = True
	rttsDelta_outlier = rttsDelta #para iterar en el otulier


	while(hay_outlier):
		desv_abs = []

		#calculo la desvio absoluto de los delta que quedan y los ordeno.
		for x in range(0,len(rttsDelta_outlier)):			
			bisect.insort(desv_abs,(abs(rttsDelta_outlier[x][DELTA]-rttDeltaPromedio),rttsDelta_outlier[x][INDICE_IP]))
	
		#Calculo tau de Thompson
		thompson = tau[len(desv_abs)-3]

		#outlier. Si el mas grande es mayor a tau por el desvio.
		desv_abs_mas_grande = desv_abs[-1]
		if desv_abs_mas_grande[DELTA] > (thompson*rttDeltaDesvio):
			# del(rttsDelta_outlier[esta[desv_abs[-1][INDICE_IP]]])
			#del(rttsDelta_outlier[esta[desv_abs[-1][INDICE_IP]]])
			#Lo marco como outlier
			saltos[desv_abs_mas_grande[INDICE_IP]].setOutlier(True)

			#Lo borro de la lista de desvios absolutos
			#rttsDelta_outlier = [(x for x in saltos[RTTS] if x[INDICE_IP] == desv_abs[-1][IND
			
			for x in xrange(1,10):
					pass	
			rttsDelta_outlier = [x for x in rttsDelta_outlier if x[INDICE_IP] != desv_abs_mas_grande[INDICE_IP]]

			#Recalculo promedo y desvio y vuelvo a empezar
			temp = [y[DELTA] for y in rttsDelta_outlier]
			promedio_outlier = np.mean(temp) # DR ??
			desvio_outlier = np.std(temp)

		else: 
			hay_outlier = False

	#imprimo resultados.		
		
	col_width_ips_avg = max(len(str(word.IP())) for word in saltos) + 2
	col_width_rtts_acum = max(len(str(word.RTT())) for word in saltos) + 2
	col_width_rtt_delta = max(len(str(word)) for word in rttsDelta) + 2
	col_width_rtt_z = max(len(str(word)) for word in rttsZ) + 2

	print "TTL".ljust(8), \
	"IP".ljust(col_width_ips_avg), \
	"RTT".ljust(col_width_rtts_acum), \
	"dRTT".ljust(col_width_rtt_delta), \
	"zdRTT".ljust(col_width_rtt_z), \
	"OUTLIER? "

	imprimio = False
	points = []
	for i in range(len(saltos)):
		imprimio = True
		responde = saltos[i].IP() 
			#Si responde y si lo hace, devuelve indice de esa ip en la lista de deltas.
		if responde != -1: #responde
			delta_index = esta[i]
			if delta_index != -1: # se lo considera en el calculo del delta.
				print str(i).ljust(8), \
				str(saltos[i].IP()).ljust(col_width_ips_avg), \
				str(saltos[i].RTT()).ljust(col_width_rtts_acum), \
				str(rttsDelta[delta_index][DELTA]).ljust(col_width_rtt_delta), \
				str(rttsZ[delta_index]).ljust(col_width_rtt_z), \
				"OUTLIER!" if saltos[i].isOutlier() else ""
				points.append(saltos[i])
			else:
				print str(i).ljust(8), \
				str(saltos[i].IP()).ljust(col_width_ips_avg), \
				str(saltos[i].RTT()).ljust(col_width_rtts_acum), \
				str(-1).ljust(col_width_rtt_delta), \
				str(-1).ljust(col_width_rtt_z)
				points.append(saltos[i])
				
		else: #No responde
			print str(i).ljust(8), \
			str("???").ljust(col_width_ips_avg), \
			"NA".ljust(col_width_rtts_acum), \
			"NA".ljust(col_width_rtt_delta), \
			"NA".ljust(col_width_rtt_z)
	
	if bool(args.get('graficar-rutas')):
		imgs = graficarMapas(points)
		for i in imgs:
			print i
			webbrowser.open(i, new=0, autoraise=True)
	if bool(args.get('graficar-rtts')):
		graficarInfo(points)
		
def graficarInfo(points):
	ind = range(len(points))
	fig, ax = plt.subplots()
	ax.bar(ind, [x.RTT() for x in points], 0.75)
	rtts=plt.axhline(y=1, label='tau', color='red', ls='--') # TODO
	plt.legend(handles=[rtts])
	plt.xticks(list(map(lambda x: x-0.4, ind)), [x.IP() for x in points], rotation=45)
	ax.set_title("TODO")
	ax.set_ylabel('rtts', color='b')
	
	#TODO
	#ax_twinx = ax.twinx()
	#s2 = np.sin(2 * np.pi * t)
	#ax_twinx.plot(t, s2, 'r.')
	#ax_twinx.set_ylabel('sin', color='r')
	
	plt.tight_layout()
	plt.show()
	
def graficarMapas(points):
	imgs = []
	imgs.append(graficarMapa(points))
	temp = []
	for p in points:
		if p.isOutlier():
			if len(temp) > 1:
				imgs.append(graficarMapa(temp))
			temp = []
		if not p in temp:
			temp.append(p)
		
	if len(temp) > 1:
		imgs.append(graficarMapa(temp))
	return imgs
	
def graficarMapa(points):
	img = "http://maps.googleapis.com/maps/api/staticmap?size=640x640&scale=2&path="
	paths = ""
	markers = ""
	first = True
	for p in points:
		coords = p.Coord()
		if coords is None:
			continue
		(lt, ln) = coords
		paths += ("" if first else "|") + str(lt) + "," + str(ln)
		markers += "&markers=color:blue|label:" + p.IP() + "|" + str(lt) + "," + str(ln)
		first = False
	return img + paths + markers
	
if __name__ == '__main__':
    main()
