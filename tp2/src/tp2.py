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
	def __init__(self, ttl, ip, rtt):
		self._ip = ip
		self._drtt = None
		self._zrtt = None
		self._rtt = rtt
		self._outlier  = False
		self._coords = None
		self._ttl = ttl
		
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
		
	def TTL(self):
		return self._ttl
		
	def setDeltaRTT(self, drtt):
		self._drtt = drtt
		
	def deltaRTT(self):
		return self._drtt 
		 
	def setZRTT(self, zrtt):
		self._zrtt = zrtt
		
	def ZRTT(self):
		return self._zrtt 
		
	def setOutlier(self, outlier = True, thresholdCrossed = None):
		self._outlier = outlier
		self._threshold = thresholdCrossed
		
	def isOutlier(self):
		return self._outlier 
	
	def thresholdCrossed(self):
		return self._threshold 
		
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
	
	while hops > 0:
	
		respuestas=[[],[]] #[ips del ttl], [[rtts de esa ip]]]
		

		for x in range(0, iteraciones):
			pid += x
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
			saltos.append(Hop(ttl, None, None))
		else:
			#calculo datos del de mayor aparicion.
			max_indice = respuestas[RTTS].index(max(respuestas[RTTS], key=len))
			media = np.percentile(respuestas[RTTS][max_indice], 90)
			saltos.append(Hop(ttl, respuestas[IPS][max_indice], media))
			
		if reply:
			break

		ttl = ttl + 1
		hops = hops - 1

	####### Calculo diferencia entre saltos #####

	saltos_analizables = [x for x in saltos if not x.RTT() is None and not x.IP() is None]
	ultimo_salto_delta = None
	for i in saltos_analizables:
		if ultimo_salto_delta is None:
			ultimo_salto_delta = i
			continue
		dif = i.RTT() - ultimo_salto_delta.RTT()
		if dif > 0:
			i.setDeltaRTT(dif)
		ultimo_salto_delta = i # ponerle 1 tab mas para no saltear este nodo si dif < 0
			
	rttsDelta = [x.deltaRTT() for x in saltos if not x.deltaRTT() is None]
	rttDeltaPromedio = np.mean(rttsDelta)  #promedio y desvio de los saltos.
	rttDeltaDesvio = np.std(rttsDelta)	
	
	for i in saltos_analizables:
		if not i.deltaRTT() is None:
			i.setZRTT((abs(i.deltaRTT()-rttDeltaPromedio)/rttDeltaDesvio))
	
	#calculo  de outliers
	hay_outlier = True

	while(hay_outlier):
		desv_abs = []
		posibles_outliers = [x for x in saltos_analizables if not x.deltaRTT() is None and not x.isOutlier()]
		#calculo la desvio absoluto de los delta que quedan y los ordeno.
		for x in posibles_outliers:	
			bisect.insort(desv_abs,(abs(x.deltaRTT()-rttDeltaPromedio), x))
	
		#Calculo tau de Thompson
		thompson = tau[len(desv_abs)-3]

		#outlier. Si el mas grande es mayor a tau por el desvio.
		(delta, salto) = desv_abs[-1]
		if delta > (thompson * rttDeltaDesvio):
			salto.setOutlier(True, thresholdCrossed = thompson * rttDeltaDesvio)
		else: 
			hay_outlier = False

	#imprimo resultados.		
		
	col_width_ips_avg = max(len(str(word.IP())) for word in saltos) + 2
	col_width_rtts_acum = max(len(str(word.RTT())) for word in saltos) + 2
	col_width_rtt_delta = max(len(str(word.deltaRTT())) for word in saltos) + 2
	col_width_rtt_z = max(len(str(word.ZRTT())) for word in saltos) + 2

	print "TTL".ljust(6), \
	"IP".ljust(col_width_ips_avg), \
	"RTT".ljust(col_width_rtts_acum), \
	"dRTT".ljust(col_width_rtt_delta), \
	"zdRTT".ljust(col_width_rtt_z), \
	"OUTLIER? "

	points = []
	for i in saltos:
		print str(i.TTL()).ljust(6), \
				strDisplay(i.IP(), "?").ljust(col_width_ips_avg), \
				numDisplay(i.RTT(), suffix= "ms").ljust(col_width_rtts_acum), \
				numDisplay(i.deltaRTT(), suffix= "ms").ljust(col_width_rtt_delta), \
				numDisplay(i.ZRTT()).ljust(col_width_rtt_z), \
				"OUTLIER!" if i.isOutlier() else ""
		if not i.IP() is None:
			points.append(i)
	
	if bool(args.get('graficar-rutas')):
		imgs = graficarMapas(points)
		for i in imgs:
			print i
			webbrowser.open(i, new=0, autoraise=True)
	if bool(args.get('graficar-rtts')):
		graficarInfo(points)
		
def numDisplay(obj, default = "-", suffix = ""):
	if obj is None:
		return default
	return str(round(float(obj), 2)) + " " + suffix
	
def strDisplay(obj, default = "-", suffix = ""):
	if obj is None:
		return default
	return str(obj) + suffix
	
def graficarInfo(points):
	ind = range(len(points))
	fig, ax = plt.subplots()
	ax.bar(ind, [x.RTT() for x in points], 0.75)
	tau = [x.thresholdCrossed() for x in points if x.isOutlier()]
	if len(tau) > 0:
		minTau = min(tau)
		tauLine = plt.axhline(y=tau, label='threshold', color='green', ls='--')
		plt.legend(handles=[tauLine])
	plt.xticks(list(map(lambda x: x-0.4, ind)), [x.IP() for x in points], rotation=45)
	ax.set_title("Saltos vs RTTs")
	ax.set_ylabel('RTT (ms)', color='b')
	
	ax_twinx = ax.twinx()
	ax_twinx.plot(ind, [0 if x.ZRTT() is None else x.ZRTT() for x in points], 'r-', linewidth=3)
	ax_twinx.set_ylabel('ZRTT (ms)', color='r')
	
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
			continue
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
		markers += "&markers=color:"+ ("red" if p.isOutlier() else "blue" )+"|label:" + p.IP() + "|" + str(lt) + "," + str(ln)
		first = False
	return img + paths + markers
	
if __name__ == '__main__':
    main()
