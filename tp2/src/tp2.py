import logging
import argparse
import os
import numpy as np
import bisect
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *

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
	
def toString(pkt):
	return pkt.summary()
			
def main(): 
	global args
	parser = argparse.ArgumentParser(description='tdc tp2 parte 1')
	parser.add_argument('--dest', default='mit.edu', help = 'destino')
	parser.add_argument('--timeout', default=1.0, help = 'timeout')
	parser.add_argument('--maxhops', default=31, help = 'maximo numero de saltos')
	args = vars(parser.parse_args())
    
	ttl = 1
	pid =  100+ttl
	hops = int(args.get('maxhops'))
	replay = False
	saltos = [[],[]] # [Ips],[Promedio RTT de la rafaga]
	esta = [] # si la ip iesima esta considerada en el calculo de los delta. SI lo esta
	#contiene al indice del arreglo rttsDelta. Si no, -1.
	rttsZ = []
	rttsDelta = [] # (Delta RTT, indice en saltos[IP])
	outliers_list = []
	

	while hops > 0:
		#print "TTL=", "%3d" % ttl,
		#sys.stdout.flush()

		respuestas=[[],[]] #[ips del ttl], [[rtts de esa ip]]]
		

		for x in range(0,30):
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
						replay = True
						break # llegamos

		if not respuestas[IPS]: #Si nadie me respondio, no se cual es el hop.
			#print "hi"
			respuestas[IPS].append(-1)
			respuestas[RTTS].append([0])

		#calculo datos del de mayor aparicion.

		max_indice = respuestas[RTTS].index(max(respuestas[RTTS]))
		#print max_indice
		#saco promedio.
		media = np.mean(respuestas[RTTS][max_indice])

		saltos[IPS].append(respuestas[IPS][max_indice])
		saltos[RTTS].append(media)

		#else:
		#	for res in respuestas[IPS][INFO]: 
		#		print "->", "\t", toString(res), "\n"

		#	print "RTT Promedio: ",str(np.mean(respuestas[RTTS]))		


		#sys.stdout.flush()
		if replay:
			break

		ttl = ttl + 1
		hops = hops - 1

	####### Calculo diferencia entre saltos #####

	max_rtts_Delta = next(x for x in saltos[RTTS] if x > 0)
	indice_max_rtts_Delta = saltos[RTTS].index(max_rtts_Delta)
	rttsDelta.append((max_rtts_Delta, indice_max_rtts_Delta))

	for i in range(indice_max_rtts_Delta+1,len(saltos[RTTS])):

		if saltos[IPS][i] == -1:	#no contestaron.
			esta.append(-1)
			continue
		dif = saltos[RTTS][i]-saltos[RTTS][i-1] #calculo dif entre saltos
		if dif >= 0: #agrego solo si da mayor o igual.
			rttsDelta.append((dif,i))
			esta.append(len(rttsDelta)-1)	#appendeo el indice donde esta la iesima ip en rttsDelta
			max_rtts_Delta = dif


	rttDeltaPromedio = np.mean(rttsDelta)  #promedio y desvio de los saltos.
	rttDeltaDesvio = np.std(rttsDelta)	

	## Zrtt

	for i in range(0,len(rttsDelta)):
		#if esta[i]:
		rttsZ.append(abs(rttsDelta[i][DELTA]-rttDeltaPromedio)/rttDeltaDesvio)



	#calculo  de outliers
	hay_outlier = True
	rttsDelta_outlier = rttsDelta #para iterar en el otulier


	#lista dado indice devuelva si es outlier
	for x in range(0,len(saltos[IPS])):
		outliers_list.append(0)

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
			outliers_list[desv_abs_mas_grande[INDICE_IP]]=1

			#Lo borro de la lista de desvios absolutos
			#rttsDelta_outlier = [(x for x in saltos[RTTS] if x[INDICE_IP] == desv_abs[-1][IND
			rttsDelta_outlier = [(x for x in rttsDelta_outlier[RTTS] if x[INDICE_IP] != desv_abs_mas_grande[INDICE_IP])]

			#Recalculo promedo y desvio y vuelvo a empezar
			temp = [y[Delta] for y in rttsDelta_outlier]
			promedio_outlier = np.mean(temp)
			desvio_outlier = np.std(temp)

		else: 
			hay_outlier = False

	#imprimo resultados.		
		
	col_width_ips_avg = max(len(str(word)) for word in saltos[IPS]) + 2
	col_width_rtts_acum = max(len(str(word)) for word in saltos[RTTS]) + 2
	col_width_rtt_delta = max(len(str(word)) for word in rttsDelta) + 2
	col_width_rtt_z = max(len(str(word)) for word in rttsZ) + 2

	print "ttl=   ", \
	"IP".ljust(col_width_ips_avg), \
	"RTT".ljust(col_width_rtts_acum), \
	"dRTT=".ljust(col_width_rtt_delta), \
	"zdRTT=".ljust(col_width_rtt_z), \
	"OUTLIER? "


	imprimio = False
	for i in range(len(saltos[IPS])):
		imprimio = True
		responde = esta[i] #Si responde y si lo hace, devuelve indice de esa ip en la lista de deltas.
		if responde != -1: #responde
			if outliers_list[i]:
				print "%i:" % (i), \
				str(saltos[IPS][i]).ljust(col_width_ips_avg), \
				str(saltos[RTTS][i]).ljust(col_width_rtts_acum), \
				str(rttsDelta[DELTA][responde]).ljust(col_width_rtt_delta), \
				str(rttsZ[responde]).ljust(col_width_rtt_z), \
				"OUTLIER!"
			else:
				if i != indice_max_rtts_Delta:
					print "%i:" % (i), \
					str(saltos[IPS][i]).ljust(col_width_ips_avg), \
					str(saltos[RTTS][i]).ljust(col_width_rtts_acum), \
					str(rttsDelta[DELTA][responde]).ljust(col_width_rtt_delta), \
					str(rttsZ[responde]).ljust(col_width_rtt_z)
				else:
					str(saltos[IPS][i]).ljust(col_width_ips_avg), \
					str(saltos[RTTS][i]).ljust(col_width_rtts_acum), \
					str(-1).ljust(col_width_rtt_delta), \
					str(-1).ljust(col_width_rtt_z)
		else: #No responde
			print "ttl=%i:" % (i), \
			str(saltos[IPS][i]).ljust(col_width_ips_avg), \
			str(-1).ljust(col_width_rtts_acum), \
			str(-1).ljust(col_width_rtt_delta), \
			str(-1).ljust(col_width_rtt_z)


if __name__ == '__main__':
    main()
