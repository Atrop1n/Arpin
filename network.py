import socket
import fcntl
import struct
import ipaddress

iface = "enp0s3"
subnet_mask = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 35099, struct.pack(b'256s', iface.encode()))[20:24])
my_ip = socket.gethostbyname(socket.gethostname())
network = ipaddress.IPv4Network(my_ip+"/"+subnet_mask, strict=False)
print(network)