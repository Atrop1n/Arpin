# Arpin
MITM script for Linux

This is a simple Python based Man-In-The-Middle-Attack for Linux. It works by poisoning ARP cache of a selected client and its router's default gateway.
## Warning
This script is intended for educational purposes only. Use with malicious intent is prohibited.   
## Principle 
In a normal newtork, all traffic from clients if forwarded to the internet via a default gateway, also called router.
![image](https://user-images.githubusercontent.com/92330911/175521194-6d5b179c-eef6-459d-8b97-8538153e5cfc.png)
However, it is possible for hackers to pose as the network's router, thus forwarding victim's traffic through themselves. 
![image](https://user-images.githubusercontent.com/92330911/175521258-509c7240-4169-4dfc-8232-66b076ae0f3b.png)
They can then sniff passing packets via Wireshark and monitor victim's network traffic.

## Dependencies
This project relies on a packet forging tool *scapy*. I used Scapy for creation and sending fake ARP packets to the victim and default gateway. 
All prerequisities can be installed by printing
```
pip3 install -r requirements.txt
```
to the console in the folder where script is located. 
## Usage
Go to the folder where arpin.py is located. Then run
```
sudo python3 arpin.py
```
Press '1' to scan the network. Next, select network inteface. At this point, network to which selected interface is connected, should be scanned for clients.
After the network scan is complete, select network's default gateway. Generally, default gateway's IP address is ending with '1', but that is not always the case.
Finally, select a victim.  
Attack is now running. You can sniff victim's packet by running
```
sudo wireshark
```
To stop the attack, press ENTER or ctrl+c.
