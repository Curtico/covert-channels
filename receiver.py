from scapy.all import *
from sys import argv

if len(argv) == 1:
    print("Usage: python3 receiver.py <interface>")
    quit()

message = 'Message: '

def pkt_callback(pkt):
    if pkt[ARP].psrc == '192.168.1.255':
        ip = pkt[ARP].pdst
        global message
        message += chr(int(ip.split('.')[3]))
        print(message)

print("[+] Started Listener")

sniff(iface=argv[1],prn=pkt_callback,filter='arp',store=0)
