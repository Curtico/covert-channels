from scapy.all import *
from sys import argv

if len(argv) < 3:
    print("Usage: python3 sender.py <interface> <message>")
    quit()

conf.iface=argv[1]

dst = "192.168.1."
msg = argv[2]

for c in msg:
    send(ARP(pdst=dst+str(ord(c)), psrc='192.168.1.255'))
