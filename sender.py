from scapy.all import *
from sys import argv

if len(argv) == 1:
    print("Usage: python3 sender.py <interface>")
    quit()

conf.iface=argv[1]

dst = "192.168.1."
msg = "team poggers strikes again"

for c in msg:
    send(ARP(pdst=dst+str(ord(c)), psrc='192.168.1.255'))
