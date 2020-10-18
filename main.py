#!/usr/bin/env python
import scapy.all as scapy
import argparse
import os
from scapy.layers import http

synIpDictonary = {}
boundary = 3


def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface


def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)


def process_packet(packet):
    ipSrc = packet.sprintf('%IP.src%')

    if packet.haslayer(scapy.TCP):
        flagsTCP = packet.sprintf('%TCP.flags%')
        checkSynFlood(ipSrc, flagsTCP)


def checkSynFlood(ipSrc, flagsTCP):
    if flagsTCP == 'S':
        if ipSrc in synIpDictonary:
            synIpDictonary[ipSrc] += 1
        else:
            synIpDictonary[ipSrc] = 1
        print('IP source: ' + ipSrc + ' TCP flags:' + flagsTCP)

    if ipSrc in synIpDictonary and flagsTCP == 'A':
        synIpDictonary[ipSrc] -= 1

    if ipSrc in synIpDictonary and synIpDictonary[ipSrc] > boundary:
        # log
        print('sospetto synflood da IP: ' + ipSrc)


iface = get_interface()

listInterface = os.listdir('/sys/class/net/')
i = 0
print('digita:\n')

for iface in listInterface:
    print(str(i) + ' per l interfaccia: ' + iface + '\n')
    i += 1
selection = -1
while len(listInterface) <= selection or selection < 0:
    selection = int(input())

ifaceSelected = listInterface[selection]

sniff(ifaceSelected)