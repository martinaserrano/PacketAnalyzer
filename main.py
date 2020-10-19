#!/usr/bin/env python
import scapy.all as scapy
import argparse
import os
import logging
from scapy.layers import http
formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger('Packets.log')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('Packets.log')
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)

synIpDictionary = {} #a dictionary which records the identified ip
boundary = 5


def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface


def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)


def process_packet(packet):
    ipSource = packet.sprintf('%IP.src%')
    ipDest = packet.sprintf('%IP.dst%')
    packetInfo = ""

    if packet.haslayer(scapy.TCP):
        TCPflags = packet.sprintf('%TCP.flags%')
        packetInfo = "Ip Source:" + ipSource + " Ip Destination: " + ipDest + " Flags: " + TCPflags + " Protocol: TCP"
        checkSynFlood(ipSource, TCPflags)
    if packet.haslayer(scapy.UDP):
        UDPdestport = packet.sprintf('%UDP.dport%')
        UDPsourceport= packet.sprintf('%UDP.sport%')
        packetInfo = "Ip Source: " + ipSource + " UDP Source Port: " + UDPsourceport + " Ip Destination: " + ipDest + " Destination Port: " + UDPdestport +" Protocol: UDP" #print info about UDP
    if packet.haslayer(scapy.ICMP):
        IcmpType = packet.sprintf('%ICMP.type%')
        IcmpCode = packet.sprintf('%ICMP.code%')
        IcmpChecksum = packet.sprintf('%ICMP.chksum%')
        packetInfo = "IP Source: " + ipSource + "IP Destination: " + ipDest+ " Type: " + IcmpType + " Code: " + IcmpCode + " Checksum: " + IcmpChecksum + " Protocol: ICMP"
    if packetInfo != "":
        print(packetInfo)
        logger.info(packetInfo)


def checkSynFlood(ipSource, TCPflags):
    if TCPflags == 'S':
        if ipSource in synIpDictionary:
            synIpDictionary[ipSource] += 1
        else:
            synIpDictionary[ipSource] = 1


    if ipSource in synIpDictionary and TCPflags == 'A':
        synIpDictionary[ipSource] -= 1

    if ipSource in synIpDictionary and synIpDictionary[ipSource] > boundary:
        suspect = "Suspect synflood from IP: " + ipSource
        print(suspect)
        synFloodLog = open('log.txt', 'a')
        synFloodLog.write(suspect)


iface = get_interface()

listInterfaces = os.listdir('/sys/class/net/')
i = 0
print('SELECT:\n')

for iface in listInterfaces:
    print(str(i) + '. interface: ' + iface + '\n')
    i += 1
selection = -1
while len(listInterfaces) <= selection or selection < 0:
    selection = int(input())

ifaceSelected = listInterfaces[selection]

sniff(ifaceSelected)