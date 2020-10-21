#!/usr/bin/env python
import scapy.all as scapy
import os
import logging

#the code sets the logger to save messages according to the following formatting: "Date and time", "Type of Log", "message"
formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger('Packets.log')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('Packets.log')
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)

synIpDictionary = {}  # a dictionary which records the identified ip
boundary = 5  # it can be a different number.
icmpDictionary = {}  # a dictiorany which records the ip source of ICMP request


def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)  # sniff function
#  iface: interface
#  store: whether to store sniffed packets or discard them
#  prn: function to apply to each packet. If something is returned, it is displayed; in this case is returned
#  def process_packet (which contains 3 variables: Ip Source, Ip Destination and packetInfo which stores information of sniffed packets).

def process_packet(packet):
    ipSource = packet.sprintf('%IP.src%')
    ipDest = packet.sprintf('%IP.dst%')
    packetInfo = ""  # variable that contains the info about traffic

    # if is a TCP packet, print Ip source, Ip Dest, Flag and proto
    if packet.haslayer(scapy.TCP):
        TCPflags = packet.sprintf('%TCP.flags%')
        packetInfo = "Ip Source:" + ipSource + " Ip Destination: " + ipDest + " Flags: " + TCPflags + " Protocol: TCP"
        checkSynFlood(ipSource, TCPflags)  #
    # if is a UDP packet, print ip source, ip dest, udp source port, udp dest port and proto
    if packet.haslayer(scapy.UDP):
        udpDestport = packet.sprintf('%UDP.dport%')
        udpSourceport= packet.sprintf('%UDP.sport%')
        packetInfo = "Ip Source: " + ipSource + " UDP Source Port: " + udpSourceport + " Ip Destination: " + ipDest + " Destination Port: " + udpDestport +" Protocol: UDP" #print info about UDP
    #if is a ICMP packet, print Ip source, Ip dest, Type, Code and Checksum
    if packet.haslayer(scapy.ICMP):
        icmpType = packet.sprintf('%ICMP.type%')
        icmpCode = packet.sprintf('%ICMP.code%')
        icmpChecksum = packet.sprintf('%ICMP.chksum%')
        packetInfo = "IP Source: " + ipSource + " IP Destination: " + ipDest+ " Type: " + icmpType + " Code: " + icmpCode + " Checksum: " + icmpChecksum + " Protocol: ICMP"
        ICMPfingerprinting(ipSource,icmpType, icmpCode)

    if packetInfo != "":  # if the infopackets are not an empty string
        print(packetInfo)  # print all the content of the variable packetInfo
        logger.info(packetInfo)  # and save the traffic in filelog


def checkSynFlood(ipSource, TCPflags):
    if TCPflags == 'S':
        if ipSource in synIpDictionary:
            synIpDictionary[ipSource] += 1
        else:
            synIpDictionary[ipSource] = 1

    if ipSource in synIpDictionary and TCPflags == 'A':
        synIpDictionary[ipSource] -= 1

    if ipSource in synIpDictionary and synIpDictionary[ipSource] > boundary:
        suspect = "Suspect SYNflood from IP: " + ipSource + " Total Syn: " + str(synIpDictionary[ipSource])
        print(suspect)
        logger.warning(suspect)
#  If the Flags is = S (means syn request), the ip is sored in a dictionary that records the ip source.
#  If the ip is already stored in the dictionary, another one is added.
#  If the flag is A (means Ack), one ip is deleted from the dictioray. Normally, each syn request corresponds to an ack,
#  so if the difference between ack and syn is more than a given boundary, there may be a SUSPECTED Syn flood (which is stored in a fil log)

def ICMPfingerprinting(ipSource, icmpType, icmpCode):
    if icmpType == 8 and icmpCode != 0:
        icmpDictionary[ipSource] = 1

    if ipSource in icmpDictionary:
        if icmpType == 13 or icmpType == 15 or icmpType ==17:
            icmpDictionary[ipSource] += 1
        if icmpDictionary[ipSource] > 3:
            suspect2 = "Suspect ICMP Fingerprinting from IP: " + ipSource
            logger.warning(suspect2)
# Normally, echo request have an ICMPType == 8 and the Code must be 0,
# in other case the code is invalid and we need to check the type of the next packets from the same ip
# So the code does a second check: If at the same ip corrisponds another ICMPtype == 13 or == 15
# or ==17 (which idenfity ICMP get address mask, ICMP get timestamp, ICMP get information)
# means that someone try to do an ICMP fingerprinting. This ip is stored in the file log.


def main():
    listInterfaces = os.listdir('/sys/class/net/') #show list of network interfaces
    i = 0
    print('SELECT YOUR INTERFACE:\n')

    for iface in listInterfaces:
        print(str(i) + '. interface: ' + iface + '\n')
        i += 1
        selection = -1
    while len(listInterfaces) <= selection or selection < 0:
        selection = int(input())
    ifaceSelected = listInterfaces[selection]
    sniff(ifaceSelected)
    # you can get the network interfaces of your computer thanks to the os.listdir function which is set inside
    # a loop that allows you to view a numbered list of interfaces.

main()