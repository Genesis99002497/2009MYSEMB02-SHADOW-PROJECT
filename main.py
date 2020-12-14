from scapy import *
from scapy.all import *
from TCPUDP import TCPPacketFormat, UDPPacketFormat
from IPv4IPv6 import IPv4PacketFormat, IPv6PacketFormat
from Capture import AnalysingPacket
from asyncio.tasks import sleep
from Check import readinput


inp=readinput()
#destinationIP=input("Enter the destination IP address")   
destinationIP=inp[0]
# protocol = input("TCP / UDP ?")
protocol=inp[1]
while(1):
    if protocol.lower()=="tcp":
        break
    elif protocol=="udp":
        break
    else:
        protocol=input("Enter the correct value")      
        
        
#specifyVersion=input("Do you want to specify the version?(Yes/No)")
specifyVersion=inp[2]
if specifyVersion.lower()=="no":
    version=4
else:
    #version=input("Which IP version do you want?(4 / 6)")
    version=inp[3]
    while(1):
        if int(version)==4 or int(version)==6:
            break
        else:
            version=input("Enter the valid IP version")
            
#noOfPackets=input("How many packets do you want to send?") 
noOfPackets=inp[4]
if protocol.lower()=="tcp":
    #specifyCustomizeTCP=input("Do you want to customize the TCP header?(Yes/No)")
    specifyCustomizeTCP=inp[5]
    tcp=TCPPacketFormat()
    protocolHeader=tcp.customizeTCP(specifyCustomizeTCP)
    
elif protocol.lower()=="udp":
    specifyCustomizeUDP=input("Do you want to customize the UDP header?(Yes/No)")
    udp=UDPPacketFormat()
    protocolHeader=udp.customizeUDP(specifyCustomizeUDP)
    
if int(version)==4:
    #specifyCustomizeIP=input("Do you want to customize the IPv4 header?(yes/no)")
    specifyCustomizeIP=inp[6]
    ipv4=IPv4PacketFormat()
    ipHeader=ipv4.customizeIPv4(specifyCustomizeIP, destinationIP)
    
elif int(version)==6:
    specifyCustomizeIP=input("Do you want to customize the IPv6 header?(yes/no)")
    ipv6=IPv6PacketFormat()
    ipHeader=ipv6.customizeIPv6(specifyCustomizeIP, destinationIP)
    
    
packet=ipHeader/protocolHeader

for i in range(int(noOfPackets)):
    send(packet)
    
    
    
packetCapture = AnalysingPacket()
packetCapture.generatePcapFile(protocol)
packetCapture.analysePcapFile(destinationIP, version)
    


