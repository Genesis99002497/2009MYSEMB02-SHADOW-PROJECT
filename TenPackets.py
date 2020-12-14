from scapy import *
from scapy.all import *
import string
from test.test_contains import seq
from distutils.command.check import check
from scapy.layers.inet import fragment

  

class PacketFormat:
    def UDPPacketHeader(self, dPort=80, sPort=64, length=8, checkSum=0x00):
        UDPHeader=UDP()
        UDPHeader.sport=sPort
        UDPHeader.dport=dPort
        UDPHeader.len=length
        UDPHeader.chksum=checkSum
        return UDPHeader
    
    def TCPPacketHeader(self, dPort=80, sPort=64, sequenceNumber=1, acknowledgementNumber=1, dataOffset=5, reserved=0, flags='S', window=25, checkSum=20, urgPtr=0):
        TCPHeader=TCP()
        TCPHeader.dport= dPort
        TCPHeader.sport= sPort
        TCPHeader.seq=sequenceNumber
        TCPHeader.ack=acknowledgementNumber
        TCPHeader.dataofs=dataOffset
#         TCPHeader.reserved=reserved
        TCPHeader.flags=flags
        TCPHeader.window=window
        TCPHeader.chksum=checkSum
        TCPHeader.urgptr=urgPtr
        send(TCPHeader)
        return TCPHeader
    
    def IPv6Header(self, dstIP, version=6, trafficClass=0, flowLabel=0, payloadLength=0, nextHeader=0, hoplimit=0, srcIP="192.168.48.187"):
        IPv6Header=IPv6()
        if dstIP!="":
            IPv6Header.dst=dstIP
        IPv6Header.version=version
        IPv6Header.tc=trafficClass
        IPv6Header.fl=flowLabel
        IPv6Header.plen=payloadLength
        IPv6Header.nh=nextHeader
        IPv6Header.hlim=hoplimit
        IPv6Header.src=srcIP
        return IPv6Header
        
    def IPv4Header(self, dstIP, version=4, internetHeaderLength=20, typeOfService=0, length=20, id=0, flags=0, fragment=0, timeToLive=64, protocol=6, checkSum=0, srcIP="192.168.48.187"):
        IPv4Header=IP()
        if dstIP!="":
            IPv4Header.dst=dstIP
        IPv4Header.version=version
        IPv4Header.ihl=internetHeaderLength
        IPv4Header.tos=typeOfService
        IPv4Header.len=length
        IPv4Header.id=id
        IPv4Header.flags=flags
        IPv4Header.frag=fragment
        IPv4Header.ttl=timeToLive
        IPv4Header.proto=protocol
        IPv4Header.chksum=checkSum
        IPv4Header.src=srcIP
        return IPv4Header
    
    
class CustomizePacket:
    def nonCustomizedTCPHeader(self):
        packetObject=PacketFormat()
        tcpHeader=packetObject.TCPPacketHeader()
        return tcpHeader
    
    def nonCustomizedUDPHeader(self):
        packetObject=PacketFormat()
        udpHeader=packetObject.UDPPacketHeader()
        return udpHeader
    
    
    def nonCustomizedIPv4Header(self, destinationIP):
        packetObject=PacketFormat()
        IPv4Header=packetObject.IPv4Header(destinationIP)
        return IPv4Header
    
    def nonCustomizedIPv6Header(self, destinationIP):
        packetObject=PacketFormat()
        IPv6Header=packetObject.IPv6Header(destinationIP)
        return IPv6Header
    
    
    def sendNonCustomizedPacket(self, protocol, version, destinationIP):
        if protocol.lower()=="tcp":
            protocolHeader=self.nonCustomizedTCPHeader()
        else:
            protocolHeader=protocolHeader=self.nonCustomizedTCPHeader()
        if int(version)==4:
            IPHeader=self.nonCustomizedIPv4Header(destinationIP)
        else:
            IPHeader=self.nonCustomizedIPv6Header(destinationIP)
        packet=protocolHeader/IPHeader
        send(packet)
        
    def customizeTCPPacket(self, dport, sport, seq, ack, dataOfs, reserved, flags, window, chkSum, urgPtr):
        packetObject=PacketFormat()
        tcpHeader=packetObject.TCPPacketHeader(dport, sport, seq, ack, dataOfs, reserved, flags, window, chkSum, urgPtr)
        return tcpHeader
        
    def customizeIPv6Packet(self,  dstIP, version=6, trafficClass=0, flowLabel=0, payloadLength=0, nextHeader=0, hoplimit=0, srcIP="192.168.48.187"):
        packetObject=PacketFormat()
        IPv6Header=packetObject.IPv6Header(dstIP, dstIP, version, trafficClass, flowLabel, payloadLength, nextHeader, hoplimit, srcIP)
        return IPv6Header
    
    def customizeIPv4Packet(self, dstIP, version=4, internetHeaderLength=20, typeOfService=0, length=20, identification=0, flags=0, fragment=0, timeToLive=64, protocol=6, checkSum=0, srcIP="192.168.48.187"):
        packetObject=PacketFormat()
        IPv4Header=packetObject.IPv4Header(dstIP, version, internetHeaderLength, typeOfService, length, identification, flags, fragment, timeToLive, protocol, checkSum, srcIP)
        return IPv4Header
    
    
    def modifyTCP(self, tcpAns, dPort=80, sPort=64, sequenceNumber=1, acknowledgementNumber=1, dataOffset=5, reserved=0, flags='S', window=25, checkSum=20, urgPtr=0):
        if tcpAns.lower()=="no":
            tcpHeader=self.nonCustomizedTCPHeader()
        else:
            tcpHeader=self.customizeTCPPacket(dPort, sPort, sequenceNumber, acknowledgementNumber, dataOffset, reserved, flags, window, checkSum, urgPtr)       
        tcpHeader.show()
        return tcpHeader
    
    
    def modifyIP(self, ipAns, dstIP, version=4, internetHeaderLength=20, typeOfService=0, length=20, identification=0, flags=0, fragment=0, timeToLive=64, protocol=6, checkSum=0, srcIP="192.168.48.187"):
        if ipAns.lower()=="no":
            IPHeader=self.nonCustomizedIPv4Header(dstIP)
        else:
            IPHeader=self.customizeIPv4Packet(dstIP, version, internetHeaderLength, typeOfService, length, identification, flags, fragment, timeToLive, protocol, checkSum, srcIP)
        IPHeader.show()
        return IPHeader
    
    def sendCustomizedPacket(self, tcpAns, dPort=80, sPort=64, sequenceNumber=1, acknowledgementNumber=1, dataOffset=5, reserved=0, TCPflags='S', window=25, TCPcheckSum=20, urgPtr=0, ipAns="", dstIP="", version=4, internetHeaderLength=20, typeOfService=0, length=20, identification=0, IPflags=0, fragment=0, timeToLive=64, protocol=6, IPcheckSum=0, srcIP="192.168.48.187"):
        protocolHeader=self.modifyTCP(tcpAns, dPort, sPort, sequenceNumber, acknowledgementNumber, dataOffset, reserved, TCPflags, window, TCPcheckSum, urgPtr)
        ipHeader= self.modifyIP(ipAns, dstIP, version, internetHeaderLength, typeOfService, length, identification, IPflags, fragment, timeToLive, protocol, IPcheckSum, srcIP)
        packet= protocolHeader/ipHeader
        packet.show()
        send(packet)
    
    
        
protocol = input("TCPUDP / UDP ?")
while(1):
    if protocol.lower()=="tcp":
        break
    elif protocol=="udp":
        break
    else:
        protocol=input("Enter the correct value")      
        
        
specifyVersion=input("Do you want to specify the version?(Yes/No)")
if specifyVersion.lower()=="no":
    version=4
else:
    version=input("Which IP version do you want?(4 / 6)")
    while(1):
        if int(version)==4 or int(version)==6:
            break
        else:
            version=input("Enter the valid IP version")

destinationIP=input("Enter the destination IP address")    
specifyCustomize=input("Do you want to customize the packet?(Yes/No)")  
noOfPackets=input("How many packets do you want to send?")


packetObject=CustomizePacket()  


if specifyCustomize.lower()=="no":
    for count in range(int(noOfPackets)):
        packetObject.sendNonCustomizedPacket(protocol, version, destinationIP)
    

if specifyCustomize.lower()=="yes":
    specifyCustomizeTCP=input("Do you want to customize the TCPUDP header?(Yes/No)")
    if specifyCustomizeTCP.lower()=="yes":
        dPort=int(input("Enter the destination port"))
        sPort=int(input("Enter the source port"))
        sequenceNumber=int(input("Enter the sequence number"))
        acknowledgementNumber=int(input("Enter the acknowledgement number"))
        dataOffset=int(input("Enter the dataOffset"))
        reserved=0
        flags=""
        ackFlag=input("Do you want to set Acknowledgement flag?(Yes/No)")
        if ackFlag.lower()=="yes":
            flags=flags+"A"
        synFlag=input("Do you want to set Synchronization flag?(Yes/No)")
        if synFlag.lower()=="yes":
            flags=flags+"S"
        finFlag=input("Do you want to set Finish flag?(Yes/No)")
        if finFlag.lower()=="yes":
            flags=flags+"F"
        pshFlag=input("Do you want to set Push flag?(Yes/No)")
        if pshFlag.lower()=="yes":
            flags=flags+"P"
        rstFlag=input("Do you want to set Reset flag?(Yes/No)")
        if rstFlag.lower()=="yes":
            flags=flags+"R"
        urgFlag=input("Do you want to set Urgent flag?(Yes/No)")
        if urgFlag.lower()=="yes":
            flags=flags+"U"
        TCPflags=flags    
        window=int(input("Enter the window size"))
        TCPcheckSum=input("Enter the chkSum")
        specifyUrgPtr=input("Do you want to set urgent pointer?(yes/no)")
        if specifyUrgPtr.lower()=="yes":
            urgPtr=1
        else:
            urgPtr=0
        
        
    specifyCustomizeIP=input("Do you want to customize the IP header?(yes/no)")
    if specifyCustomizeIP.lower()=="yes" and int(version)==4:
        version=4
        internetHeaderLength=int(input("Enter the InternetHeader Length"))
        typeOfService=int(input("Enter the type of service"))
        length=int(input("Enter the length"))
        id=int(input("Enter the ID"))
        IPflags=0
        fragment=input("Do you want to fragment the data packet?(Yes/No)")
        if fragment.lower()=="yes":
            IPflags=IPflags+1
        
        timeToLive=int(input("Enter the Time to Live"))
        protocol="tcp"
        IPcheckSum=int(input("Enter the check sum"))
        srcIP="192.168.48.187"
        frag=0
    if specifyCustomizeTCP.lower()=="yes" and   specifyCustomizeIP.lower()=="yes":
        packetObject.sendCustomizedPacket(specifyCustomizeTCP, dPort, sPort, sequenceNumber, acknowledgementNumber, dataOffset, reserved,TCPflags, window, TCPcheckSum, urgPtr,specifyCustomizeIP, destinationIP, version, internetHeaderLength, typeOfService, length, id, str(IPflags),frag, timeToLive, protocol, IPcheckSum, srcIP)
        
    
        
        
        
    


        
    