from scapy import *
from scapy.all import *
import string
class IPv4PacketFormat:
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
        IPv4Header.src="192.168.48.187"
        IPv4Header.show()
        return IPv4Header


    def ipv4Values(self, dstIP):
        self.dstIP=dstIP
        version=4
        internetHeaderLength=int(input("Enter the InternetHeader Length"))
        typeOfService=int(input("Enter the type of service"))
        length=int(input("Enter the length"))
        identification=int(input("Enter the ID"))
        IPflags=0
        fragment=input("Do you want to fragment the data packet?(Yes/No)")
        if fragment.lower()=="yes":
            IPflags=IPflags+1     
            
        frag=0
        timeToLive=int(input("Enter the Time to Live"))
        protocol="tcp"
        IPcheckSum=int(input("Enter the check sum"))
        srcIP="192.168.48.187"
        

        ipv4Header=self.IPv4Header(dstIP, version, internetHeaderLength, typeOfService, length, identification, IPflags, frag, timeToLive, protocol, IPcheckSum, srcIP)
        return ipv4Header   
            
    def customizeIPv4(self,customize, dstIP):        
        if customize.lower()=="yes":
            ipv4Header=self.ipv4Values(dstIP)
            
        elif customize.lower()=="no":
            ipv4Header=self.IPv4Header(dstIP)
            
        return ipv4Header
    
    
class IPv6PacketFormat:
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
        IPv6Header.src="192.168.48.187"
        return IPv6Header
    
    
    def ipv6Values(self, dstIP):
        self.dstIP=dstIP
        version=6
        trafficClass=int(input("Enter the Traffic Class"))
        flowLabel=int(input("Enter the type of Flow Label"))
        payloadLength=int(input("Enter the pay load length"))
        nextHeader=int(input("Enter the next header"))
        hoplimit=int(input("Enter the Time to hop limit"))
        srcIP="192.168.48.187"
        

        ipv6Header=self.IPv6Header(dstIP, version, trafficClass, flowLabel, payloadLength, nextHeader, hoplimit, srcIP)
        return ipv6Header   
            
    def customizeIPv6(self,customize, dstIP):        
        if customize.lower()=="yes":
            ipv6Header=self.ipv6Values(dstIP)
            
        elif customize.lower()=="no":
            ipv6Header=self.IPv6Header(dstIP)
            
        return ipv6Header
            
    
