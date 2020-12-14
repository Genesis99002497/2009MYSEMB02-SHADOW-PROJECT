from scapy import *
from scapy.all import *
import string

class TCPPacketFormat:
    def TCPPacketHeader(self, dPort=80, sPort=64, sequenceNumber=1, acknowledgementNumber=1, dataOffset=5, flags='S', window=25, checkSum=20, urgPtr=0):
        TCPHeader=TCP()
        TCPHeader.dport= dPort
        TCPHeader.sport= sPort
        TCPHeader.seq=sequenceNumber
        TCPHeader.ack=acknowledgementNumber
        TCPHeader.dataofs=dataOffset
        #TCPHeader.reserved=reserved
        TCPHeader.flags=flags
        TCPHeader.window=121   #window
        TCPHeader.chksum=checkSum
        TCPHeader.urgptr=urgPtr
        TCPHeader.show()
        return TCPHeader
    
    
        
    def tcpValues(self):    
        dPort=int(input("Enter the destination port"))
        sPort=int(input("Enter the source port"))
        sequenceNumber=int(input("Enter the sequence number"))
        acknowledgementNumber=int(input("Enter the acknowledgement number"))
        dataOffset=int(input("Enter the dataOffset"))
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
        TCPcheckSum=int(input("Enter the chkSum"))
        specifyUrgPtr=input("Do you want to set urgent pointer?(yes/no)")
        if specifyUrgPtr.lower()=="yes":
            urgPtr=1
        else:
            urgPtr=0
            
        tcpHeader=self.TCPPacketHeader(dPort, sPort, sequenceNumber, acknowledgementNumber, dataOffset, TCPflags, window, TCPcheckSum, urgPtr)
        return tcpHeader
        
        
    def customizeTCP(self,customize):        
        if customize.lower()=="yes":
            tcpHeader=self.tcpValues()
            
        elif customize.lower()=="no":
            tcpHeader=self.TCPPacketHeader()
            
        return tcpHeader
    
class UDPPacketFormat:
    def UDPPacketHeader(self, dPort=80, sPort=64, length=8, checkSum=0x00):
        UDPHeader=UDP()
        UDPHeader.sport=sPort
        UDPHeader.dport=dPort
        UDPHeader.len=length
        UDPHeader.chksum=checkSum
        UDPHeader.show()
        return UDPHeader
    
    def udpValues(self):    
        dPort=int(input("Enter the destination port"))
        sPort=int(input("Enter the source port"))
        length=int(input("Enter the length"))
        checkSum=int(input("Enter the chkSum"))
            
        udpHeader=self.UDPPacketHeader(dPort, sPort, length, checkSum)
        return udpHeader
        
        
    def customizeUDP(self, customize):        
        if customize.lower()=="yes":
            udpHeader=self.udpValues()
            
        elif customize.lower()=="no":
            udpHeader=self.UDPPacketHeader()
            
        return udpHeader
            
    
