from scapy.all import sniff
from scapy.all import wrpcap
from scapy.all import rdpcap


class AnalysingPacket:
    def generatePcapFile(self, protocol):
        pkts = sniff(timeout=20, filter=protocol)
        print(pkts)
        wrpcap('scapy.pcap', pkts)
    
    def analysePcapFile(self, destinationIP, version):    
        pkts_list = rdpcap('scapy.pcap')
        noOfPackets=len(pkts_list)
        count=0
        for i in range(noOfPackets):
            if pkts_list[i]['IP'].src=="192.168.48.187" and pkts_list[i]['IP'].version==int(version) and pkts_list[i]['TCP'].window==121:
                pkts_list[i].show()
                count=count+1
        print(count)
