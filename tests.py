from scapy.all import *

packets = rdpcap('eth-1.pcap')

for packet in packets:
    print(packet)
    break