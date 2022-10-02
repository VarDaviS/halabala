from scapy.all import *
from binascii import *
import yaml



def main():
    pkts = rdpcap("eth-1.pcap")
    for packet in pkts:
        hex = hexlify(raw(packet)).decode()
        print(hex)
        destination_mac = hex[0:12]
        source_mac = hex[13:24]
        type = hex[24:28]
        if type 
        print(destination_mac)
        print(source_mac)
        print(type)


if __name__ == "__main__":
    main()

