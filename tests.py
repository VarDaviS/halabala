from scapy.all import *
from binascii import *
import yaml

import main



def repr_str(dumper, data):
    if '\n' in data:
        return dumper.represent_scalar(u'tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_str(data)



def Yaml(packet):

    x = {"Hexamess":packet.hex}
    data = {"Packets" : x}
    file = open("neviiiim.yaml", "w")
    print("h")

    yaml.dump(data, file)




def hexa(data):
    index = 0
    dlzka = len(data)
    hexamess = "|\n"

    while index < dlzka:
        if(not index % 32):
            hexamess = hexamess + "\n" + data[index:index+2].upper()+" "
        else:
            hexamess = hexamess + data[index:index+2].upper()+" "
        index += 2
    print(hexamess)
    return hexamess


"""
    while index < dlzka:
        if (not index % 32):
            # print("Newline and tab + prve bajty")

            print("\n" + str(int(index / 32)) + "\t" + packet_Data[index].upper() + packet_Data[
                index + 1].upper(), end=" ")
        else:
            print(packet_Data[index].upper() + packet_Data[index + 1].upper(), end=" ")

        index += 2"""



packets = rdpcap('eth/eth-1.pcap')
for packet in packets:
    hex = hexlify(raw(packet)).decode()
    packetObj = Packet()
    packetObj.hex = hexa(hex)
    Yaml(packetObj)
    yaml.SafeDumper.org_represent_str = yaml.SafeDumper.represent_str




