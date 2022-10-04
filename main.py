from scapy.all import *
from binascii import *
import yaml


class Packet:
    frame_number = None
    len_frame_pcap = None
    len_frame_medium = None
    frame_type = None
    src_mac = None
    dst_mac=None
    ether_type=None
    src_ip=None
    dst_ip=None
    protocol=None
    src_port=None
    dst_port=None
    app_protocol=None
    hexa_frame = None
    pid = None


    def __init__(self,frame_number=None ,frame_len_pcap=1 , frame_type=None ,source_mac=None,dest_mac=None,ether_type=None):
        self.frame_number = frame_number
        self.len_frame_pcap = frame_len_pcap
        self.len_frame_medium = frame_len_pcap + 4
        self.frame_type = frame_type
        self.src_mac = source_mac
        self.dst_mac = dest_mac
        self.ether_type = ether_type



def main():
    Ethertype()

def Ethertype():
    pkts = rdpcap("traces/trace-27.pcap")
    frameTypeDictionary = Load_frametype_dictionary()
    IPDictionary = Load_ipprotocol_dictionary()
    SnapDictionary = Load_snap_dictionary()
    packet_count = 0
    Packets = []
    for packet in pkts:

        hex = hexlify(raw(packet)).decode()
        #rawpack = raw(packet)
        #hex = rawpack.hex()
        # print(hex)
        destination_mac = Maccorection(hex[0:12])
        source_mac = Maccorection(hex[13:24])
        type_lenght = hex[24:28]

        packet_count += 1
        packetObj = Packet(packet_count,len(hex),None,source_mac,destination_mac)


        if int(type_lenght, 16) > 1500:
            ether = "Ethernet II"
            packetObj.ether_type = ether
            print(packet_count)
            #print(D[type_lenght])
            # print(source_mac)
            # print(type_lenght)
            #print(packet_count)
            #print()
            if type_lenght in frameTypeDictionary:
                ip = IPFinder(hex,frameTypeDictionary,IPDictionary)
                #print(packet_count)
                Packets.append(Packet(packet_count, len(hex), ether, source_mac, destination_mac, frameTypeDictionary[type_lenght]))
            else:
                #print(packet_count)
                Packets.append(Packet(packet_count, len(hex), ether, source_mac, destination_mac,None))

        else:
            DSAP = int(hex[28:30],16)
            SSAP = int(hex[30:32],16)
            if DSAP == 170:
                ether = "IEEE 802.3 LLC+SNAP"
                packetObj.ether_type = ether
                #print(packet_count)
                pid = SnapDictionary[hex[40:44]]
                packetObj.pid = pid
                print("Pid:" + pid)
            elif DSAP == 255:
                ether = "IEEE 802.3 RAW"
                packetObj.ether_type = ether
            else:
                ether = "IEEE 802.3 LLC"
                packetObj.ether_type = ether
            #Packets.append(Packet(packet_count,len(hex),ether,source_mac,destination_mac))
            Packets.append(packetObj)
    Yaml(Packets , hex)


def Yaml(Packets , hex):


    b = []
    for packet in Packets:
        if packet.pid != None:
            x = {"frame_number": packet.frame_number, "len_frame_pcap": packet.len_frame_pcap,"len_frame_medium":packet.len_frame_medium,"frame type":packet.frame_type,"src_mac":packet.src_mac,"dst_mac":packet.dst_mac,"ether_type":packet.ether_type
                ,"pid":packet.pid,"hexagulas":hexa(hex)}
        else:
            x = {"frame_number": packet.frame_number, "len_frame_pcap": packet.len_frame_pcap,"len_frame_medium":packet.len_frame_medium,"frame type":packet.frame_type,"src_mac":packet.src_mac,"dst_mac":packet.dst_mac,"ether_type":packet.ether_type
                 ,"hexagulas":hexa(hex)}
        b.append(x)
    data = {"Packets" : b}
    file_descriptor = open("neviiiim.yaml", "w")
    print("h")
    yaml.dump(data, file_descriptor)



def Maccorection(mac):
    mac = mac[:2]+":"+mac[2:4]+":"+mac[4:6]+":"+mac[6:8]+":"+mac[8:10]+":"+mac[10:12]
    return mac.upper()


def IPCorection(hex):
    ip = str(int(hex[:2], 16)) + "." + str(int(hex[2:4], 16)) + "." + str(int(hex[4:6], 16)) + "." + str(int(hex[6:8], 16))
    return ip


def IPFinder(hex, frameTypeDictionary,IPDictionary):
    match frameTypeDictionary[hex[24:28]]:
        case "ARP":
            if int(hex[43:44])==2:
                arpopcode = "REPLY"
            else:
                arpopcode = "REQUEST"
            src_ip = IPCorection(hex[56:64])
            dest_ip = IPCorection(hex[76:84])
        case "IPv4":
            protocol = IPDictionary[hex[46:48]]
            #print(protocol)
            src_ip = IPCorection(hex[56:64])
            dest_ip = IPCorection(hex[76:84])

        case "IPv6":
            protocol = IPDictionary[hex[40:42]]
            src_ip = hex[44:48]+":"+hex[48:52]+":"+hex[52:56]+":"+hex[60:64]+":"+hex[64:68]+":"+hex[68:72]
            dest_ip = hex[72:76]+":"+hex[80:84]+":"+hex[84:88]+":"+hex[92:96]+":"+hex[96:100]+":"+hex[100:104]


        case _:
            print("Helll")



def hexa(data):
    index = 0
    dlzka = len(data)
    hexamess = ""

    while index < dlzka:
        if(not index % 32):
            hexamess = hexamess + "\n" + data[index:index+2].upper()+" "
        else:
            hexamess = hexamess + data[index:index+2].upper()+" "
        index += 2
    return hexamess



"""Define Ethertypes"""
def Load_frametype_dictionary():
    filename = "Protocols/fremeType"
    D = {}
    with open(filename) as f:
        for line in f:
            if line[0] == "#":
                line.strip()
            else:
                (key,val) = line.strip().split("-")
                D[key] = val
    return D



def Load_ipprotocol_dictionary():
    filename = "Protocols/IPv4protocol"
    IP = {}
    with open(filename) as f:
        for line in f:
            if line[0] == "#":
                line.strip()
            else:
                (key,val) = line.strip().split("=")
                IP[key] = val
    return IP



def Load_snap_dictionary():
    filename = "Protocols/Snap"
    Snap = {}
    with open(filename) as f:
        for line in f:
            if line[0] == "#":
                line.strip()
            else:
                (key,val) = line.strip().split(" ")
                Snap[key] = val
    return Snap






if __name__ == "__main__":
    main()

