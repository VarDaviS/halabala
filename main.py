from scapy.all import *
from binascii import *
import yaml


class Packet:
    frame_number = None
    len_frame_pcap = None
    len_frame_medium = None
    frame_type = None
    src_mac = None
    dst_mac = None
    ether_type = None
    src_ip = None
    dst_ip = None
    protocol = None
    src_port = None
    dst_port = None
    app_protocol = None
    hexa_frame = None
    pid = None
    sap = None

    def __init__(self, frame_number, frame_len_pcap=1, frame_type=None, source_mac=None, dest_mac=None,
                 ether_type=None):
        self.frame_number = frame_number
        self.len_frame_pcap = frame_len_pcap
        self.len_frame_medium = frame_len_pcap + 4
        self.frame_type = frame_type
        self.src_mac = source_mac
        self.dst_mac = dest_mac
        self.ether_type = ether_type


def main():
    Ethertype()



class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)



""" Function which finds frame type, mac addresses, ethertype and ip """


def Ethertype():
    pkts = rdpcap("eth/eth-2.pcap")
    etherTypeDictionary = Load_ethertype_dictionary()
    IPDictionary = Load_ipprotocol_dictionary()
    SnapDictionary = Load_snap_dictionary()
    SapDictionary = Load_sap_dictionary()
    packet_count = 0
    Packets = []
    for packet in pkts:
        hex = hexlify(raw(packet)).decode()
        destination_mac = Maccorection(hex[0:12])
        source_mac = Maccorection(hex[12:24])
        type_lenght = hex[24:28]

        packet_count += 1
        packetObj = Packet(packet_count, len(hex), None, source_mac, destination_mac)

        """finds Frame type and its IP addreses,pid,"""
        if int(type_lenght, 16) > 1500:
            frame_type = "Ethernet II"
            packetObj.frame_type = frame_type
            #print(packet_count)

            if type_lenght in etherTypeDictionary:
                packetObj = IPFinder(hex, etherTypeDictionary, IPDictionary, packetObj)
                Packets.append(packetObj)
            else:
                Packets.append(packetObj)

        else:
            DSAP = int(hex[28:30], 16)
            SSAP = int(hex[30:32], 16)
            if DSAP == 170:
                frame_type = "IEEE 802.3 LLC & SNAP"
                packetObj.frame_type = frame_type
                if hex[40:44] in SnapDictionary:
                    pid = SnapDictionary[hex[40:44]]
                else:
                    pid = SnapDictionary[hex[92:96]]
                packetObj.pid = pid
                print("Pid:" + pid)
            elif DSAP == 255:
                frame_type = "IEEE 802.3 RAW"
                packetObj.frame_type = frame_type
            else:
                frame_type = "IEEE 802.3 LLC"
                packetObj.frame_type = frame_type
                if hex[28:30] in SapDictionary:
                    packetObj.sap = SapDictionary[hex[28:30]]
                    print("SAP:" + packetObj.sap)
            # Packets.append(Packet(packet_count,len(hex),ether,source_mac,destination_mac))
            Packets.append(packetObj)
    Yaml(Packets, hex)


def str_presenter(dumper, data):
    if len(data.splitlines()) > 1 or '\n' in data:
        text_list = [line.rstrip() for line in data.splitlines()]
        fixed_data = "\n".join(text_list)
        return dumper.represent_scalar('tag:yaml.org,2002:str', fixed_data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


"""Serialize data to .yaml formate"""


def Yaml(Packets, hex):
    b = []

    for packet in Packets:
        x = {"frame_number": packet.frame_number,"len_frame_medium": packet.len_frame_medium, "len_frame_pcap": packet.len_frame_pcap,

             "frame_type": packet.frame_type, "src_mac": packet.src_mac, "dst_mac": packet.dst_mac}
        if packet.pid != None:
            x["pid"] = packet.pid
        """elif packet.ether_type != None:
            x["ether_type"] = packet.ether_type
        if packet.src_ip != None:
            x["src_ip"] = packet.src_ip
            x["dst_ip"] = packet.dst_ip
        if packet.protocol != None:
            x["protocol"] = packet.protocol
        if packet.src_port:
            x["src_port"] = packet.src_port
            x["dst_port"] = packet.dst_port
        if packet.protocol == "TCP" and packet.app_protocol != None:
            x["app_protocol"] = packet.app_protocol"""
        if packet.sap != None:
            x["sap"] = packet.sap


        x["hexa_frame"] = hexa(hex)
        b.append(x)
    data = {"name":"PKS2022/23","pcap_name": "all.pcap", "packets": b}
    file_descriptor = open("neviiiim.yaml", "w")
    print("h")

    yaml.add_representer(str, str_presenter)
    yaml.representer.SafeRepresenter.add_representer(str, str_presenter)
    yaml.dump(data, file_descriptor,Dumper=MyDumper, sort_keys=False, indent=2)


"""from hexacode creates standard mac address"""


def Maccorection(mac):
    mac = mac[:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] + ":" + mac[8:10] + ":" + mac[10:12]
    return mac.upper()


"""From hexacode makes standard ip address"""


def IPCorection(hex):
    ip = str(int(hex[:2], 16)) + "." + str(int(hex[2:4], 16)) + "." + str(int(hex[4:6], 16)) + "." + str(
        int(hex[6:8], 16))
    return ip


"""from L3 it gets IP addreses and protocols"""


def IPFinder(hex, etherTypeDictionary, IPDictionary, packetObj):
    app_protocol_dictionary = Load_app_dictionary()
    match etherTypeDictionary[hex[24:28]]:
        case "ARP":
            if int(hex[43:44]) == 2:
                arpopcode = "REPLY"
            else:
                arpopcode = "REQUEST"
            packetObj.src_ip = IPCorection(hex[56:64])
            packetObj.dst_ip = IPCorection(hex[76:84])
            packetObj.arpcode = arpopcode
            packetObj.ether_type = "ARP"
        case "IPv4":
            protocol = IPDictionary[hex[46:48]]
            packetObj.src_ip = IPCorection(hex[52:60])
            packetObj.dst_ip = IPCorection(hex[60:68])
            packetObj.protocol = protocol
            if protocol == ("TCP" or "UDP"):
                hex_src_port = hex[69:72]
                hex_dst_port = hex[73:76]
                packetObj.src_port = int(hex[68:72], 16)
                packetObj.dst_port = int(hex[72:76],16)
                if protocol == "TCP":
                    if  hex_src_port in app_protocol_dictionary:
                        packetObj.app_protocol = app_protocol_dictionary[hex_src_port]
                    elif hex_dst_port in app_protocol_dictionary:
                        packetObj.app_protocol = app_protocol_dictionary[hex_dst_port]

            packetObj.ether_type = "IPv4"
        case "IPv6":
            protocol = IPDictionary[hex[40:42]]
            packetObj.src_ip = hex[44:48] + ":" + hex[48:52] + ":" + hex[52:56] + ":" + hex[60:64] + ":" + hex[64:68] + ":" + hex[68:72]
            packetObj.dst_ip = hex[72:76] + ":" + hex[80:84] + ":" + hex[84:88] + ":" + hex[92:96] + ":" + hex[96:100] + ":" + hex[100:104]
            packetObj.protocol = protocol
            packetObj.ether_type = "IPv6"
        case _:
            print("Helll")
    return packetObj


"""Creates hexaframe with width of 16 Bytes"""


def hexa(data):
    index = 0
    dlzka = len(data)
    hexamess = ''

    while index < dlzka:
        if (not index % 32 and hexamess != ''):
            hexamess = hexamess + '\n' + data[index:index + 2].upper() + ' '
        elif ((not (index + 2) % 32) or ((index + 2) == dlzka)):
            hexamess = hexamess + data[index:index + 2].upper()
        else:
            hexamess = hexamess + data[index:index + 2].upper() + ' '
        index += 2
    hexamess += "\n\n"
    return str(hexamess)


"""Define Ethertypes"""


def Load_ethertype_dictionary():
    filename = "Protocols/fremeType"
    D = {}
    with open(filename) as f:
        for line in f:
            if line[0] == "#":
                line.strip()
            else:
                (key, val) = line.strip().split("-")
                D[key] = val
    return D


def Load_sap_dictionary():
    filename = "Protocols/SAP"
    sap = {}
    with open(filename) as f:
        for line in f:
            if line[0] == "#":
                line.strip()
            else:
                (key, val) = line.strip().split(" ")
                sap[key] = val
    return sap


def Load_ipprotocol_dictionary():
    filename = "Protocols/IPv4protocol"
    IP = {}
    with open(filename) as f:
        for line in f:
            if line[0] == "#":
                line.strip()
            else:
                (key, val) = line.strip().split("=")
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
                (key, val) = line.strip().split(" ")
                Snap[key] = val
    return Snap

def Load_app_dictionary():
    filename = "Protocols/TCP"
    app_protocol = {}
    with open(filename) as f:
        for line in f:
            if line[0] == "#":
                line.strip()
            else:
                (key, val) = line.strip().split(" ")
                app_protocol[key] = val
    return app_protocol

def app_protocol(src_port,dst_port,app_protocol_dictionary):

    if src_port in app_protocol_dictionary:
        app_protocol = app_protocol_dictionary[src_port]
    else:
        app_protocol = app_protocol_dictionary[dst_port]


if __name__ == "__main__":
    main()
