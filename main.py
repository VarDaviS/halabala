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
    arp_opcode = None
    hexa_frame = None
    hexcode = None
    pid = None
    sap = None
    flag = None
    icmp_type = None

    def __init__(self, frame_number, frame_len_pcap=1, frame_type=None, source_mac=None, dest_mac=None, ether_type=None):
        self.frame_number = frame_number
        self.len_frame_pcap = int(frame_len_pcap/2)
        self.len_frame_medium = int(frame_len_pcap/2) + 4 if int(frame_len_pcap/2) + 4 >64 else 64
        self.frame_type = frame_type
        self.src_mac = source_mac
        self.dst_mac = dest_mac



def main():
    pcapname = "trace-14.pcap"
    if pcapname[:3] == "eth":
        file_path = "eth/"+pcapname
    elif pcapname[:5] == "trace":
        file_path = "traces/"+pcapname
    else:
        print("Wrong name of pcap")
        return 1
    Ethertype(pcapname,file_path)


class MyDumper(yaml.Dumper):

    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, False)


""" Function which finds frame type, mac addresses, ethertype and ip """


def Ethertype(pcapname, file_path):
    pkts = rdpcap(file_path)
    etherTypeDictionary = Load_ethertype_dictionary()
    IPDictionary = Load_ipprotocol_dictionary()
    SnapDictionary = Load_snap_dictionary()
    SapDictionary = Load_sap_dictionary()
    icmpdict = Load_icmp_dictionary()
    app_protocol_dictionary = Load_app_dictionary()
    packet_count = 0
    Packets = []
    for packet in pkts:
        hex = hexlify(raw(packet)).decode()
        tempHex = hex[:]
        if hex[0:12] == "01000c000000" or hex[0:12] == "03000c000000":
            hex = hex[52:]
        destination_mac = Maccorection(hex[0:12])
        source_mac = Maccorection(hex[12:24])
        type_lenght = hex[24:28]

        packet_count += 1
        packetObj = Packet(packet_count, len(tempHex), None, source_mac, destination_mac)
        packetObj.hexcode = hex[:]
        data = tempHex[:]
        packetObj.hexa_frame = hexa(data)
        """finds Frame type and its IP addreses,pid,"""
        if int(type_lenght, 16) > 1500:
            frame_type = "ETHERNET II"
            packetObj.frame_type = frame_type

            if type_lenght in etherTypeDictionary:
                packetObj = IPFinder(hex, etherTypeDictionary, IPDictionary, packetObj,icmpdict)
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
                    packetObj.pid = pid
            elif DSAP == 255:
                frame_type = "IEEE 802.3 RAW"
                packetObj.frame_type = frame_type
            else:
                frame_type = "IEEE 802.3 LLC"
                packetObj.frame_type = frame_type
                if hex[28:30] in SapDictionary:
                    packetObj.sap = SapDictionary[hex[28:30]]

            # Packets.append(Packet(packet_count,len(hex),ether,source_mac,destination_mac))

            Packets.append(packetObj)

    while (1):
        searching = input("")
        minusp = searching[0:2]
        protocol = searching[3:]
        protocol.removesuffix("\n")
        values = app_protocol_dictionary.values()

        if minusp == "-p":
            if protocol in values:
                tcp_filter(Packets,protocol.upper(),pcapname)
                print("Output finished")
            elif protocol == "ARP":
                arp_filter(Packets,pcapname)
                print("Output finished")
            elif protocol == "ICMP":
                icmp_filter(Packets,pcapname)
                print("Output finished")
            elif protocol == "UDP":
                udp_filter(Packets,pcapname)
                print("Output finished")
            elif protocol == "ALL":
                Yaml(Packets,pcapname)
                print("Output finished")
            elif protocol == "-help":
                print("HTTPS\tHTTP\ttelnet\tftp-datove\tftp\tftp-kontrolne\tSSH\nARP\nICMP\nUDP\nALL\nexit - to end the program")
            else:print("Wrong input")
        elif searching == "exit":
            exit(0)
        else:
            print("wrong input dopici")
            print(minusp)



def str_presenter(dumper, data):
    if len(data.splitlines()) > 1 or '\n' in data:
        text_list = [line.rstrip() for line in data.splitlines()]
        fixed_data = "\n".join(text_list)
        return dumper.represent_scalar('tag:yaml.org,2002:str', fixed_data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


"""Serialize data to .yaml formate"""


def Yaml(Packets, pcapname):
    b = []
    c = []
    d = []
    for packet in Packets:
        x = {"frame_number": packet.frame_number, "len_frame_pcap": packet.len_frame_pcap,"len_frame_medium": packet.len_frame_medium,
             "frame_type": packet.frame_type, "src_mac": packet.src_mac, "dst_mac": packet.dst_mac}
        if packet.pid != None:
            x["pid"] = packet.pid
        elif packet.ether_type != None:
            x["ether_type"] = packet.ether_type
        if packet.arp_opcode != None:
            x["arp_opcode"] = packet.arp_opcode
        if packet.src_ip != None:
            x["src_ip"] = packet.src_ip
            x["dst_ip"] = packet.dst_ip
        if packet.protocol != None:
            x["protocol"] = packet.protocol

        if packet.src_port != None:
            x["src_port"] = packet.src_port
            x["dst_port"] = packet.dst_port
        if packet.protocol == "TCP" and packet.app_protocol != None:
            x["app_protocol"] = packet.app_protocol
        if packet.sap != None:
            x["sap"] = packet.sap
        if packet.icmp_type != None:
            x["icmp_type"] = packet.icmp_type


        x["hexa_frame"] = packet.hexa_frame
        b.append(x)
    ip = ipv4_counter(Packets)
    keys = list(ip.keys())
    for i in keys:
        y = {"node": i, "number_of_sent_packets": ip[i]}
        c.append(y)
    values = list(ip.values())
    for i in range(len(ip)):
        if (values[i] == max(values)):
            d.append(keys[i])
        i += 1
    data = {"name": "PKS2022/23", "pcap_name": pcapname, "packets": b,"ipv4_senders": c, "max_send_packets_by": d}
    file_descriptor = open("ALLoutput.yaml", "w")


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


def IPFinder(hex, etherTypeDictionary, IPDictionary, packetObj,icmpdict):
    app_protocol_dictionary = Load_app_dictionary()
    match etherTypeDictionary[hex[24:28]]:
        case "ARP":
            if int(hex[43:44]) == 2:
                arpopcode = "REPLY"
            else:
                arpopcode = "REQUEST"
            packetObj.src_ip = IPCorection(hex[56:64])
            packetObj.dst_ip = IPCorection(hex[76:84])
            packetObj.arp_opcode = arpopcode
        case "IPv4":
            protocol = IPDictionary[hex[46:48]]
            packetObj.src_ip = IPCorection(hex[52:60])
            packetObj.dst_ip = IPCorection(hex[60:68])
            packetObj.protocol = protocol
            if protocol == "TCP" or protocol == "UDP":
                hex_src_port = hex[69:72]
                hex_dst_port = hex[73:76]
                packetObj.src_port = int(hex[68:72], 16)
                packetObj.dst_port = int(hex[72:76],16)
                if  hex_src_port in app_protocol_dictionary:
                    packetObj.app_protocol = app_protocol_dictionary[hex_src_port].upper()
                elif hex_dst_port in app_protocol_dictionary:
                    packetObj.app_protocol = app_protocol_dictionary[hex_dst_port].upper()

        case "IPv6":
            protocol = IPDictionary[hex[40:42]]
            packetObj.src_ip = hex[44:48] + ":" + hex[48:52] + ":" + hex[52:56] + ":" + hex[60:64] + ":" + hex[64:68] + ":" + hex[68:72]
            packetObj.dst_ip = hex[72:76] + ":" + hex[80:84] + ":" + hex[84:88] + ":" + hex[92:96] + ":" + hex[96:100] + ":" + hex[100:104]
            packetObj.protocol = protocol
    if packetObj.protocol == "ICMP" and packetObj.hexcode[68:70] in icmpdict:
        packetObj.icmp_type = icmpdict[packetObj.hexcode[68:70]]



    packetObj.ether_type = etherTypeDictionary[hex[24:28]]
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


def sameflag_packets(finding,packet):
    if packet.protocol == "TCP" and finding.__contains__(packet.src_ip) and finding.__contains__(packet.dst_ip) and \
            finding.__contains__(packet.src_port) and finding.__contains__(packet.dst_port):
        return True
    else: return False


def tcp_filter(Packets,appprotocol,pcapname):
    finding = None
    flag = {"02": "SYN","18":"ACK", "12": "SYN","19" : "FIN", "10": "ACK", "01": "FIN", "11": "FIN", "04": "RST","14": "RST"}
    pkts = Packets[:]
    tcp = []
    comunications = []
    j = 0
    fullcoms = []
    partcoms = []
    appended = 0
    start = 0
    fincount = 0
    rstcount = 0
    finandack = 0
    tcpcomunication_count = -1
    while j < len(pkts):
        j = 0
        i = 0
        while i < len(pkts):
            if pkts[i].protocol == "TCP" and finding is None:
                finding = (pkts[i].src_ip, pkts[i].dst_ip, pkts[i].dst_port, pkts[i].src_port)
                tcpcomunication_count += 1
            if sameflag_packets(finding, pkts[i])==True:
                if pkts[i].hexcode[94:96] in flag:
                    pkts[i].flag = flag[pkts[i].hexcode[94:96]]
                tcp.append(pkts[i])
                start += 1
                if pkts[i].flag == "FIN":
                    fincount += 1
                if pkts[i].flag == "RST":
                    rstcount += 1
                if pkts[i].flag == "FIN&ACK":
                    finandack += 1
                j -= 1

            if fincount == 2:
                appended = 0
                temp = tcp[len(tcp)-2]
                k = i
                if temp.flag == "FIN":
                    while appended < 2:
                        k += 1
                        if k == len(pkts):
                             break
                        if sameflag_packets(finding, pkts[k])==True:
                            if pkts[k].hexcode[94:96] in flag:
                                pkts[k].flag = flag[pkts[k].hexcode[94:96]]
                            tcp.append(pkts[k])
                            appended += 1

                if temp.flag == "ACK":
                    while appended < 1:
                        k += 1
                        if k == len(pkts):
                            break
                        if sameflag_packets(finding, pkts[k])==True:
                            if pkts[k].hexcode[94:96] in flag:
                                pkts[k].flag = flag[pkts[k].hexcode[94:96]]
                            tcp.append(pkts[k])
                            appended += 1

                for pckt in tcp:

                    pkts.remove(pckt)
                comunications.append(tcp.copy())
                tcp = []
                break

            if rstcount == 1:
                fincount = 0
                j = 0
                for pckt in tcp:
                    pkts.remove(pckt)
                comunications.append(tcp.copy())
                tcp = []
                break

            if pkts[i].protocol != "TCP":
                j += 1
            i += 1

        rstcount = 0
        fincount = 0
        finandack = 0
        finding = None
        for pckt in tcp:
            pkts.remove(pckt)
        if tcp != []:
            comunications.append(tcp.copy())
        tcp = []
    for comunication in comunications:
        if comunication[0].flag =="SYN" and comunication[1].flag == "SYN":
            if ((comunication[len(comunication)-4].flag == "FIN" or comunication[len(comunication)-5].flag == "FIN") and (comunication[len(comunication)-3].flag == "FIN" or comunication[len(comunication)-2].flag == "FIN")) or comunication[len(comunication)-1].flag == "RST"\
                    or (comunication[len(comunication)-3].flag == "FIN" and comunication[len(comunication)-2].flag == "FIN"):
                fullcoms.append(comunication)
            else:
                partcoms.append(comunication)
        else:partcoms.append(comunication)

    tcp_yaml_dump(fullcoms,partcoms,appprotocol,pcapname)


def tcp_yaml_dump(fulcoms,partcoms,appprotocol,pcapname):
    b = []
    d = []
    c = []
    parthouse = []
    fullhouse = []
    m = []
    n = []
    i = 1
    j = 0
    src_ip = []
    dst_ip = []
    for Packets in fulcoms:
        for packet in Packets:
            x = {"frame_number": packet.frame_number, "len_frame_pcap": packet.len_frame_pcap,
                 "len_frame_medium": packet.len_frame_medium,
                 "frame_type": packet.frame_type, "src_mac": packet.src_mac, "dst_mac": packet.dst_mac,
                 "ether_type": packet.ether_type, "src_ip": packet.src_ip, "dst_ip": packet.dst_ip,
                 "protocol": packet.protocol, "app_protocol": packet.app_protocol,
                 "src_port": packet.src_port, "dst_port": packet.dst_port, "hexa_frame": packet.hexa_frame}
            if j <= len(src_ip):
                src_ip.append(packet.src_ip)
                dst_ip.append(packet.dst_ip)
            b.append(x)
        j += 1
        d.append(b)
        b = []

    for a in d:
        packetstay = 0
        for gulas in a:
            if gulas['app_protocol'] == appprotocol:
                packetstay = 1

        if packetstay == 1:
            m.append(a)

    j = 0
    while j < len(m):
        complete = {"number_comm": i, "src_comm": src_ip[j], "dst_comm": dst_ip[j], "packets": m[j]}
        j += 1
        i += 1
        fullhouse.append(complete)

    if partcoms != []:
        for packets in partcoms:
            for packet in packets:
                x = {"frame_number": packet.frame_number, "len_frame_pcap": packet.len_frame_pcap,
                     "len_frame_medium": packet.len_frame_medium,
                     "frame_type": packet.frame_type, "src_mac": packet.src_mac, "dst_mac": packet.dst_mac,
                     "ether_type": packet.ether_type, "src_ip": packet.src_ip, "dst_ip": packet.dst_ip,
                     "protocol": packet.protocol, "app_protocol":packet.app_protocol,
                     "src_port": packet.src_port, "dst_port": packet.dst_port, "hexa_frame": packet.hexa_frame}
                if src_ip is None:
                    src_ip = packet.src_ip
                    dst_ip = packet.dst_ip
                b.append(x)
            c.append(b)
            b = []
        n = []
        for a in c:
            packetstay = 0
            for packet in a:
                if packet["app_protocol"] == appprotocol:
                    packetstay = 1
                    break
            if packetstay == 1:
                n.append(a)
    i = 1
    j = 0
    while j < len(n):
        complete = {"number_comm": i, "packets": n[j]}
        j += 1
        i += 1
        parthouse.append(complete)


    data = {"name": "PKS2022/23", "pcap_name": pcapname}
    if fullhouse != []:
        data["complete_comms"] = fullhouse
    if parthouse != []:
        data["partial_comms"] = parthouse

    file_descriptor = open("TCPoutput.yaml", "w")


    yaml.add_representer(str, str_presenter)
    yaml.representer.SafeRepresenter.add_representer(str, str_presenter)
    yaml.dump(data, file_descriptor, Dumper=MyDumper, sort_keys=False, indent=2)


def udp_filter(Packets,pcapname):
    pkts = Packets.copy()
    i = 0
    dst_port = None
    comunications  = []
    comunication = []
    while len(pkts) > i:
        if pkts[i].dst_port == 69 and pkts[i].protocol == "UDP":
            src_port = pkts[i].src_port
            j = i
            comunication.append(pkts[i])
            pkts.remove(pkts[i])
            while len(pkts) > j:
                if pkts[j].dst_port == src_port:
                    dst_port = pkts[j].src_port
                    comunication.append(pkts[j])
                    pkts.remove(pkts[j])
                    break
                j += 1

            if dst_port != None:
                k = i
                comports =[dst_port,src_port]
                while len(pkts) > k:
                    if comports.__contains__(pkts[k].src_port) and comports.__contains__(pkts[k].dst_port):
                        comunication.append(pkts[k])
                        pkts.remove(pkts[k])
                        i = -1
                    else: k += 1


                comunications.append(comunication)
                comunication = []
        i += 1

    udpYamlDump(comunications,pcapname)


def udpYamlDump(comunications,pcapname):
    b = []
    d = []
    fullhouse = []
    coms = {}
    i = 1
    j = 0
    src_ip = []
    dst_ip = []
    for Packets in comunications:
        for packet in Packets:
            x = {"frame_number": packet.frame_number, "len_frame_pcap": packet.len_frame_pcap,
                 "len_frame_medium": packet.len_frame_medium,
                 "frame_type": packet.frame_type, "src_mac": packet.src_mac, "dst_mac": packet.dst_mac,
                 "ether_type": packet.ether_type,"src_ip":packet.src_ip,"dst_ip":packet.dst_ip,"protocol":packet.protocol,
                 "src_port": packet.src_port,"dst_port":packet.dst_port,"hexa_frame":packet.hexa_frame}
            if j <= len(src_ip):
                src_ip.append(packet.src_ip)
                dst_ip.append(packet.dst_ip)
            b.append(x)
        j += 1
        d.append(b)
        b = []
    j = 0
    while j < len(d):
        complete = {"number_comm": i, "src_comm": d[j][0]["src_ip"], "dst_comm":d[j][0]["dst_ip"], "packets": d[j]}
        j += 1
        i += 1
        fullhouse.append(complete)


    data = {"name": "PKS2022/23", "pcap_name":pcapname}
    if fullhouse!= []:
        data["complete_comms"]=fullhouse
    file_descriptor = open("UDPoutput.yaml", "w")


    yaml.add_representer(str, str_presenter)
    yaml.representer.SafeRepresenter.add_representer(str, str_presenter)
    yaml.dump(data, file_descriptor, Dumper=MyDumper, sort_keys=False, indent=2)


def icmp_filter(Packets,pcapname):
    pkts = Packets.copy()
    i = 0
    pair = []
    pairs = []
    singles = []
    while i < len(pkts):
        if pkts[i].icmp_type == "REQUEST":
            src_add = pkts[i].src_ip
            dst_add = pkts[i].dst_ip
            k = i+1
            while k < len(pkts):
                if src_add == pkts[k].dst_ip and dst_add == pkts[k].src_ip and pkts[k].icmp_type == "REPLY":
                    pair.append(pkts[i])
                    pair.append(pkts[k])
                    pkts.remove(pkts[k])
                    pkts.remove(pkts[i])
                    i -= 1

                if pair != []:
                    pairs.append(pair)
                    pair = []
                    break
                k += 1
        i += 1

    for packet in pkts:
        if packet.protocol == "ICMP":
            singles.append(packet)
            pkts.remove(packet)
    pairs.append(singles)
    icmpYamlDump(pairs,pcapname)


def icmpYamlDump(comunications,pcapname):
    b = []
    d = []
    fullhouse = []
    listes = []
    k = 0
    i = 1
    j = 0
    src_ip = []
    dst_ip = []
    partialcomms = []
    for Packets in comunications:
        for packet in Packets:
            x = {"frame_number": packet.frame_number, "len_frame_pcap": packet.len_frame_pcap,
                 "len_frame_medium": packet.len_frame_medium,
                 "frame_type": packet.frame_type, "src_mac": packet.src_mac, "dst_mac": packet.dst_mac,
                 "ether_type": packet.ether_type, "src_ip": packet.src_ip, "dst_ip": packet.dst_ip,
                 "protocol": packet.protocol, "icmp_type": packet.icmp_type, "hexa_frame": packet.hexa_frame}
            if j <= len(src_ip):
                src_ip.append(packet.src_ip)
                dst_ip.append(packet.dst_ip)
            b.append(x)
        j += 1
        d.append(b)
        b = []
    j = 0
    while j < len(d)-1:
        complete = {"number_comm": i, "src_comm": d[j][0]["src_ip"], "dst_comm": d[j][0]["dst_ip"], "packets": d[j]}
        j += 1
        i += 1
        fullhouse.append(complete)

    while k < len(d[j]):
        listes = [d[j][k]]
        incomplete = {"number_comm": k+1, "packets":listes}
        partialcomms.append(incomplete)
        k += 1

    data = {"name": "PKS2022/23", "pcap_name": pcapname}

    if fullhouse != []:
        data["complete_comms"] = fullhouse
    if partialcomms != [] :
        data["partial_comms"] = partialcomms

    file_descriptor = open("ICMPoutput.yaml", "w")


    yaml.add_representer(str, str_presenter)
    yaml.representer.SafeRepresenter.add_representer(str, str_presenter)
    yaml.dump(data, file_descriptor, Dumper=MyDumper, sort_keys=False, indent=2)


def arp_filter(Pakcets,pcapname):
    pkts = Pakcets[:]
    i = 0
    requesty = []
    dvojice = []
    alone = []
    while i < len(pkts):
        if pkts[i].arp_opcode == "REPLY":
            macaddress = pkts[i].dst_mac

            for k in range(i).__reversed__():
                if pkts[k].src_mac == macaddress and pkts[k].arp_opcode == "REQUEST":
                    requesty.append(pkts[k])
                    requesty.append(pkts[i])
                    pkts.remove(pkts[i])
                    pkts.remove(pkts[k])
                    i -= 1
                    dvojice.append(requesty)
                    requesty = []
                    break
        i += 1
    i = 0
    while i < len(pkts):
        if pkts[i].ether_type == "ARP":
            alone.append(pkts[i])
        i += 1
    dvojice.append(alone)
    arpYamlDump(dvojice,pcapname)



def arpYamlDump(comunications,pcapname):
    b = []
    d = []
    fullhouse = []
    k = 0
    i = 1
    j = 0
    src_ip = None
    dst_ip = None
    partialcomms = []
    for Packets in comunications:

        for packet in Packets:
            x = {"frame_number": packet.frame_number, "len_frame_pcap": packet.len_frame_pcap,
                 "len_frame_medium": packet.len_frame_medium,
                 "frame_type": packet.frame_type, "src_mac": packet.src_mac, "dst_mac": packet.dst_mac,
                 "ether_type": packet.ether_type, "arp_opcode": packet.arp_opcode,"src_ip": packet.src_ip, "dst_ip": packet.dst_ip,
                  "hexa_frame": packet.hexa_frame}
            if src_ip is None:
                src_ip = packet.src_ip
                dst_ip = packet.dst_ip
            b.append(x)
        d.append(b)
        b = []
    while j < len(d)-1:
        complete = {"number_comm": i, "src_comm": src_ip, "dst_comm": dst_ip, "packets": d[j]}
        j += 1
        i += 1
        fullhouse.append(complete)
    while k < len(d[j]):
        complete = {"number_comm": k+1, "src_comm": src_ip, "dst_comm": dst_ip, "packets": d[j][k]}
        partialcomms.append(complete)
        k += 1

    data = {"name": "PKS2022/23", "pcap_name": pcapname}
    if fullhouse != []:
        data["complete_comms"] = fullhouse
    if partialcomms != []:
        data["partial_comms"] = partialcomms
    file_descriptor = open("ARPoutput.yaml", "w")

    yaml.add_representer(str, str_presenter)
    yaml.representer.SafeRepresenter.add_representer(str, str_presenter)
    yaml.dump(data, file_descriptor, Dumper=MyDumper, sort_keys=False, indent=2)


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


def Load_icmp_dictionary():
    filename = "Protocols/ICMP"
    icmp = {}
    with open(filename) as f:
        for line in f:
            if line[0] == "#":
                line.strip()
            else:
                (key, val) = line.strip().split("=")
                icmp[key] = val
    return icmp


def ipv4_counter(packets):
    ipCount = {}
    i = 0
    count_of_packets_sent =0
    for packet in packets:
        if packet.ether_type == "IPv4":
                if packet.src_ip in ipCount:
                    ipCount[packet.src_ip] = ipCount[packet.src_ip]+1
                else:ipCount[packet.src_ip] = 1

                if ipCount[packet.src_ip] > count_of_packets_sent:
                    count_of_packets_sent = ipCount[packet.src_ip]

    return ipCount


if __name__ == "__main__":
    main()
