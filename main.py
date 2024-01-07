from binascii import hexlify
from scapy.utils import *
from bitstring import BitArray
import ruamel.yaml.scalarstring

staty = []
stats = {}
max_senders = []
#funkcia na spracovanie tftp komunikacie
def save_tftp_comm(src_ip, dest_ip, source_port, dest_port, packet_id):
    tftp = {
    }
    #prechadzam tftp komunikaciu ak je IP IP rovnaka a dest port je none viem ze ide o odpoved a teda ulozim si port a zanpisem si index packetu
    for comm in tftp_comms:
        if (src_ip == comm["src_ip"] and dest_ip == comm["dst_ip"]) or (src_ip == comm["dst_ip"] and dest_ip == comm["src_ip"]):
            if comm["dest_port"] is None: # tu sme na odpovedi, cize source bude dest
                comm["dest_port"] = source_port
                tftp_ports.append(source_port)
                comm["packet_idx"].append(packet_id)
                return
            #ak sa rovnaju porty viem ze je to komunikacia len si zapisem index packetu
            if (dest_port == comm["dest_port"] and source_port == comm["src_port"]) or (dest_port == comm["src_port"] and source_port == comm["dest_port"]):
                comm["packet_idx"].append(packet_id)
                return
    #ak sme dosli sem na koniec viem ze ide o prvy zaznam v TFTP a teda ulozim si potrebne veci a dest port necham ako none
    tftp["src_ip"] = src_ip
    tftp["dst_ip"] = dest_ip
    tftp["dest_port"] = None
    tftp["src_port"] = source_port
    tftp_ports.append(source_port)
    tftp["packet_idx"] = [packet_id]
    tftp_comms.append(tftp)




#vypise o aky protokol ide nad tcp alebo udp
def analyze_4layer(packet, head_len, ip_prot, ip_src, ip_dest, counter):
    tcp_dictionary = {}
    tcp_file = open("protocols/tcpheader.txt")
    udp_dictionary = {}
    udp_file = open("protocols/udpheader.txt")
    #rozdelim si hodnoty v subore na kluc + value a potom len vypisem value ak sa najde zhoda
    for line in tcp_file:
        key, value = line.split()
        tcp_dictionary[key] = value
    for line in udp_file:
        key, value = line.split()
        udp_dictionary[key] = value

    source_port = int(convert_bytes(packet, 14 + head_len, 16 + head_len), 16)
    dest_port = int(convert_bytes(packet, 16 + head_len, 18 + head_len), 16)
    packet_dict["src_port"] = source_port
    packet_dict["dst_port"] = dest_port
    #vypis protokolu
    if ip_prot == 6:
        for key in tcp_dictionary.keys():
            if source_port == int(key):
                tcp = tcp_dictionary[key]
                packet_dict["app_protocol"] = tcp
                break
            elif dest_port == int(key):
                tcp = tcp_dictionary[key]
                packet_dict["app_protocol"] = tcp
                break
     # vypis protokolu
    elif ip_prot == 17:
        for key in udp_dictionary.keys():
            if source_port == int(key):
                udp = udp_dictionary[key]
                packet_dict["app_protocol"] = udp
                break
            elif dest_port == int(key):
                udp = udp_dictionary[key]
                packet_dict["app_protocol"] = udp
                break
    #ak je to zaciatok komunikacie alebo uz je to v zozname portov ktore komunikovali idem analyzovat ci ide o komunikaciu
    if dest_port == 69 or (dest_port in tftp_ports or source_port in tftp_ports):
        save_tftp_comm(ip_src, ip_dest, source_port, dest_port, counter-1)




#vypis protokolu nad e2
def ether_type(protocol):
    e2_file = open("protocols/ethernet_prot.txt", "r")
    for row in e2_file:
        file_protc = row[0:5]
        file_protc = int(file_protc, 16)
        if protocol == file_protc:
            value_to_print = row[5:-1]
            packet_dict["ether_type"] = value_to_print

#analyza ipv4
def ipv4(packet, counter):
    ip_dict = {}
    ip_file = open("protocols/IPheader.txt")
    icmp_file = open("protocols/imcp.txt")

    for line in ip_file:
        key, value = line.split()
        ip_dict[key] = value
    #aby som vedel urcit velkost hlavicky musim tento bajt rozdelit a vytiahnut iba druhe cislo ktore hovori o velkosti
    len = hex(packet.__bytes__()[14])
    len = BitArray(hex=len)
    ip_len = len.bin[4:]
    ip_len = int(ip_len, 2) * 4
    ip_protc = packet.__bytes__()[23]
    ip_src = convert_bytes(packet, 26, 30)
    ip_dest = convert_bytes(packet, 30, 34)
    ip_src = convert_ip(ip_src)
    ip_dest = convert_ip(ip_dest)
    packet_dict["src_ip"] = ip_src
    packet_dict["dst_ip"] = ip_dest
    # statistika odosielatelov (ak nie je v zozname len ho prida ak je pripocita jednotku)
    if ip_src not in stats:
        stats[ip_src] = 1
    else:
        stats[ip_src] += 1

    for key in ip_dict.keys():
        if ip_protc == int(key):
            packet_dict["protocol"] = ip_dict[key]

    analyze_4layer(packet, ip_len, ip_protc, ip_src, ip_dest, counter)
    #vypis message pri ICMP
    if ip_protc == 1:
        icmp_type = convert_bytes(packet, 14 + ip_len, 15 + ip_len)
        icmp_type = int(icmp_type, 16)
        print(icmp_type)
        for row in icmp_file:
            icmp_prot = row[0:3]
            icmp_prot = int(icmp_prot, 16)
            if icmp_type == icmp_prot:
                value_to_print = str(row[3:-1])
                packet_dict["icmp_type"] = value_to_print



def print_mac(packet):
    packet_dict["src_mac"] = form_mac(packet, 6, 12)
    packet_dict["dst_mac"] = form_mac(packet, 0, 6)
#funkcia pre vyformatovanie mac adresy
def form_mac(packet, begin, end):
    bts = packet.__bytes__()[begin:end]
    #odstrani b''
    str_data = str(hexlify(bts))[2:-1]
    out = ""
    i = 0
    for c in str_data:
        out += c
        i += 1
        #pridanie : do mac adresy
        if i % 2 == 0:
            out += ":"
    if i % 2 == 0:
        out = out[:-1]
    return out.upper()

#formatovanie vypisu packetu
def form_hexdump(packet):
    bts = packet.__bytes__()[0:]
    str_data = str(hexlify(bts))[2:-1]
    out = ""
    i = 0
    for c in str_data:
        out += c
        i += 1
        if i % 2 == 0 and i % 32 != 0 and i != len(str_data):
            out += " "
        if i % 32 == 0:
            out += "\n"
        elif i == len(str_data):
            out += "\n"

    return out.upper()
#formatovanie vypisu pre IP
def convert_ip(source):
    bites = ""
    source_a = ""
    counter = 1
    for c in source:
        bites += c
        if counter % 2 == 0:
            bites = int(bites,16)
            source_a += str(bites)
            bites = ""
            if counter < 8:
                source_a += "."
        counter += 1
    return source_a

#vytiahne bajty z pola a vrati ich ako string
def convert_bytes(packet, begin, end):
    bts = packet.__bytes__()[begin:end]
    str_data = str(hexlify(bts))[2:-1]
    return str_data.upper()

#analyzuje 802
def analyze_802(pkt_value, packet):
    snap_file = open("protocols/snap_pid.txt", "r")
    sap_file = open("protocols/sap.txt", "r")
    snap_pkt = convert_bytes(packet, 20, 22)
    snap_pkt = int(snap_pkt, 16)
    sap_pkt = convert_bytes(packet, 15, 16)
    sap_pkt = int(sap_pkt, 16)

    if pkt_value == 0xAA:
        packet_dict["frame_type"] = "IEEE 802.3 LLC & SNAP"
        print_mac(packet)

        for row in snap_file:
            snap_prot = row[0:5]
            snap_prot = int(snap_prot, 16)
            if snap_pkt == snap_prot:
                value_to_print = str(row[5:-1])
                packet_dict["pid"] = value_to_print

    elif pkt_value == 0xFF:
        packet_dict["frame_type"] = "IEEE 802.3 RAW"
        print_mac(packet)

    else:
        packet_dict["frame_type"] = "IEEE 802.3 LLC"
        print_mac(packet)

        for row in sap_file:
            sap_prot = row[0:3]
            sap_prot = int(sap_prot, 16)
            if sap_pkt == sap_prot:
                value_to_print = str(row[3:-1])
                packet_dict["sap"] = value_to_print


if __name__ == '__main__':
    while True:
        file_name = input("Zadaj nazov suboru: ")
        try:
            pcap = rdpcap('packets/' + file_name + '.pcap')
        except IOError:
            print('Zadal si zly nazov!')
            continue
        counter = 1
        #vytvorenie dictov pre zakladny subor a subor pre komunikacie
        yaml_file = {
            "name": "PKS2022/23",
            "pcap_name": file_name + '.pcap'
        }
        comm_file = {
            "name": "PKS2022/23",
            "pcap_name": "tftp.pcap",
            "filter_name": "TFTP"
        }
        print("1 - pre analyzu packetov\n2 - pre analyzu packetov a komunikacie (TFTP)\n3 - ukonci program")
        decision = input("Vyber si moznost:")
        packety = []
        comms = []
        tftp_comms = []
        tftp_ports = []
        if int(decision) == 3:
            break
        #cyklus prechadza kazdy packet v .pcap subore a robi zakladny vypis
        for packet in pcap:
            packet_dict = {}
            packet_len = len(packet)
            packet_dict["frame_number"] = counter
            if packet_len >= 61:
                packet_dict["len_frame_pcap"] = packet_len
                packet_dict["len_frame_medium"] = packet_len + 4
            else:
                packet_dict["len_frame_pcap"] = packet_len
                packet_dict["len_frame_medium"] = 64
            protocol = convert_bytes(packet, 12, 14)
            protocol = int(protocol, 16)
            isl_protocol = convert_bytes(packet, 0, 6)

            if protocol >= 0x0200:
                packet_dict["frame_type"] = "ETHERNET II"
                print_mac(packet)
                ether_type(protocol)
                if protocol == 0x0800:
                    ipv4(packet, counter)

            #kontrola ci nie je ISL protokol aby som vedel odignorovat prvych 26 bajtov
            elif isl_protocol == "01000C000000":
                prot = convert_bytes(packet, 41, 42)
                prot = int(prot, 16)
                if prot == 0xAA:
                    packet_dict["frame_type"] = "IEEE 802.3 LLC & SNAP"
                    packet_dict["src_mac"] = form_mac(packet, 32, 38)
                    packet_dict["dst_mac"] = form_mac(packet, 26, 32)
                    snap_pid = open("protocols/snap_pid.txt", "r")
                    snap_real = convert_bytes(packet, 46, 48)
                    snap_real = int(snap_real, 16)
                    for row in snap_pid:
                        snap_prot = row[0:5]
                        snap_prot = int(snap_prot, 16)
                        if snap_real == snap_prot:
                            value_to_print = str(row[5:-1])
                            packet_dict["pid"] = value_to_print

            else:
                llc_value = convert_bytes(packet, 14, 15)
                llc_value = int(llc_value, 16)
                analyze_802(llc_value, packet)

            packet_dict["hexa_frame"] = ruamel.yaml.scalarstring.LiteralScalarString(form_hexdump(packet))
            counter += 1
            packety.append(packet_dict)
        #pridavanie zaznamov do pola komunikacii (pamatam si len indexy ktore komunikovali a potom ich len vypisem)
        for counter, comm in enumerate(tftp_comms):
            comm_dict = {
                "number_comm": counter+1,
                "src_comm": comm["src_ip"],
                "dst_comm": comm["dst_ip"],
                "packets": []
            }
            for i in comm["packet_idx"]:
                comm_dict["packets"].append(packety[i])
            comms.append(comm_dict)
        #pridavanie zaznamov pre ipv4 senderov
        for ip, number in stats.items():
            test = {
                "node" : ip,
                "number_of_sent_packets" : number
            }
            staty.append(test)
        #vysorti dictionary ipv4 senderov aby som vedel vypisat tych co naviac odoslali
        sort_stats = sorted(stats.items(),key=lambda x:x[1],reverse=True)
        #vypis najviac odoslanych (ak su dvaja co odoslali rovnaky pocet vypise oboch
        pocitadlo = 0
        for x in sort_stats:
            max_value = 0
            if pocitadlo == 0:
                max_value = x[1]

            if max_value == x[1]:
                max_senders.append(x[0])
            pocitadlo += 1


        print(tftp_comms)
        yaml_file["packets"] = packety
        yaml_file["ipv4_senders"] = staty
        yaml_file["max_send_packets_by"] = max_senders
        comm_file["complete_comms"] = comms
        #zapis do .yaml
        with open(file_name + '.yaml', 'w') as outfile:
            yaml = ruamel.yaml.YAML()
            yaml.default_flow_style = False
            yaml.dump(yaml_file, outfile)
        if int(decision) == 2:
            with open('packets-tftp.yaml', 'w') as outfile:
                yaml = ruamel.yaml.YAML()
                yaml.default_flow_style = False
                yaml.dump(comm_file, outfile)

