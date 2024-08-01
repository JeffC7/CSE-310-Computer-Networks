import dpkt

def is_arp_request(packet):
    address = packet[0:6].hex()
    if address == 'ffffffffffff':
        return False
    opcode = int.from_bytes(packet[20:22], "big")
    return opcode == 1

def is_arp_reply(packet):
    address = packet[0:6].hex()
    if address == 'ffffffffffff':
        return False
    opcode = int.from_bytes(packet[20:22], "big")
    return opcode == 2

def is_exchange(request, reply):
    if request[28:32] == reply[38:42] and request[38:42] == reply[28:32]:
        return True
    return False

def printMACAddress(address):
    return "{}:{}:{}:{}:{}:{}".format(address[0:2], address[2:4], address[4:6], address[6:8], address[8:10], address[10:12])

def printIPAddress(address):
    return "{}.{}.{}.{}".format(address[0], address[1], address[2], address[3])

def print_arp_packet(packet):
    print("Hardware Type: {}".format(int.from_bytes(packet[14:16], "big")))
    print("Protocol Type: 0x{}".format(packet[16:18].hex()))
    print("Hardware Size: {}".format(int.from_bytes(packet[18:19], "big")))
    print("Protocol Size: {}".format(int.from_bytes(packet[19:20], "big")))
    print("Opcode: {}".format(int.from_bytes(packet[20:22], "big")))
    print("Sender MAC address: {}".format(printMACAddress(packet[22:28].hex())))
    print("Sender IP address: {}".format(printIPAddress(packet[28:32])))
    print("Target MAC address: {}".format(printMACAddress(packet[32:38].hex())))
    print("Target IP address: {}".format(printIPAddress(packet[38:42])))

def print_exchange():
    filename = input("Type in the name of the pcap file you want to analyze (should be in the same directory): ")
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)

    arp_packets = []
    for ts, buf in pcap:
        # check if the packet is an ARP packet
        if buf[12:14] == b'\x08\x06':
            # check if the packet is an ARP request
            if is_arp_request(buf) and len(arp_packets) == 0:
                arp_packets.append(buf)
            # check if the packet is an ARP reply
            elif is_arp_reply(buf) and len(arp_packets) == 1 and is_exchange(arp_packets[0], buf):
                arp_packets.append(buf)
                break
    print("ARP Request:")
    print_arp_packet(arp_packets[0])
    print("")
    print("ARP Reply:")
    print_arp_packet(arp_packets[1])    

print_exchange()