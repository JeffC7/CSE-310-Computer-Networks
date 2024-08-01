import dpkt, socket

SENDER_IP = "130.245.145.12"
RECEIVER_IP = "128.208.2.198"
total_tcp_flows = 0
flows = {}

f = open("assignment2.pcap", 'rb')
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
    ethernet_data = dpkt.ethernet.Ethernet(buf)
    source  = socket.inet_ntoa(ethernet_data.ip.src)
    destination = socket.inet_ntoa(ethernet_data.ip.dst)
    tcp = ethernet_data.ip.data
    syn_flag = tcp.flags & 2
    ack_flag = tcp.flags & 16
    fin_flag = tcp.flags & 1
    
    pkt = {
        'src': source, 
        'dst': destination,
        'source_port': tcp.sport,
        "destination_port": tcp.dport,
        'tcp': tcp,
        'timestamp': ts
    }
    
    if (source == SENDER_IP and destination == RECEIVER_IP):
        if(syn_flag):
            total_tcp_flows += 1
            flows[tcp.sport] = [pkt]
        elif(ack_flag):
            flows[tcp.sport].append(pkt)
    elif destination == SENDER_IP and source == RECEIVER_IP:
        if(ack_flag):
            flows[tcp.dport].append(pkt)

print("The total number of TCP Flows: %s" % total_tcp_flows + "\n")
flow_counter = 1
for flow in flows.values():
    print("Flow " + str(flow_counter) + ":")
    print("Source port: " + str(flow[0]['source_port']) + " Source IP: " + str(flow[0]['src']) + " Destination port: " + str(flow[0]['destination_port']) + " Destination IP: " + str(flow[0]['dst']))
    
    dopts = dpkt.tcp.parse_opts(flow[0]['tcp'].opts)
    scale_factor = int.from_bytes(dopts[5][1], byteorder='big')
    print("1st Transaction: Sequence Number: " + str(flow[3]['tcp'].seq) + " Ack Number: " + str(flow[3]['tcp'].ack) + " Receive Window Size: " + str(flow[3]['tcp'].win * (2 ** scale_factor)))
    print("2nd Transaction: Sequence Number: " + str(flow[4]['tcp'].seq) + " Ack Number: " + str(flow[4]['tcp'].ack) + " Receive Window Size: " + str(flow[4]['tcp'].win * (2 ** scale_factor)))
    print("The throughput of sender: " + str((flow[len(flow)-3]['tcp'].ack - flow[3]['tcp'].seq)/(flow[len(flow)-3]['timestamp']- flow[3]['timestamp'])) + " bytes/second" + "\n")
    
    triple_ack_counter = 0
    acks = {} # counter to see how many times the server sends packet with same ack number
    triple_ack_ready = 0
    seqs = set()
    rtt = flow[1]["timestamp"] - flow[0]["timestamp"]
    rto = 2 * rtt
    times = {}
    timout_counter = 0
    other_counter = 0
    
    cw = []
    packet_counter = 0
    start_time = flow[0]['timestamp']
    end_time = flow[1]['timestamp']
    cw_rtt =  end_time - start_time
    for pkt in flow:
        if(pkt["src"] == SENDER_IP):
            if len(cw) < 3:
                if pkt is not flow[0] or not flow[1]:
                    time = (pkt['timestamp'] - start_time) - ((len(cw) + 1) * rtt)
                    if (rtt < time):
                        cw.append(packet_counter)
                        packet_counter = 0
                    packet_counter += 1
        # Check to see if the client is sending an ack
        if(pkt["src"] == SENDER_IP):
            tcp = pkt["tcp"]
            if(tcp.seq+len(tcp.data) in seqs):
                if(triple_ack_ready == tcp.seq):
                    triple_ack_counter += 1
                    triple_ack_ready = False
                elif pkt["timestamp"] - times[tcp.seq+len(tcp.data)] > rto:
                    timout_counter += 1
                else:
                    other_counter += 1
            else:
                times[tcp.seq+len(tcp.data)] = pkt["timestamp"]
                seqs.add(tcp.seq+len(tcp.data))

        # Check to see if the server is sending an ack
        if(pkt["src"] == RECEIVER_IP):
            if(pkt['tcp'].ack not in acks):
                acks[pkt['tcp'].ack] = 1
            else:
                acks[pkt['tcp'].ack] += 1
            
            if acks[pkt['tcp'].ack] == 3:
                triple_ack_ready = pkt['tcp'].ack

    print("Congestion Window Sizes: " + str(cw))
    print("The number of retransmissions due to triple acks: " + str(triple_ack_counter))
    print("The number of retransmissions due to timeouts: " + str(timout_counter))
    print("The number of retransmissions due to other reasons: " + str(other_counter) + "\n")


    flow_counter += 1