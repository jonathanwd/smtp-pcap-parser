from scapy.all import *
import pandas as pd
import ipaddress
import sys
import os

def read_pcap(scapy_cap, data):
    for p in range(len(scapy_cap)):
        packet = scapy_cap[p]
        ip = packet.getlayer(IP)
        ip6 = packet.getlayer(IPv6)
        tcp = packet.getlayer(TCP)
        if ip6:
            ip = ip6
        if not ip or not tcp:
            continue
        client_ip = ip.src
        address = ipaddress.ip_address(client_ip)
        if address in ipaddress.ip_network('128.187.82.224/27') or address in ipaddress.ip_network('2620:10f:3007:a050::/64'):
            continue
        d = {
            'timestamp': packet.time,
            'client_ip': client_ip,
            'client_port': tcp.sport,
            'server_ip': ip.dst,
            'server_port': tcp.dport,
            'flags': str(tcp.flags),
            'seq': tcp.seq,
            'window': tcp.window,
            'version': ip.version 
        }
        data.append(d)

data = []
directory = str(sys.argv[1])
output_filename = "parsed.pkl"
for filename in os.listdir(directory):
    if filename.endswith(".pcap"):
        print("Parsing file " + filename)
        scapy_cap = rdpcap(directory + '/' + filename)
        read_pcap(scapy_cap, data)
df = pd.DataFrame(data=data)
df.to_pickle(output_filename)
print("pcap parsing complete")
