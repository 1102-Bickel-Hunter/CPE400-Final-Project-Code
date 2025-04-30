# Hunter Bickel
# 4/29/25
import datetime
import glob
import os
import pandas as pd
from scapy.all import rdpcap, wrpcap, load_layer, Raw
from scapy.layers.inet import TCP, UDP
from scapy.layers.tls.record import TLS
from scapy.layers.http import HTTPRequest, HTTPResponse

# Load TLS layers
load_layer('tls')

# Classify encryption
def classify_packet(pkt):
    # Encrypted TLS (TCP) check
    if pkt.haslayer(TLS):
        return True
    # Unencrypted HTTP check or raw payload on TCP/UDP
    if pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse) or pkt.haslayer(Raw):
        return False
    # Else
    return None

# Process packets
records = []

for pcap_file in glob.glob('captures/*.pcap'):
    
    packets = rdpcap(pcap_file)

    for pkt in packets:

        proto = ''
        
        # Get protocol information
        if pkt.haslayer(TCP):
            proto = 'TCP'
        elif pkt.haslayer(UDP):
            proto = 'UDP'
        else: # If packet does not have TCP or UDP, then skip it
            continue   

        encrypted = classify_packet(pkt)

        # Append to records
        records.append({
            'capture': os.path.basename(pcap_file),
            'protocol': proto,
            'encrypted': encrypted
        })

# Create data and export

datafile = pd.DataFrame(records)
print(
    datafile
    .groupby(['capture', 'encrypted'])
    .size()
    .rename_axis(['capture', 'encrypted'])
    .reset_index(name='count')
)
datafile.to_csv('output.csv', index=False)