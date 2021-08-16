#!/usr/bin/env python
# coding: utf-8


from scapy.all import *
import pandas as pd

def read_pcap(file):
    all_fields = ['Source Path','Session','Protocol','Query Name','Payload','RR type'] 
    # removed 'time','source port','destination port', 'source IP','destination IP'
    df = pd.DataFrame(columns = all_fields)
    
    pcap = rdpcap(file)
    for k,v in pcap.sessions().items():
        for packet in v:

            if packet.haslayer(DNS) and isinstance(packet.an, DNSRR):
                values = []
                values.append(file) # source file path
                #values.append(float(packet.time)) # removed: not calculating time-based features
                values.append(k) # session                
                values.append(packet.payload.proto) # transport layer protocol
                values.append(str(packet.qd.qname)) # query name
                values.append(str(packet.an.rdata)) # payload
                values.append(int(packet.an.type))  # RR type
                
#                 for field in ['src','dst']:
#                     values.append(packet[IP].fields[field])
                
#                 for field in ['sport','dport']:
#                     values.append(packet[type(packet[IP].payload)].fields[field])

                df_append = pd.DataFrame([values], columns = all_fields)
                df = pd.concat([df, df_append], axis=0)

    df = df.reset_index()
    df = df.drop(columns='index')
    
    return df


import math
import wordninja
import numpy as np

def parse_features(df, label):
    df.loc[:,'Label'] = [int(label) for i in df.index]

    def splitquery(x):
        groups = x.rsplit('.',3)
        SD = groups[0].lstrip('b\'') if len(groups)==4 else ''
        TLD = '.'.join(groups[-3:-1]).lstrip('b\'')
        return SD, TLD

    df.loc[:,['Subdomain','Top Level Domain']] = [splitquery(query) for query in df['Query Name']]
    
    df = df.loc[:,['Label','Source Path','Session','Protocol','Query Name','Subdomain','Top Level Domain','Payload','RR type']]
  
    def shannon(x):
        x = str(x)
        freqs = (float(x.count(c))/len(x) for c in set(x))
        return -sum((prob * math.log(prob, 2) for prob in freqs))

    df.loc[:,'Subdomain Entropy'] = [shannon(name) for name in df['Subdomain']]
    df.loc[:,'Payload Entropy'] = [shannon(name) for name in df['Payload']]

    df.loc[:,'longest word Subdomain'] = [len(max(wordninja.split(name), key=len, default='')) for name in df['Subdomain']]
    
    def ratio(x):
        x = str(x)
        total = len(x)
        uppercase, lowercase, numeric, special = 0, 0, 0, 0
        if total != 0:
            for i in range(total):
                if x[i].isupper():
                    uppercase += 1
                elif x[i].islower():
                    lowercase += 1
                elif x[i].isdigit():
                    numeric += 1
                else:
                    special += 1
            return [uppercase/total, lowercase/total, numeric/total, special/total]
        else:
            return 0,0,0,0

    df.loc[:,['Subdomain Uppercase Ratio', 'Subdomain Lowercase Ratio', 'Subdomain Numeric Ratio', 'Subdomain Special Char Ratio']] \
        = [ratio(name) for name in df['Subdomain']]
    df.loc[:,['Payload Uppercase Ratio', 'Payload Lowercase Ratio', 'Payload Numeric Ratio', 'Payload Special Char Ratio']] \
        = [ratio(name) for name in df['Payload']]

    df.loc[:,'Packets in Session'] = df.groupby('Session')['Session'].transform('count')
    df.loc[:,'Avg Subdomain Length (Session)'] = df.groupby('Session')['Subdomain'].transform(lambda x: np.mean(x.str.len()))
    df.loc[:,'Avg Payload Length (Session)'] = df.groupby('Session')['Payload'].transform(lambda x: np.mean(x.str.len()))

    return df

    