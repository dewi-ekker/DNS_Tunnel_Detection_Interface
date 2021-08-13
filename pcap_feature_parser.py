#!/usr/bin/env python
# coding: utf-8


from scapy.all import *
import pandas as pd

def read_pcap(file):
    all_fields = ['Source Path','Session','Source Port','Destination Port',
                  'Protocol','RR type','Queryname','Payload'] # removed 'source IP','destination IP'
    df = pd.DataFrame(columns = all_fields)
    
    pcap = rdpcap(file)
    for k,v in pcap.sessions().items():
        for packet in v:

            if packet.haslayer(DNS) and isinstance(packet.an, DNSRR):
                values = []
                values.append(file) # source filepath
                #values.append(float(packet.time)) # removed time: not calculating time-based features
                values.append(k) # session
                
                #for field in ['src','dst']:
                    #values.append(packet[IP].fields[field])
                
                for field in ['sport','dport']:
                    values.append(packet[type(packet[IP].payload)].fields[field])
                
                values.append(packet.payload.proto) # transport layer protocol
                values.append(int(packet.an.type))  # RR type
                values.append(str(packet.qd.qname)) # query name
                values.append(str(packet.an.rdata)) # payload

                df_append = pd.DataFrame([values], columns = all_fields)
                df = pd.concat([df, df_append], axis=0)

    df = df.reset_index()
    df = df.drop(columns='index')
    
    return df


import math
import wordninja
import numpy as np

def parse_features(df, label):
    df.insert(1, 'Label', [int(label) for i in df.index])

    def splitquery(x):
        groups = x.rsplit('.',3)
        SD = groups[0].lstrip('b\'') if len(groups)==4 else ''
        TLD = '.'.join(groups[-3:-1]).lstrip('b\'')
        return SD, TLD

    df[['Subdomain','Top Level Domain']] = [splitquery(query) for query in df['Queryname']]
  
    def shannon(x):
        x = str(x)
        freqs = (
            float(x.count(c))/len(x)
            for c in set(x))
        return -sum((
            prob * math.log(prob, 2)
            for prob in freqs))

#     df['Queryname Entropy'] = [shannon(name) for name in df['Queryname']]
    df['Subdomain Entropy'] = [shannon(name) for name in df['Subdomain']]
    df['Payload Entropy'] = [shannon(name) for name in df['Payload']]

    df['longest word Subdomain'] = [len(max(wordninja.split(name), key=len, default='')) for name in df['Subdomain']]
    df['longest word Payload'] = [len(max(wordninja.split(name), key=len, default='')) for name in df['Payload']]

    def count(x):
        x = str(x)
        total = len(x)
        uppercase, lowercase, numeric, special = 0, 0, 0, 0
        for i in range(total):
            if x[i].isupper():
                uppercase += 1
            elif x[i].islower():
                lowercase += 1
            elif x[i].isdigit():
                numeric += 1
            else:
                special += 1
        return [total, uppercase, lowercase, numeric, special]

#     df[['Character Count', 
#         'Uppercase Count', 
#         'Lowercase Count', 
#         'Numeric Count', 
#         'Special Char Count']] = [count(name) for name in df['Queryname']]
    
    df[['Subdomain Character Count', 
        'Subdomain Uppercase Count', 
        'Subdomain Lowercase Count', 
        'Subdomain Numeric Count', 
        'Subdomain Special Char Count']] = [count(name) for name in df['Subdomain']]
    
    df[['Payload Character Count', 
        'Payload Uppercase Count', 
        'Payload Lowercase Count', 
        'Payload Numeric Count', 
        'Payload Special Char Count']] = [count(name) for name in df['Payload']]

#     df['Dashes Count'] = [str(name).count('-') for name in df['Queryname']]
#     df['Slashes Count'] = [str(name).count('/') for name in df['Queryname']]
#     df['Periods Count'] = [str(name).count('.') for name in df['Queryname']]
#     df['Equal Signs Count'] = [str(name).count('=') for name in df['Queryname']]

    df['Packets in Session'] = df.groupby('Session')['Session'].transform('count')
    
#     df['Avg Queryname Length (Session)'] = df.groupby('Session')['Queryname'].transform(lambda x: np.mean(x.str.len()))
    df['Avg Subdomain Length (Session)'] = df.groupby('Session')['Subdomain'].transform(lambda x: np.mean(x.str.len()))
    df['Avg Payload Length (Session)'] = df.groupby('Session')['Payload'].transform(lambda x: np.mean(x.str.len()))

    return df

    