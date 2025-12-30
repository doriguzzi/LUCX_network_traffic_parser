# Copyright (c) 2025 @ FBK - Fondazione Bruno Kessler
# Author: Roberto Doriguzzi-Corin
# Project: LUCX: LUCID network traffic parser eXtended
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import time
import glob
import copy
import pyshark
import socket
import pickle
import random
import hashlib
import argparse
import ipaddress
from collections import OrderedDict
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import OneHotEncoder
from multiprocessing import Process, Manager, Value, Queue
from util_functions import *

# Sample commands
# split a pcap file into smaller chunks to leverage multi-core CPUs: tcpdump -r dataset.pcap -w dataset-chunk -C 1000
# dataset parsing (first step): python3 lucx_network_traffic_parser.py --dataset_type DOS2019 --dataset_folder ./sample-dataset/ --packets_per_flow 10 --dataset_id DOS2019 --traffic_type all --time_window 10
# dataset parsing (second step): python3 lucx_network_traffic_parser.py --preprocess_folder ./sample-dataset/


IDS2018_DDOS_FLOWS = {'attackers': ['18.218.115.60', '18.219.9.1','18.219.32.43','18.218.55.126','52.14.136.135','18.219.5.43','18.216.200.189','18.218.229.235','18.218.11.51','18.216.24.42'],
                      'victims': ['18.218.83.150','172.31.69.28']}

IDS2017_DDOS_FLOWS = {'attackers': ['172.16.0.1'],
                      'victims': ['192.168.10.50']}

DOS2019_FLOWS = {'attackers': ['172.16.0.5'], 'victims': ['192.168.50.1', '192.168.50.4']}

BINARY_CLASSES = ['benign','ddos']

DOS2019_CLASSES = ['benign', 'dns', 'syn','udplag','webddos'] 
#DOS2019_CLASSES = ['benign', 'dns', 'ldap', 'mssql', 'netbios', 'ntp', 'portmap', 'snmp', 'ssdp', 'syn', 'tftp', 'udp', 'udplag', 'webddos'] #IMPORTANT: alphabetical order

DDOS_ATTACK_SPECS = {
    'DOS2017' : IDS2017_DDOS_FLOWS,
    'DOS2018' : IDS2018_DDOS_FLOWS,
    'DOS2019': DOS2019_FLOWS,
    'BINARY': DOS2019_FLOWS # for binary classification set the correct DDoS labels
}

DDOS_ATTACK_CLASSES = {
    'BINARY' : BINARY_CLASSES,
    'DOS2019': DOS2019_CLASSES
}

random.seed(SEED)
np.random.seed(SEED)

class packet_features:
    def __init__(self):
        self.id_fwd = (0,0,0,0,0) # 5-tuple src_ip_addr, src_port,,dst_ip_addr,dst_port,protocol
        self.id_bwd = (0,0,0,0,0)  # 5-tuple src_ip_addr, src_port,,dst_ip_addr,dst_port,protocol
        self.features_list = []


    def __str__(self):
        return "{} -> {}".format(self.id_fwd, self.features_list)  

def pyshark_packet_features(pkt,encoding_lookup,tls_fields_count):
    pf = packet_features()
    tmp_id = [0,0,0,0,0]
    
    try:
        pf.features_list.append(float(pkt.sniff_timestamp))  # timestampchild.find('Tag').text
        pf.features_list.append(int(pkt.ip.len))  # packet length
        pf.features_list.append(int(pkt.ip.ttl))  # TTL
        pf.features_list.append(flag_to_int(pkt.ip.flags_df)) # don't fragment
        pf.features_list.append(flag_to_int(pkt.ip.flags_mf)) # more fragments
        pf.features_list.append(flag_to_int(pkt.ip.flags_rb)) # reserved bit

        pf.features_list.append(int(pkt.ip.frag_offset)) # 13-bit fragment offset

        tmp_id[0] = str(pkt.ip.src)  # int(ipaddress.IPv4Address(pkt.ip.src))
        tmp_id[2] = str(pkt.ip.dst)  # int(ipaddress.IPv4Address(pkt.ip.dst))

        protocols =sentence_to_encoding(pkt.frame_info.protocols, encoding_lookup['protocols'])
        # print("Protocols: ",protocols)
        pf.features_list = pf.features_list + list(protocols)

        protocol = int(pkt.ip.proto)
        tmp_id[4] = protocol
        if pkt.transport_layer != None:
            if protocol == socket.IPPROTO_TCP:
                tmp_id[1] = int(pkt.tcp.srcport)
                tmp_id[3] = int(pkt.tcp.dstport)
                pf.features_list.append(int(pkt.tcp.len))  # TCP payload's length
                pf.features_list.append(flag_to_int(pkt.tcp.flags_ack)) # Acknowledgment
                pf.features_list.append(flag_to_int(pkt.tcp.flags_cwr)) # Congestion Window Reduced
                pf.features_list.append(flag_to_int(pkt.tcp.flags_ece)) # 
                pf.features_list.append(flag_to_int(pkt.tcp.flags_fin))
                pf.features_list.append(flag_to_int(pkt.tcp.flags_push))
                pf.features_list.append(flag_to_int(pkt.tcp.flags_reset))
                pf.features_list.append(flag_to_int(pkt.tcp.flags_syn))
                pf.features_list.append(flag_to_int(pkt.tcp.flags_urg))
                pf.features_list.append(int(pkt.tcp.window_size_value))  # TCP window size  
                
                if tls_fields_count > 0:
                    try:
                        # TLS layer is available if packet contains TLS
                        tls_layer = pkt.tls
                        tls_record_versions =sentence_to_encoding(getattr(tls_layer, 'record_version', '0x0'), encoding_lookup['tls_record_versions'])
                        pf.features_list = pf.features_list + list(tls_record_versions)
                        tls_handshake_extensions_supported_version =sentence_to_encoding(getattr(tls_layer, 'tls_handshake_extensions_supported_version', '0x0'), encoding_lookup['tls_handshake_extensions_supported_version'])
                        pf.features_list = pf.features_list + list(tls_handshake_extensions_supported_version)
                        tls_handshake_type =sentence_to_encoding(getattr(tls_layer, 'tls_handshake_type', '0x0'), encoding_lookup['tls_handshake_types'])
                        pf.features_list = pf.features_list + list(tls_handshake_type)
                        handshake_ciphersuite =sentence_to_encoding(getattr(tls_layer, 'handshake_ciphersuite', '0x0'), encoding_lookup['tls_handshake_ciphersuites'])
                        pf.features_list = pf.features_list + list(handshake_ciphersuite)
                        tls_record_content_type =sentence_to_encoding(getattr(tls_layer, 'record_content_type', '0x0'), encoding_lookup['tls_record_content_type'])
                        pf.features_list = pf.features_list + list(tls_record_content_type)

                        pf.features_list.append(int(getattr(tls_layer, 'record_length', 0)))  # TLS record length in bytes
                        #print ("TLS packet found:" , pf.features_list[29:])
                    except AttributeError:
                        pf.features_list = pf.features_list + [0]*tls_fields_count  # TLS fields not present
                pf.features_list = pf.features_list + [0, 0, 0]  # UDP + ICMP positions
            elif protocol == socket.IPPROTO_UDP:
                pf.features_list = pf.features_list + [0]*tls_fields_count + [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  # TCP positions
                tmp_id[1] = int(pkt.udp.srcport)
                pf.features_list.append(int(pkt.udp.length))  # UDP length (UDP header + payload)
                tmp_id[3] = int(pkt.udp.dstport)
                pf.features_list = pf.features_list + [0, 0]  # ICMP position
        elif protocol == socket.IPPROTO_ICMP:
            pf.features_list = pf.features_list + [0]*tls_fields_count + [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  # TCP and UDP positions
            pf.features_list.append(int(pkt.icmp.type))  # ICMP type
            pf.features_list.append(int(pkt.icmp.code))  # ICMP code
        else:
            pf.features_list = pf.features_list + [0]*tls_fields_count + [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  # padding for layer3-only packets (TCP+UDP+ICMP positions)
            tmp_id[4] = 0
    
        pf.id_fwd = (tmp_id[0], tmp_id[1], tmp_id[2], tmp_id[3], tmp_id[4])
        pf.id_bwd = (tmp_id[2], tmp_id[3], tmp_id[0], tmp_id[1], tmp_id[4])

        return pf

    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        return None   
    
def multiclass_labels(labels='BINARY'):
    one_hot_labels = {}

    if labels is not None and labels in DDOS_ATTACK_CLASSES:
        DDOS_CLASSES = DDOS_ATTACK_CLASSES[labels]
    else:
        return None 
    
    if len(DDOS_CLASSES) == 2:  # binary classification
        one_hot_labels[DDOS_CLASSES[0]] = 0  # benign
        one_hot_labels[DDOS_CLASSES[1]] = 1  # ddos
    else:  # multiclass classification
        label_encoder = LabelEncoder()
        integer_encoded = label_encoder.fit_transform(DDOS_CLASSES)


        # Reshape the integer encoded labels to a 2D array
        integer_encoded = integer_encoded.reshape(len(integer_encoded), 1)

        # One-hot encode the integer encoded labels
        onehot_encoder = OneHotEncoder(sparse_output=False)
        onehot_encoded = onehot_encoder.fit_transform(integer_encoded)

        # Print the original class labels
        #print("Original class labels:", DDOS_CLASSES)

        # Print the one-hot encoded representation
        #print("One-hot encoded representation:")
        for i in range(len(DDOS_CLASSES)):
            one_hot_labels[DDOS_CLASSES[i]] = onehot_encoded[i]
            #print(DDOS_CLASSES[i], "->", onehot_encoded[i])

    return one_hot_labels

def flag_to_int(value):
    mapping = {'0':0, 'False': 0, '1': 1, 'True': 1}
    return mapping.get(value, None)

def get_ddos_flows(attackers,victims):
    DDOS_FLOWS = {}

    if '/' in attackers: # subnet
        DDOS_FLOWS['attackers'] = [str(ip) for ip in list(ipaddress.IPv4Network(attackers).hosts())]
    else: # single address
        DDOS_FLOWS['attackers'] = [str(ipaddress.IPv4Address(attackers))]

    if '/' in victims:  # subnet
        DDOS_FLOWS['victims'] = [str(ip) for ip in list(ipaddress.IPv4Network(victims).hosts())]
    else:  # single address
        DDOS_FLOWS['victims'] = [str(ipaddress.IPv4Address(victims))]

    return DDOS_FLOWS

# function that build the labels based on the dataset type
def parse_labels(dataset_type=None, attackers=None,victims=None, label=1):
    output_dict = {}

    if attackers is not None and victims is not None:
        DDOS_FLOWS = get_ddos_flows(attackers, victims)
    elif dataset_type is not None and dataset_type in DDOS_ATTACK_SPECS:
        DDOS_FLOWS = DDOS_ATTACK_SPECS[dataset_type]
    else:
        return None

    for attacker in DDOS_FLOWS['attackers']:
        for victim in DDOS_FLOWS['victims']:
            ip_src = str(attacker)
            ip_dst = str(victim)
            key_fwd = (ip_src, ip_dst)
            key_bwd = (ip_dst, ip_src)

            if key_fwd not in output_dict:
                output_dict[key_fwd] = label
            if key_bwd not in output_dict:
                output_dict[key_bwd] = label

    return output_dict

def parse_packet(pkt,encoding_lookup, tls_fields_count, parser='pyshark'):
    return pyshark_packet_features(pkt,encoding_lookup,tls_fields_count)

# Offline preprocessing of pcap files for model training, validation and testing
def process_pcap(pcap_file,bin_labels,mc_labels, max_flow_len,labelled_flows,max_flows=0, tls_features = False, traffic_type='all',time_window=TIME_WINDOW, parser='pyshark'):
    start_time = time.time()
    temp_dict = OrderedDict()
    start_time_window = -1

    pcap_name = pcap_file.split("/")[-1]
    print("Processing file: ", pcap_name)
    traffic_label = pcap_name.split("-")[0]

    # Precompute one-hot encodings for categorical features
    protocol_lookup = precompute_encodings(categorical_features)
    tls_lookup = precompute_encodings(tls_categorical_features)
    encoding_lookup = protocol_lookup | tls_lookup

    # Precompute TLS fields count
    if tls_features == False:   
        tls_fields_count = 0    
    else:   
        tls_fields_count =  sum(len(v) for v in tls_categorical_features.values()) + 1  # +1 for record length

    if parser == 'pyshark':
        packets = pyshark.FileCapture(pcap_file)
    else:
        print("Unsupported parser:", parser)
        return

    for i, pkt in enumerate(packets):
        if i % 1000 == 0:
            print(pcap_name + " packet #", i)
        
        timestamp = float(pkt.sniff_timestamp)

        # start_time_window is used to group packets/flows captured in a time-window
        if start_time_window == -1 or timestamp > start_time_window + time_window:
            start_time_window = timestamp

        pf = parse_packet(pkt,encoding_lookup,tls_fields_count,parser)

        store_packet(pf, temp_dict, start_time_window, max_flow_len)
        if max_flows > 0 and len(temp_dict) >= max_flows:
            break

    apply_labels(temp_dict, labelled_flows, bin_labels, mc_labels, traffic_label, traffic_type)
    print('Completed file {} in {} seconds.'.format(pcap_name, time.time() - start_time))

# Transforms live traffic into input samples for inference
def process_live_traffic(cap, bin_labels,mc_labels, max_flow_len, tls_features = False,  traffic_type='all',time_window=TIME_WINDOW, parser='pyshark'):
    start_time = time.time()
    temp_dict = OrderedDict()
    labelled_flows = []

    # Label assigned to malicious live traffic (binary classification only)
    traffic_label = BINARY_CLASSES[1]  

    start_time_window = start_time
    time_window = start_time_window + time_window

    # Precompute one-hot encodings for categorical features
    protocol_lookup = precompute_encodings(categorical_features)
    tls_lookup = precompute_encodings(tls_categorical_features)
    encoding_lookup = protocol_lookup | tls_lookup

    # Precompute TLS fields count
    if tls_features == False:   
        tls_fields_count = 0    
    else:   
        tls_fields_count =  sum(len(v) for v in tls_categorical_features.values()) + 1  # +1 for record length

    if parser != 'pyshark':
        print("Unsupported parser:", parser)
        return

    if isinstance(cap, pyshark.LiveCapture) == True:
        for pkt in cap.sniff_continuously():
            if time.time() >= time_window:
                break
            pf = parse_packet(pkt,encoding_lookup,tls_fields_count,parser)
            temp_dict = store_packet(pf, temp_dict, start_time_window, max_flow_len)
    elif isinstance(cap, pyshark.FileCapture) == True:
        while time.time() < time_window:
            try:
                pkt = cap.next()
                pf = parse_packet(pkt,encoding_lookup,tls_fields_count,parser)
                temp_dict = store_packet(pf,temp_dict,start_time_window,max_flow_len)
            except:
                break

    apply_labels(temp_dict,labelled_flows, bin_labels, mc_labels, traffic_label, traffic_type)
    return labelled_flows

def store_packet(pf,temp_dict,start_time_window, max_flow_len):
    if pf is not None:
        if pf.id_fwd in temp_dict and start_time_window in temp_dict[pf.id_fwd] and \
                temp_dict[pf.id_fwd][start_time_window].shape[0] < max_flow_len:
            temp_dict[pf.id_fwd][start_time_window] = np.vstack(
                [temp_dict[pf.id_fwd][start_time_window], pf.features_list])
        elif pf.id_bwd in temp_dict and start_time_window in temp_dict[pf.id_bwd] and \
                temp_dict[pf.id_bwd][start_time_window].shape[0] < max_flow_len:
            temp_dict[pf.id_bwd][start_time_window] = np.vstack(
                [temp_dict[pf.id_bwd][start_time_window], pf.features_list])
        else:
            if pf.id_fwd not in temp_dict and pf.id_bwd not in temp_dict:
                temp_dict[pf.id_fwd] = {start_time_window: np.array([pf.features_list]), 'label': 0}
            elif pf.id_fwd in temp_dict and start_time_window not in temp_dict[pf.id_fwd]:
                temp_dict[pf.id_fwd][start_time_window] = np.array([pf.features_list])
            elif pf.id_bwd in temp_dict and start_time_window not in temp_dict[pf.id_bwd]:
                temp_dict[pf.id_bwd][start_time_window] = np.array([pf.features_list])
    return temp_dict

def apply_labels(flows, labelled_flows, bin_labels, mc_labels, traffic_label, traffic_type):
    for five_tuple, flow in flows.items():
        if bin_labels is not None:
            short_key = (five_tuple[0], five_tuple[2])  # for IDS2017/IDS2018 dataset the labels have shorter keys
            bin_label = bin_labels.get(short_key, 0) # attack/benign

            if bin_label == 0:
                flow['label'] = mc_labels['benign']
                flow['label_string'] = 'benign'
            else:
                flow['label'] = mc_labels[traffic_label]
                flow['label_string'] = traffic_label

        for flow_key, packet_list in flow.items():
            # relative time wrt the time of the first packet in the flow
            if flow_key != 'label' and flow_key != 'label_string':
                amin = np.amin(packet_list,axis=0)[0]
                packet_list[:, 0] = packet_list[:, 0] - amin

        labelled_flows.append((five_tuple,flow))

# returns the total number of flows
def count_flows(preprocessed_flows, mc_labels):
    flow_counters = {key: 0 for key in list(mc_labels.keys())}
    fragment_counters = {key: 0 for key in list(mc_labels.keys())}
    total_flows = len(preprocessed_flows)
    total_fragments = 0
    for flow in preprocessed_flows:
        flow_fragments = len(flow[1]) - 2 # the label and the label string do not count
        total_fragments += flow_fragments
        flow_label = flow[1]['label_string']
        flow_counters[flow_label] +=1
        fragment_counters[flow_label] += flow_fragments  

    return total_flows, total_fragments, flow_counters, fragment_counters

# balance the dataset based on the number of benign and malicious fragments of flows
def balance_dataset(flows,mc_labels,samples_per_class=float('inf')):
    new_flow_list = []
    new_fragment_counters = {key: 0 for key in list(mc_labels.keys())}

    _,_,_,fragment_counters = count_flows(flows,mc_labels)

    list_of_fragment_counters = np.array(list(fragment_counters.values()))

    fragment_nonzero_values = list_of_fragment_counters[np.nonzero(list_of_fragment_counters)]

    min_fragments = np.min(fragment_nonzero_values) #min(fragment_counters.values())
    samples_per_class = min(min_fragments,samples_per_class)

    for flow in flows:
        if new_fragment_counters[flow[1]['label_string']] < samples_per_class:
            new_fragment_counters[flow[1]['label_string']] += len(flow[1]) - 2
            new_flow_list.append(flow)

    return new_flow_list, new_fragment_counters

def mc_to_bin_labels(flows):
    labels = {'benign': 0, 'attack': 1}
    for flow in flows:
        if flow[1]['label_string'] == 'benign':
            flow[1]['label'] = labels['benign']
        else:
            flow[1]['label_string'] = 'attack'
            flow[1]['label'] = labels['attack']
    return flows, labels

def mc_to_int_labels(flows):
    labels = {}
    for flow in flows:
        flow[1]['label'] = DOS2019_CLASSES.index(flow[1]['label_string'])

        retVal = labels.get(flow[1]['label_string'])
        if retVal is None:
            labels[flow[1]['label_string']] = DOS2019_CLASSES.index(flow[1]['label_string'])
    return flows, labels

# convert the dataset from dictionaries with 5-tuples keys into a list of flow fragments and another list of labels
def dataset_to_list_of_fragments(dataset):
    keys = []
    X = []
    y = []

    for flow in dataset:
        tuple = flow[0]
        flow_data = flow[1]
        label = flow_data['label']
        for key, fragment in flow_data.items():
            if key != 'label' and key != 'label_string':
                X.append(fragment)
                y.append(label)
                keys.append(tuple)

    return X,y,keys

def train_test_split(flow_list,mc_labels, train_size=TRAIN_SIZE, shuffle=True):
    test_list = []
    _,total_fragments,_,_ = count_flows(flow_list,mc_labels)
    test_examples = total_fragments - total_fragments*train_size

    if shuffle == True:
        random.shuffle(flow_list)

    current_test_examples = 0
    while current_test_examples < test_examples:
        flow = flow_list.pop(0)
        test_list.append(flow)
        current_test_examples += len(flow[1])-2


    return flow_list,test_list

def main(argv):
    command_options = " ".join(str(x) for x in argv[1:])

    help_string = 'Usage[0]: python3 lucx_network_traffic_parser.py --dataset_type <dataset_name> --dataset_folder <folder path> --dataset_id <dataset identifier> --packets_per_flow <n> --time_window <t>\n' \
                  'Usage[1]: python3 lucx_network_traffic_parser.py --preprocess_folder <folder path>'
    manager = Manager()

    parser = argparse.ArgumentParser(
        description='Dataset parser',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-d', '--dataset_folder', nargs='+', type=str,
                        help='Folder with the dataset')
    parser.add_argument('-o', '--output_folder', nargs='+', type=str,
                        help='Output folder')
    parser.add_argument('-f', '--traffic_type', default='all', nargs='?', type=str,
                        help='Type of flow to process (all, benign, ddos)')
    parser.add_argument('-p', '--preprocess_folder', nargs='+', type=str,
                        help='Folder with preprocessed data')
    parser.add_argument('--preprocess_file', nargs='+', type=str,
                        help='File with preprocessed data')
    parser.add_argument('-t', '--dataset_type', nargs='?', type=str,
                        help='Type of the dataset. Available options are: DOS2017, DOS2018, DOS2019')
    parser.add_argument('-n', '--packets_per_flow', nargs='?', type=int, default=MAX_FLOW_LEN,
                        help='Maximum number of packets in a sample')
    parser.add_argument('-s', '--samples', default=float('inf'), type=int,
                        help='Number of training samples in the reduced output')
    parser.add_argument('-m', '--max_flows', default=0, type=int,
                        help='Max number of flows to extract from the pcap files')
    parser.add_argument('-c', '--classes', default='BINARY', type=str,
                        help='Names assigned to the traffic classes (e.g., BINARY, DOS2019)')

    

    parser.add_argument('-w', '--time_window', nargs='?', type=float, default=TIME_WINDOW,
                        help='Length of the time window')

    parser.add_argument('--dont_normalize', help='Normalize the dataset', action='store_true')
    parser.add_argument('--flatten', help='Flatten the input arrays', action='store_true')
    parser.add_argument('-mc', '--multiclass', default=0, type=int,
                        help='0=binary, 1=one-hot encoding multiclass, 2=integer multiclass')
    parser.add_argument('--parser', default='pyshark', nargs='?', type=str,
                        help='Pcap parser (scapy, pyshark)')
    
    parser.add_argument('--no_split', help='Do not split the dataset', action='store_true')
    parser.add_argument('--enable_tls', help='Extract TLS features', action='store_true')

    args = parser.parse_args()
    time_window = args.time_window
    max_flow_len = args.packets_per_flow
    traffic_type = args.traffic_type
    dataset_type = args.dataset_type
    parser = args.parser

    if args.dataset_folder is not None and args.dataset_type is not None:
        process_list = []
        flows_list = []

        if args.output_folder is not None and os.path.isdir(args.output_folder[0]) is True:
            output_folder = args.output_folder[0]
        else:
            output_folder = args.dataset_folder[0]

        in_labels = parse_labels(dataset_type,args.dataset_folder[0])
        mc_labels = multiclass_labels(args.classes)
        filelist = glob.glob(args.dataset_folder[0]+ '/*.pcap')

        start_time = time.time()
        for file in filelist:
            try:
                flows = manager.list()
                p = Process(target=process_pcap,args=(file,in_labels,mc_labels, max_flow_len,flows,args.max_flows, args.enable_tls, traffic_type,time_window,parser))
                process_list.append(p)
                flows_list.append(flows)
            except FileNotFoundError as e:
                continue

        for p in process_list:
            p.start()

        for p in process_list:
            p.join()

        np.seterr(divide='ignore', invalid='ignore')
        try:
            preprocessed_flows = list(flows_list[0])
        except:
            print ("ERROR: No traffic flows. \nPlease check that the dataset folder name (" + args.dataset_folder[0] + ") is correct and \nthe folder contains the traffic traces in pcap format (the pcap extension is mandatory)")
            exit(1)

        #concatenation of the features
        for results in flows_list[1:]:
            preprocessed_flows = preprocessed_flows + list(results)

        process_time = time.time()-start_time

        dataset_id = str(args.dataset_type)

        filename = str(int(time_window)) + 't-' + str(max_flow_len) + 'n-' + dataset_id + '-preprocess'
        output_file = output_folder + '/' + filename
        output_file = output_file.replace("//", "/") # remove double slashes when needed

        with open(output_file + '.data', 'wb') as filehandle:
            # store the data as binary data stream
            pickle.dump(preprocessed_flows, filehandle)

        total_flows, total_samples, flow_counters, fragment_counters = count_flows(preprocessed_flows,mc_labels)

        flow_string = ''
        for label, counter in flow_counters.items():
            flow_string += "("+ label + "," + str(counter) + ") "

        sample_string = ''
        for label, counter in fragment_counters.items():
            sample_string += "("+ label + "," + str(counter) + ") " 

        log_string = time.strftime("%Y-%m-%d %H:%M:%S") + " | dataset_type:" + args.dataset_type + \
                        " | Tot (flows,samples): (" + str(total_flows) + "," + str(total_samples) + ") | Flows: " + flow_string + "| Samples: " + sample_string + \
                        ") | options:" + command_options + " | process_time:" + str(process_time) + " |\n"
        print (log_string)

        # saving log file
        with open(output_folder + '/history.log', "a") as myfile:
            myfile.write(log_string)

    if args.preprocess_folder is not None or args.preprocess_file is not None:
        if args.preprocess_folder is not None:
            output_folder = args.output_folder[0] if args.output_folder is not None else args.preprocess_folder[0]
            filelist = glob.glob(args.preprocess_folder[0] + '/*.data')
        else:
            output_folder = args.output_folder[0] if args.output_folder is not None else os.path.dirname(os.path.realpath(args.preprocess_file[0]))
            filelist = args.preprocess_file

        # obtain time_window and flow_len from filename and ensure that all files have the same values
        time_window = None
        max_flow_len = None
        dataset_id = None
        for file in filelist:
            filename = file.split('/')[-1].strip()
            current_time_window = int(filename.split('-')[0].strip().replace('t',''))
            current_max_flow_len = int(filename.split('-')[1].strip().replace('n',''))
            current_dataset_id = str(filename.split('-')[2].strip())
            if time_window != None and current_time_window != time_window:
                print ("Inconsistent time windows!!")
                exit()
            else:
                time_window = current_time_window
            if max_flow_len != None and current_max_flow_len != max_flow_len:
                print ("Inconsistent flow lengths!!")
                exit()
            else:
                max_flow_len = current_max_flow_len

            if dataset_id != None and current_dataset_id != dataset_id:
                dataset_id = "IDS201X"
            else:
                dataset_id = current_dataset_id



        preprocessed_flows = []
        for file in filelist:
            with open(file, 'rb') as filehandle:
                # read the data as binary data stream
                preprocessed_flows = preprocessed_flows + pickle.load(filehandle)


        # balance samples and redux the number of samples when requested
        # transform a multiclass problem into a binary problem
        if args.multiclass == 0:
            preprocessed_flows, labels = mc_to_bin_labels(preprocessed_flows)
        elif args.multiclass == 1:
            labels = multiclass_labels(dataset_id)
        elif args.multiclass == 2:
            preprocessed_flows, labels = mc_to_int_labels(preprocessed_flows)
        
        # Full version of the dataset (no train/test/val split and no shuffling)
        X_full, y_full, _ = dataset_to_list_of_fragments(preprocessed_flows)

        preprocessed_flows, fragment_counters = balance_dataset(preprocessed_flows,labels,args.samples)
        total_flows,total_samples,_,_ = count_flows(preprocessed_flows, labels)

        if total_flows == 0:
            print("Empty dataset!")
            exit()

        preprocessed_train, preprocessed_test = train_test_split(preprocessed_flows,labels, train_size=TRAIN_SIZE, shuffle=True)
        preprocessed_train, preprocessed_val = train_test_split(preprocessed_train, labels, train_size=TRAIN_SIZE, shuffle=True)

        X_train, y_train, _ = dataset_to_list_of_fragments(preprocessed_train)
        X_val, y_val, _ = dataset_to_list_of_fragments(preprocessed_val)
        X_test, y_test, _ = dataset_to_list_of_fragments(preprocessed_test)

        # obtain 1D samples
        if args.flatten == True:
            X_full = flatten_samples(X_full,args.enable_tls)
            X_train = flatten_samples(X_train,args.enable_tls)
            X_val = flatten_samples(X_val,args.enable_tls)
            X_test = flatten_samples(X_test,args.enable_tls)

        mins,maxs = static_min_max(args.flatten,time_window=time_window,max_flow_len=max_flow_len, enable_tls=args.enable_tls) 
        # mins,maxs = find_min_max(X_full) # mins and maxs computed from the dataset

        output_file = output_folder + '/' + str(time_window) + 't-' + str(max_flow_len) + 'n-' + dataset_id + '-dataset'
        
        if args.flatten == True:
            norm_X_train = normalize(X_train,mins,maxs) if args.dont_normalize == False else X_train
            norm_X_val = normalize(X_val, mins, maxs) if args.dont_normalize == False else X_val
            norm_X_test = normalize(X_test, mins, maxs) if args.dont_normalize == False else X_test
            norm_X_full = normalize(X_full, mins, maxs) if args.dont_normalize == False else X_full
        else:
            norm_X_train = normalize_and_padding(X_train,mins,maxs,max_flow_len) if args.dont_normalize == False else padding(X_train,max_flow_len)
            norm_X_val = normalize_and_padding(X_val, mins, maxs,max_flow_len) if args.dont_normalize == False else padding(X_val,max_flow_len)
            norm_X_test = normalize_and_padding(X_test, mins, maxs,max_flow_len) if args.dont_normalize == False else padding(X_test,max_flow_len)
            norm_X_full = normalize_and_padding(X_full, mins, maxs,max_flow_len) if args.dont_normalize == False else padding(X_full,max_flow_len)

        norm_X_train_np = np.array(norm_X_train)
        y_train_np = np.array(y_train)
        norm_X_val_np = np.array(norm_X_val)
        y_val_np = np.array(y_val)
        norm_X_test_np = np.array(norm_X_test)
        y_test_np = np.array(y_test)

        norm_X_full_np = np.array(norm_X_full)
        y_full_np = np.array(y_full)

        hf = h5py.File(output_file + '-full.hdf5', 'w')
        hf.create_dataset('set_x', data=norm_X_full_np)
        hf.create_dataset('set_y', data=y_full_np)
        hf.close()

        hf = h5py.File(output_file + '-train.hdf5', 'w')
        hf.create_dataset('set_x', data=norm_X_train_np)
        hf.create_dataset('set_y', data=y_train_np)
        hf.close()

        hf = h5py.File(output_file + '-val.hdf5', 'w')
        hf.create_dataset('set_x', data=norm_X_val_np)
        hf.create_dataset('set_y', data=y_val_np)
        hf.close()

        hf = h5py.File(output_file + '-test.hdf5', 'w')
        hf.create_dataset('set_x', data=norm_X_test_np)
        hf.create_dataset('set_y', data=y_test_np)
        hf.close()

        fragment_string = ''
        for label, counter in fragment_counters.items():
            fragment_string += "("+ label + "," + str(counter) + ") " 

        [train_packets, val_packets, test_packets] = count_packets_in_dataset([norm_X_train_np, norm_X_val_np, norm_X_test_np],args.flatten)
        log_string = time.strftime("%Y-%m-%d %H:%M:%S") + " | Tot (flows,samples): (" + str(total_flows) + "," + str(total_samples) + ") | Samples: " + fragment_string + \
                        " | Train/Val/Test sizes: (" + str(norm_X_train_np.shape[0]) + "," + str(norm_X_val_np.shape[0]) + "," + str(norm_X_test_np.shape[0]) + \
                        ") | Packets (train,val,test):(" + str(train_packets) + "," + str(val_packets) + "," + str(test_packets) + \
                        ") | options:" + command_options + " |\n"

        print(log_string)

        # saving log file
        with open(output_folder + '/history.log', "a") as myfile:
            myfile.write(log_string)


    if args.dataset_folder is None and args.preprocess_folder is None:
        print (help_string)
    if args.dataset_type is None and args.dataset_folder is not None:
        print("Please specify the dataset type (DOS2017, DOS2018, DOS2020)!")
        print(help_string)

if __name__ == "__main__":
    main(sys.argv)
