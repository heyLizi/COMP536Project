#!/usr/bin/env python
import argparse
import sys
import socket
import random
import string
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from probe_hdrs import *

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def generate_random_payload():
    chars = string.ascii_letters + string.digits
    random_len=random.randint(1, 50)
    random_str_list = [random.choice(chars) for i in range(random_len)]
    random_payload = ''.join(random_str_list)
    return random_payload


def send_data_packet_with_random_sport(dstAddr, payload):
    iface = get_if()
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=dstAddr) / TCP(dport=1234, sport=random.randint(49152,65535)) / payload
    print "Sending "+payload
    #pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


def send_data_packet_with_fixed_sport(dstAddr, payload):
    iface = get_if()
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=dstAddr) / TCP(dport=1234, sport=65535) / payload
    print "Sending "+payload
    #pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


def send_probe_packet(sw1_out_port, payload):
    iface = get_if()
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')  / \
           Probe(hop_cnt=0, packet_id=pkt_id) / \
           ProbeFwd(egress_spec=sw1_out_port) / \
           ProbeFwd(egress_spec=2) / \
           ProbeFwd(egress_spec=1) / \
           payload
    #pkt.show2()
    print "Sending probe packet with "+str(pkt_id)
    sendp(pkt, iface=iface, verbose=False)


def read_data_from_log_and_do_statistics():
    """
    Need to ensure s1.log is truncated before "make" and no packet is sent in this python file before the codes who call the method  
    """
    s1_total_cnt, sw2_cnt, sw3_cnt = 0, 0, 0  # how many times that a packet passes through each switch
    s1_total_amnt, sw2_amnt, sw3_amnt = 0, 0, 0  # how much traffic amount is sent via each switch
    target_str_1 = "Transmitting packet of size "
    target_str_2 = " out of port 2" 
    target_str_3 = " out of port 3" 
    with open("logs/s1.log", "r") as log1:
        for line in log1:
            if target_str_2 in line:
                start_idx = line.index(target_str_1) + len(target_str_1)
                end_idx = line.index(target_str_2)
                amnt = line[start_idx:end_idx]
                amnt = int(amnt)
                sw2_cnt = sw2_cnt + 1
                s1_total_cnt = s1_total_cnt + 1
                sw2_amnt = sw2_amnt + amnt
                s1_total_amnt = s1_total_amnt + amnt
            elif target_str_3 in line:
                start_idx = line.index(target_str_1) + len(target_str_1)
                end_idx = line.index(target_str_3)
                amnt = line[start_idx:end_idx]
                amnt = int(amnt)
                sw3_cnt = sw3_cnt + 1
                s1_total_cnt = s1_total_cnt + 1
                sw3_amnt = sw3_amnt + amnt
                s1_total_amnt = s1_total_amnt + amnt
    print "Total Count via SW1: "+str(s1_total_cnt)
    print "      Count via SW2: "+str(sw2_cnt)
    print "      Count via SW3: "+str(sw3_cnt)
    print "Total Traffic Amount via SW1: "+str(s1_total_amnt)
    print "      Traffic Amount via SW2: "+str(sw2_amnt)
    print "      Traffic Amount via SW3: "+str(sw3_amnt)


def main():

    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)
    
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    
    '''
    print "************************************* Milestone 1 *************************************"
     
    print "**         Task 1&2: Build Network and Perform ECMP Load Balancing at S1             **"
    print "sending on interface %s to %s" % (iface, str(addr))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)
    
    print "\n"
    print "**               Task 3: Implement a Query Packet and Perform Monitoring             **"
    send_probe_packet(1, 2, "probe_pkt")
    send_probe_packet(1, 3, "probe_pkt")

    print "\n"
    print "***************************************************************************************"
    print "\n\n"
    '''
    
    '''
    print "************************************* Milestone 2 *************************************"
    print "**                Task 1: Generate Flows and Do Statistics of ECMP                   **"
    
    for i in range(0, 50):
        random_payload = generate_random_payload()
        send_data_packet_with_random_sport(addr, random_payload)
    read_data_from_log_and_do_statistics()
    
    for i in range(0, 50):
        random_payload = generate_random_payload()
        send_data_packet_with_fixed_sport(addr, random_payload)
    read_data_from_log_and_do_statistics()
    
    print "\n"
    print "**         Task 2&3: Perform Per-Packet Load Balancing at S1 and Do Statistics       **"
    for i in range(0, 50):
        payload_i = "payload"+str(i)
        send_data_packet_with_fixed_sport(addr, payload_i)
    read_data_from_log_and_do_statistics()
    '''
    
    print "************************************* Milestone 3 *************************************"
    print "**         Task 1&2: Perform Flowlet Load Balancing at S1 and Do Statistics          **"
    
    for i in range(0, 50):
        payload_i = "payload"+str(i)
        send_data_packet_with_fixed_sport(addr, payload_i)
    read_data_from_log_and_do_statistics()
    

if __name__ == '__main__':
    main()
