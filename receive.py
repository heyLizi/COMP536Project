#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

from probe_hdrs import *

def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]


def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234:
        #pkt.show2()
        print "Receiving "+str(pkt[Raw])
        #hexdump(pkt)
        sys.stdout.flush()

    if Probe in pkt:
        print "Number of bytes sent out by outgoing ports"
        if ProbeData in pkt[Probe]:
            data_layers = [l for l in expand(pkt) if l.name=='ProbeData']
            for data in data_layers:
                print "    Switch {} - Port {}: {} bytes".format(data.swid, data.port, data.byte_cnt)
        print ""
        
        


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
