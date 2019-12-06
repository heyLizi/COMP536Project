#!/usr/bin/env python
import sys
import struct
import os
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR
from cnt_probe_hdr import *

def expand(pkt):
    yield pkt
    while pkt.payload:
        pkt = pkt.payload
        yield pkt

def handle_pkt(pkt):
    if CntProbe not in pkt:
        return

    pkt.show2()
    layers = [l for l in expand(pkt) if l.name == 'cnt_probe']

    for info in layers:
        print "dport: " + str(info.dport)
        print "count: " + str(info.count)
        
    sys.stdout.flush()


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
