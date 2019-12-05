#!/usr/bin/env python
import sys
import struct
import os
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR
from probe_hdr import *

def expand(pkt):
    yield pkt
    while pkt.payload:
        pkt = pkt.payload
        yield pkt

def handle_pkt(pkt):
    if Probe not in pkt:
        return

    pkt.show2()
    layers = [l for l in expand(pkt) if l.name == 'probe']

    for info in layers:
        print "heavy hitter: " + str(info.heavyHitter)
        
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
