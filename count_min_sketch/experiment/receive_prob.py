#!/usr/bin/env python
import sys
import struct
import os

sys.path.append("../cnt_probe_py")

import pandas as pd

from scapy.all import *
from scapy.layers.inet import _IPOption_HDR
from cnt_probe_hdr import *

data = []

def expand(pkt):
    yield pkt
    while pkt.payload:
        pkt = pkt.payload
        yield pkt

def handle_pkt(pkt):
    if CntProbe not in pkt:
        return

    # pkt.show2()
    layers = [l for l in expand(pkt) if l.name == 'cnt_probe']

    for info in layers:
        print "dport: " + str(info.dport)
        print "count: " + str(info.count)
        data.append([info.dport, info.ts, info.count])
        
    sys.stdout.flush()


def main():
    iface = "h2-eth0"
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))
    
    # store prob result to file
    df = pd.DataFrame(data, columns=["dport", "ts", "count"])
    df.to_csv("top10_prob_count.csv", index=None)

if __name__ == '__main__':
    main()

