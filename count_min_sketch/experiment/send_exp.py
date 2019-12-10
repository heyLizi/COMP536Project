#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

sys.path.append("../st_py")

import pandas as pd

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from cms_hdr import *


def main():
    df = pd.read_csv("../../dataset/AOL_100t_top100.csv")

    print "finish loading query"

    for i in range(len(df)):
        row = df.iloc[i]
        dport = row["dport"]
        ts = row["ts"]

        iface = "h1-eth0"
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt /IP(dst="10.0.1.2") / CMS(dstPort=dport, srcPort=49152, ts=ts) / ''

        sendp(pkt, iface=iface, verbose=False)

        if i % 1000 == 0:
            print "%d finish" % i


if __name__ == '__main__':
    main()
