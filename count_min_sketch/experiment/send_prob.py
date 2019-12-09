#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
# import re

sys.path.append("../cnt_probe_py")
sys.path.append("../st_py")

import pandas as pd

from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import Ether, StrFixedLenField, XByteField, IntField
from scapy.all import bind_layers
from cnt_probe_hdr import *
import readline


def main():
    df = pd.read_csv("../../dataset/AOL_100t_top10.csv")
    print("finish loading data")

    for i in range(len(df)):
        row = df.iloc[i]
        dport = row["dport"]
        ts = row["ts"]

        iface = 'h1-eth0'
        pkt = Ether(dst='00:00:00:00:01:02', type=TYPE_CNT_PROBE)
        pkt = pkt / CntProbe(srcAddr="10.0.1.1", dstAddr="10.0.1.2", protocol=0x19, sport=49152, dport=dport, ts=ts)
        pkt = pkt/' '
        # pkt.show2()
        sendp(pkt, iface=iface, verbose=False)

        if i % 1000 == 0:
            print("%d finish" % i)

if __name__ == '__main__':
    main()

