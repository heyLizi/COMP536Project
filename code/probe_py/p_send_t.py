#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
# import re

from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import Ether, StrFixedLenField, XByteField, IntField
from scapy.all import bind_layers
from probe_hdr import *
import readline


def main():
    print "collecting heavy hitter' statistics.."
    iface = 'h1-eth0'
    pkt = Ether(dst='00:00:00:00:01:02', type=TYPE_PROBE) / \
            Probe(heavyHitter = 0)
    pkt = pkt/' '
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
