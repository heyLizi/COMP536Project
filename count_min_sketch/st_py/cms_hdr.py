from scapy.all import *

TYPE_CMS = 0x8000;
PROTO_CMS = 0x19;

class CMS(Packet):
    name = "cms"
    fields_desc = [ 
        BitField("srcPort", 0, 16),
        BitField("dstPort", 0, 16),
        BitField("ts", 0, 32)
    ]


bind_layers(Ether, CMS, type=TYPE_CMS)
bind_layers(IP, CMS, proto=PROTO_CMS)