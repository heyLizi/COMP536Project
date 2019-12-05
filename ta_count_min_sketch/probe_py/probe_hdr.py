from scapy.all import *

TYPE_PROBE = 0x812

class Probe(Packet):
	name = "probe"
	fields_desc = [ IntField("heavyHitter", 0)]

bind_layers(Ether, Probe, type=TYPE_PROBE)
