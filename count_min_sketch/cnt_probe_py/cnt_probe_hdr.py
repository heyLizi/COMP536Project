from scapy.all import *

TYPE_CNT_PROBE = 0x814

class CntProbe(Packet):
	name = "cnt_probe"
	fields_desc = [
		IPField("srcAddr", "0.0.0.0"),
		IPField("dstAddr", "0.0.0.0"),
		ByteField("protocol", 0),
		BitField("sport", 0, 16),
		BitField("dport", 0, 16),
		BitField("count", 0, 64)
	]
bind_layers(Ether, CntProbe, type=TYPE_CNT_PROBE)
