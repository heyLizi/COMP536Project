/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_PROBE = 0x812;
const bit<16> TYPE_CNT_PROBE = 0x814;
const bit<8> PROTO_CMS = 0x19;

const bit<16> CMS_TABLE_NUM = 4;
const bit<16> CMS_TABLE_WIDTH = 32;

const bit<1> time_adaptive = 1;
const bit<32> TIME_PARAM = 1;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> time_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header cms_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> ts;
}

header probe_t {
    bit<32> heavyHitter;
}

header cnt_probe_t {
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<8> protocol;
    bit<16> sport;
    bit<16> dport;
    bit<32> ts;
    bit<32> count;
}


struct metadata {
    bit<16> hash_value1;
    bit<16> hash_value2;
    bit<16> hash_value3;
    bit<16> hash_value4;

    bit<32> count1;
    bit<32> count2;
    bit<32> count3;
    bit<32> count4;
    bit<32> min_count;
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    cms_t           cms;
    probe_t         probe;
    cnt_probe_t     cnt_probe;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_PROBE: parse_probe;
            TYPE_CNT_PROBE: parse_cnt_probe;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_CMS: parse_cms;
            default: accept;
        }
    }

    state parse_probe {
        packet.extract(hdr.probe);
        transition accept;
    }

    state parse_cnt_probe {
        packet.extract(hdr.cnt_probe);
        transition accept;
    }

    state parse_cms {
        packet.extract(hdr.cms);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1) heavy_hitter_reg; // port
    register<bit<32>>(1) hh_count_reg; // count

    register<bit<32>>((bit<32>)CMS_TABLE_WIDTH) hash_table_reg1;
    register<bit<32>>((bit<32>)CMS_TABLE_WIDTH) hash_table_reg2;
    register<bit<32>>((bit<32>)CMS_TABLE_WIDTH) hash_table_reg3;
    register<bit<32>>((bit<32>)CMS_TABLE_WIDTH) hash_table_reg4;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        // update forward port and ttl
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.probe.isValid()) {
            bit<32> heavy_hitter;
            heavy_hitter_reg.read(heavy_hitter, 0);
            hdr.probe.heavyHitter = heavy_hitter;
            standard_metadata.egress_spec = 2;
        } else if (hdr.cnt_probe.isValid() || hdr.ipv4.isValid()) {
            bit<16> hash_base = 0;
            bit<32> srcAddr = hdr.ipv4.isValid() ? hdr.ipv4.srcAddr : hdr.cnt_probe.srcAddr;
            bit<32> dstAddr = hdr.ipv4.isValid() ? hdr.ipv4.dstAddr : hdr.cnt_probe.dstAddr;
            bit<8> protocol = hdr.ipv4.isValid() ? hdr.ipv4.protocol : hdr.cnt_probe.protocol;
            bit<16> sport = hdr.ipv4.isValid() ? hdr.cms.srcPort : hdr.cnt_probe.sport;
            bit<16> dport = hdr.ipv4.isValid() ? hdr.cms.dstPort : hdr.cnt_probe.dport;
            bit<32> ts = hdr.ipv4.isValid() ? hdr.cms.ts : hdr.cnt_probe.ts;

            hash(meta.hash_value1, HashAlgorithm.crc16, hash_base, {srcAddr, dstAddr, protocol, sport, dport, ts}, CMS_TABLE_WIDTH);
            hash(meta.hash_value2, HashAlgorithm.crc16, hash_base, {dstAddr, protocol, sport, dport, srcAddr, ts}, CMS_TABLE_WIDTH);
            hash(meta.hash_value3, HashAlgorithm.crc16, hash_base, {protocol, sport, dport, srcAddr, dstAddr, ts}, CMS_TABLE_WIDTH);
            hash(meta.hash_value4, HashAlgorithm.crc16, hash_base, {sport, dport, srcAddr, dstAddr, protocol, ts}, CMS_TABLE_WIDTH);
            // read count
            hash_table_reg1.read(meta.count1, (bit<32>)meta.hash_value1);
            hash_table_reg2.read(meta.count2, (bit<32>)meta.hash_value2);
            hash_table_reg3.read(meta.count3, (bit<32>)meta.hash_value3);
            hash_table_reg4.read(meta.count4, (bit<32>)meta.hash_value4);
            // find min
            meta.min_count = meta.count1;
            if (meta.count2 < meta.min_count) meta.min_count = meta.count2;
            if (meta.count3 < meta.min_count) meta.min_count = meta.count3;
            if (meta.count4 < meta.min_count) meta.min_count = meta.count4;
            // calculate ft
            bit<32> ft = 1;
            if (time_adaptive == 1) {
                // pre-emphasis
                ft = (bit<32>)ts * TIME_PARAM;
            }

            if (hdr.ipv4.isValid()) {
                ipv4_lpm.apply();
                bit<32> curr_hh_cnt;
                // update count
                meta.count1 = meta.count1 + ft;
                meta.count2 = meta.count2 + ft;
                meta.count3 = meta.count3 + ft;
                meta.count4 = meta.count4 + ft;
                // write back
                hash_table_reg1.write((bit<32>)meta.hash_value1, meta.count1);
                hash_table_reg2.write((bit<32>)meta.hash_value2, meta.count2);
                hash_table_reg3.write((bit<32>)meta.hash_value3, meta.count3);
                hash_table_reg4.write((bit<32>)meta.hash_value4, meta.count4);
                // update min
                meta.min_count = meta.min_count + ft;
                // update heavy hitter reg
                hh_count_reg.read(curr_hh_cnt, 0);
                if (curr_hh_cnt < meta.min_count) {
                    hh_count_reg.write(0, curr_hh_cnt);
                    heavy_hitter_reg.write(0, (bit<32>)hdr.cms.dstPort);
                }
            } else if (hdr.cnt_probe.isValid()) {
                standard_metadata.egress_spec = 2;
                hdr.cnt_probe.count = meta.min_count;
                // de-emphasis
                // meta.min_count = meta.min_count / ft;
                bit<32> quo = 0;
                bit<32> remainder = 0;
                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 31)) >> 31);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 30)) >> 30);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 29)) >> 29);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 28)) >> 28);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 27)) >> 27);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 26)) >> 26);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 25)) >> 25);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 24)) >> 24);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 23)) >> 23);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 22)) >> 22);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 21)) >> 21);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 20)) >> 20);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 19)) >> 19);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 18)) >> 18);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 17)) >> 17);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 16)) >> 16);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 15)) >> 15);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 14)) >> 14);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 13)) >> 13);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 12)) >> 12);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 11)) >> 11);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 10)) >> 10);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 9)) >> 9);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 8)) >> 8);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 7)) >> 7);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 6)) >> 6);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 5)) >> 5);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 4)) >> 4);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 3)) >> 3);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 2)) >> 2);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 1)) >> 1);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}

                quo = quo << 1; remainder = remainder << 1;
                remainder = remainder | ((meta.min_count & (1 << 0)) >> 0);
                if (remainder >= ft) { remainder = remainder - ft; quo = quo | 1;}
                
                hdr.cnt_probe.count = quo;
            } 
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
	   update_checksum(
	        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.cms);
        packet.emit(hdr.probe);
        packet.emit(hdr.cnt_probe);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
