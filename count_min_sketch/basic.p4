/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_PROBE = 0x812;
const bit<8> TCP_PROTO = 0x06;

const bit<16> CMS_TABLE_NUM = 4;
const bit<16> CMS_TABLE_WIDTH = 32;

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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header probe_t {
    bit<32> heavyHitter;
}

struct metadata {
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    tcp_t           tcp;
    probe_t         probe;
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
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TCP_PROTO: parse_tcp;
            default: accept;
        }
    }

    state parse_probe {
        packet.extract(hdr.probe);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
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
    register<bit<64>>(1) hh_count_reg; // count

    register<bit<64>>((bit<32>)CMS_TABLE_WIDTH) hash_table_reg1;
    register<bit<64>>((bit<32>)CMS_TABLE_WIDTH) hash_table_reg2;
    register<bit<64>>((bit<32>)CMS_TABLE_WIDTH) hash_table_reg3;
    register<bit<64>>((bit<32>)CMS_TABLE_WIDTH) hash_table_reg4;

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
        } else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            
            bit<16> hash_value1;
            bit<16> hash_value2;
            bit<16> hash_value3;
            bit<16> hash_value4;

            bit<64> count1;
            bit<64> count2;
            bit<64> count3;
            bit<64> count4;
            bit<64> min_count;
            bit<64> curr_hh_cnt;

            bit<16> hash_base = 0;

            // update count min sketch
            hash(hash_value1, HashAlgorithm.crc16, hash_base, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort,hdr.tcp.dstPort}, CMS_TABLE_WIDTH);
            hash(hash_value2, HashAlgorithm.crc16, hash_base, {hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.tcp.srcPort,hdr.tcp.dstPort, hdr.ipv4.srcAddr}, CMS_TABLE_WIDTH);
            hash(hash_value3, HashAlgorithm.crc16, hash_base, {hdr.ipv4.protocol, hdr.tcp.srcPort,hdr.tcp.dstPort, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, CMS_TABLE_WIDTH);
            hash(hash_value4, HashAlgorithm.crc16, hash_base, {hdr.tcp.srcPort,hdr.tcp.dstPort, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol}, CMS_TABLE_WIDTH);

            // read count
            hash_table_reg1.read(count1, (bit<32>)hash_value1);
            hash_table_reg2.read(count2, (bit<32>)hash_value2);
            hash_table_reg3.read(count3, (bit<32>)hash_value3);
            hash_table_reg4.read(count4, (bit<32>)hash_value4);

            // update count
            count1 = count1 + 1;
            count2 = count2 + 1;
            count3 = count3 + 1;
            count4 = count4 + 1;

            // write back
            hash_table_reg1.write((bit<32>)hash_value1, count1);
            hash_table_reg2.write((bit<32>)hash_value2, count2);
            hash_table_reg3.write((bit<32>)hash_value3, count3);
            hash_table_reg4.write((bit<32>)hash_value4, count4);

            // find min
            min_count = count1;
            if (count2 < min_count) min_count = count2;
            if (count3 < min_count) min_count = count3;
            if (count4 < min_count) min_count = count4;
            // update heavy hitter reg
            hh_count_reg.read(curr_hh_cnt, 0);
            if (curr_hh_cnt < min_count) {
                hh_count_reg.write(0, curr_hh_cnt);
                heavy_hitter_reg.write(0, (bit<32>)hdr.tcp.dstPort);
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
        packet.emit(hdr.tcp);
        packet.emit(hdr.probe);
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
