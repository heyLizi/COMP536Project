/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TCP_PROTO = 0x06

const bit<16> CMS_TABLE_NUM = 4
const bit<16> CMS_TABLE_WIDTH = 32

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

header hh_detection_t {
    macAddr_t srcAddr;
    macAddr_t dstAddr;
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<32>   hh_count;
    time_t    start_time;
    time_t    end_time;
}

struct metadata {
   
}

struct headers {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    tcp_t            tcp;
    hh_detection_t   hh_detection;
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

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition parse_hh_detection;
    }
    
    state parse_hh_detection {
        packet.extract(hdr.hh_detection);
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

    register<bit<32>>(CMS_TABLE_WIDTH) hash_table_reg1;
    register<bit<32>>(CMS_TABLE_WIDTH) hash_table_reg2;
    register<bit<32>>(CMS_TABLE_WIDTH) hash_table_reg3;
    register<bit<32>>(CMS_TABLE_WIDTH) hash_table_reg4;

    register<bit<32>>(5) heavy_hitter_reg;
    register<bit<32>>(1) time_reg;

    bit<16> hash_value1;
    bit<32> count1;
    bit<16> hash_value2;
    bit<32> count2;
    bit<16> hash_value3;
    bit<32> count3;
    bit<16> hash_value4;
    bit<32> count4;
    bit<32> min_count;

    macAddr_t hh_srcAddr;
    macAddr_t hh_dstAddr;
    bit<16>   hh_srcPort;
    bit<16>   hh_dstPort;
    bit<32>   hh_count;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    action calc_and_save_hash_values() {
        hash(hash_value1,
        HashAlgorithm.crc16,
        0,
        { hdr.ipv4.srcAddr,
          hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort
        },
        CMS_TABLE_WIDTH);

        hash(hash_value2,
        HashAlgorithm.csum16,
        0,
        { hdr.ipv4.srcAddr,
          hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol
        },
        CMS_TABLE_WIDTH);

        hash(hash_value3,
        HashAlgorithm.crc16,
        0,
        { hdr.ipv4.srcAddr,
          hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol,
          hdr.ipv4.totalLen
        },
        CMS_TABLE_WIDTH);

        hash(hash_value4,
        HashAlgorithm.csum16,
        0,
        { hdr.ipv4.srcAddr,
          hdr.ipv4.dstAddr,
          hdr.tcp.srcPort,
          hdr.tcp.dstPort,
          hdr.ipv4.protocol,
          hdr.ipv4.totalLen,
          hdr.ipv4.version
        },
        CMS_TABLE_WIDTH);

        hash_table_reg1.read(count1, hash_value1);
        hash_table_reg2.read(count2, hash_value2);
        hash_table_reg3.read(count3, hash_value3);
        hash_table_reg4.read(count4, hash_value4);

        count1 = count1 + 1;
        count2 = count2 + 1;
        count3 = count3 + 1;
        count4 = count4 + 1;

        hash_table_reg1.write(hash_value1, count1);
        hash_table_reg2.write(hash_value2, count2);
        hash_table_reg3.write(hash_value3, count3);
        hash_table_reg4.write(hash_value4, count4);
    }

    action find_min_value() {
        min_count = count1;
        if (count2 < in_count) {
            min_count =count2;
        }
        if (count3 < min_count) {
           min_count = count3;
        }
        if (count4 < min_count) {
            min_count = count4;
        }
    }

    action read_and_update_heavy_hitter() {
        heavy_hitter_reg.read(hh_srcAddr, 0);
        heavy_hitter_reg.read(hh_dstAddr, 1);
        heavy_hitter_reg.read(hh_srcPort, 2);
        heavy_hitter_reg.read(hh_dstPort, 3);
        heavy_hitter_reg.read(hh_count, 4);

        if (hh_count < min_count) {
            hh_srcAddr = hdr.ipv4.srcAddr;
            hh_dstAddr = hdr.ipv4.dstAddr;
            hh_srcPort = hdr.tcp.srcPort;
            hh_dstAddr = hdr.tcp.dstPort;
            hh_count = min_count;

            heavy_hitter_reg.write(0, hh_srcAddr);
            heavy_hitter_reg.write(1, hh_dstAddr);
            heavy_hitter_reg.write(2, hh_srcPort);
            heavy_hitter_reg.write(3, hh_dstPort);
            heavy_hitter_reg.write(4, hh_count);
        }
    }

    action encapsulate_hh_header() {
        time
        time_t cur_time;
        time_reg.read(meta.detection_time_metadata.last_detection_time, 0);
        
        meta.heavy_hitter_metadata.time = standard_metadata.ingress_global_timestamp;
        heavy_hitter_reg.write(5, meta.heavy_hitter_metadata.time);
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
    
    table hash_vals {
        actions = {
            calc_and_save_hash_values;
        }
    }

    table min_val {
        actions = {
            find_min_value;   
        }
    }

    table heavy_hitter {
        actions = {
            read_and_update_heavy_hitter;
        }
    }

    table heavy_hitter_detection {
        actions = {
            encapsulate_hh_header;
        }
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            if (head.hh_detection.flag == 0) { 
                hash_vals.apply();
                min_val.apply();
                heavy_hitter.apply();
            }
            else {
                heavy_hitter_detection.apply();
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
    
    register<bit<32>>(MAX_PORTS) byte_cnt_reg;

    action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_swid(bit<7> swid) {
        hdr.probe_data[0].swid = swid;
    }

    table swid {
        actions = {
            set_swid;
            NoAction;
        }
        default_action = NoAction();
    }

    table send_frame {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            rewrite_mac;
            drop;
        }
        size = 256;
    }

    apply {
        bit<32> byte_cnt = 0;
        
        byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
        if (hdr.ipv4.isValid()) {
            // increment byte cnt for this packet's port
            byte_cnt = byte_cnt + standard_metadata.packet_length;
        }
        byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, byte_cnt);
        
        send_frame.apply();

        if (hdr.probe.isValid()) {
            // fill out probe fields
            hdr.probe_data.push_front(1);
            hdr.probe_data[0].setValid();
            if (hdr.probe.hop_cnt == 1) {
                hdr.probe_data[0].bos = 1;
            }
            else {
                hdr.probe_data[0].bos = 0;
            }
            // set switch ID field
            swid.apply();
            hdr.probe_data[0].port = (bit<8>)standard_metadata.egress_port;
            hdr.probe_data[0].byte_cnt = byte_cnt;
        }
    }
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
        packet.emit(hdr.probe_data);
        packet.emit(hdr.probe_fwd);
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
