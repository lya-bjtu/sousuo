#include "tofino/intrinsic_metadata.p4"

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type vlan_tag_t {
    fields {
        pri : 3;
        cfi : 1;
        vlan_id : 12;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type ipv6_t {
    fields {
        version : 4;
        trafficClass : 8;
        flowLabel : 20;
        payloadLen : 16;
        nextHdr : 8;
        hopLimit : 8;
        srcAddr : 128;
        dstAddr : 128;
    }
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 3;
        ecn : 3;
        ctrl : 6;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        hdr_length : 16;
        checksum : 16;
    }
}

parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        0x8100 : parse_vlan_tag;
        0x800 : parse_ipv4;
        0x86dd : parse_ipv6;
        default: ingress;
    }
}




header ipv4_t ipv4;
header ipv6_t ipv6;

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.fragOffset, latest.protocol) {
        6 : parse_tcp;
        17 : parse_udp;
        default: ingress;
    }
}

parser parse_ipv6 {
    extract(ipv6);
    return select(latest.nextHdr) {
        6 : parse_tcp;
        17 : parse_udp;
        default : ingress;
    }
}

header vlan_tag_t vlan_tag;

parser parse_vlan_tag {
    extract(vlan_tag);
    return select(latest.etherType) {
        0x800 : parse_ipv4;
        default : ingress;
    }
}

header tcp_t tcp;

parser parse_tcp {
    extract(tcp);
    return ingress;
}

header udp_t udp;

parser parse_udp {
    extract(udp);
    return ingress;
}


field_list ipv4_field_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_chksum_calc {
    input {
        ipv4_field_list;
    }
    algorithm : csum16;
    output_width: 16;
}

calculated_field ipv4.hdrChecksum {
    update ipv4_chksum_calc;
}


field_list meter_field_list {
    ipv4.protocol;
}

field_list_calculation meter_hash_calc {
    input { meter_field_list; }
    algorithm : identity;
    output_width : 8;
}

field_list cnt_field_list {
    ipv4.version;
}

field_list_calculation cnt_hash_calc {
    input { cnt_field_list; }
    algorithm : identity;
    output_width : 4;
}


action nop() {
}


meter meter_0 {
    type : bytes;
    static : simple_meter;
    instance_count : 256;
}

meter meter_1 {
    type : bytes;
    static : meter_drop;
    instance_count : 256;
}

counter counter_0 {
    type : packets;
    static : simple_counter;
    instance_count : 16;
}

counter colorCntr {
    type : packets;
    static : color_match;
    instance_count : 1024;
}


action meter_action (egress_port, srcmac, dstmac) {
    add(ipv4.ttl, ipv4.ttl, -1);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_port);
    modify_field(ethernet.srcAddr, srcmac);
    modify_field(ethernet.dstAddr, dstmac);
    execute_meter_from_hash(meter_0, meter_hash_calc, ipv4.diffserv);
}

action meter_or_action(egress_port, idx){
    execute_meter_with_or(meter_1, idx, ig_intr_md_for_tm.drop_ctl);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_port);
}


action cnt_action () {
    count_from_hash(counter_0, cnt_hash_calc);
}

action count_color(color_idx) {
    count(colorCntr, color_idx);
}


table simple_meter {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        nop;
        meter_action;
    }
    size : 1024;
}

table simple_counter {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        nop;
        cnt_action;
    }
    size : 1024;
}

table color_match {
    reads {
        ethernet.dstAddr: exact;
        ipv4.diffserv: exact;
    }
    actions {
        count_color;
        nop;
    }
    size : 256;
}

table meter_drop {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        nop;
        meter_or_action;
    }
    size : 1024;
}
       



control ingress {
    if (valid(tcp)){
        if (tcp.srcPort == 555){
            apply(meter_drop);
        } else{
            apply(simple_meter);
            apply(simple_counter);
            apply(color_match);
        }
    }
}

control egress {

}
