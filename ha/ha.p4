/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#if __TARGET_TOFINO__ == 2
#include "tofino2/intrinsic_metadata.p4"
#else
#include "tofino/intrinsic_metadata.p4"
#endif

/* Sample P4 program */
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type vlan_tag_t {
    fields {
        pri     : 3;
        cfi     : 1;
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

#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17

header ipv4_t ipv4;
header ipv6_t ipv6;

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.fragOffset, latest.protocol) {
        IP_PROTOCOLS_TCP : parse_tcp;
        IP_PROTOCOLS_UDP : parse_udp;
        default: ingress;
    }
}

parser parse_ipv6 {
    extract(ipv6);
    return select(latest.nextHdr) {
        IP_PROTOCOLS_TCP : parse_tcp;
        IP_PROTOCOLS_UDP : parse_udp;
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

action set_md(level2_exclusion_id, qid, cos, rid, level1_mcast_hash) {
    modify_field(ig_intr_md_for_tm.level2_exclusion_id, level2_exclusion_id);
    modify_field(ig_intr_md_for_tm.qid, qid);
    modify_field(ig_intr_md_for_tm.ingress_cos, cos);
    modify_field(ig_intr_md_for_tm.rid, rid);
    modify_field(ig_intr_md_for_tm.level1_mcast_hash, level1_mcast_hash);
}

@pragma phase0 1
table port_tbl {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        set_md;
    }
    default_action: set_md(0, 0, 0, 0, 0);
    size : 288;
}

action set_egr_port(val) {
   modify_field(ig_intr_md_for_tm.ucast_egress_port, val);
}

action tcam_range_action(val, value_0, value_1, value_2) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, val);
    modify_field(vlan_tag.vlan_id, value_0);
    modify_field(vlan_tag.pri, value_1);
    modify_field(ipv4.ttl, value_2);
}

action drop_packet() {
   drop();
}

action nop() {
}

@pragma stage 1
table set_eg {
    reads {
        ig_intr_md_for_tm.level2_exclusion_id : exact;
        ig_intr_md_for_tm.qid : exact;
        ig_intr_md_for_tm.ingress_cos : exact;
        ig_intr_md_for_tm.rid : exact;
        ig_intr_md_for_tm.level1_mcast_hash : exact;
    }
    actions {
        set_egr_port;
        drop_packet;
    }
    size : 288;
}

action hash_action_ha(value_0, value_1, value_2) {
    modify_field(vlan_tag.vlan_id, value_0);
    modify_field(vlan_tag.pri, value_1);
    modify_field(ipv4.ttl, value_2);
}

@pragma use_hash_action 1
@pragma stage 3
table hash_action_ha_exm {
    reads {
        ipv4.ttl : exact;
        vlan_tag.pri : exact;
        ipv4 : valid;
        ethernet : valid;
    }
    actions {
        hash_action_ha;
    }
    default_action : hash_action_ha(1947, 5, 45);
    size : 8192;
}

@pragma command_line --no-dead-code-elimination
@pragma entries_with_ranges 1
@pragma immediate 1
@pragma stage 4
table tcam_range {
    reads {
        ipv4.dstAddr : ternary;
        tcp.dstPort : range;
        ipv4.ttl : range;
    }
    actions {
      tcam_range_action;
      nop;
      //set_egr_port;
    }
    size : 1024;
}

/* Main control flow */
control ingress {
    if (0 == ig_intr_md.resubmit_flag) {
        apply(port_tbl);
    }
    apply(set_eg);
    /* Hash-action tables are always executed. Using gateway condition
       of tcp-srcport to prevent all tests from hitting this condition
    */
    if (tcp.srcPort == 9000) {
        apply(hash_action_ha_exm);
    }
    apply(tcam_range);
}

control egress {
}
