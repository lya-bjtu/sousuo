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

// This is P4 sample source for default entry

#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include <tofino/stateful_alu_blackbox.p4>

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

/* Allocate a 32-bit container for ipv4 identification for keyless table case.
   This will force compiler to publish the keyless action info and
   bf-drivers will need to program it.
*/
@pragma pa_container_size ingress ipv4.identification 32
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

header_type routing_metadata_t {
    fields {
        drop: 1;
    }
}

metadata routing_metadata_t /*metadata*/ routing_metadata;

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

meter meter_1 {
    type : bytes;
    direct : meter_tbl_direct;
    result : ipv4.diffserv;
}

@pragma meter_pre_color_aware_per_flow_enable 1
meter meter_2 {
    type : bytes;
    static : meter_tbl_color_aware_indirect;
    result : ipv4.diffserv;
    pre_color : ipv4.diffserv;
    instance_count : 500;
}

action act_1(value_0, value_1, value_2) {
    modify_field(vlan_tag.vlan_id, value_0);
    modify_field(vlan_tag.pri, value_1);
    modify_field(ipv4.ttl, value_2);
}

action set_egr(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}

action keyless_action(value_0, value_1, value_2, value_3) {
    modify_field(vlan_tag.vlan_id, value_0);
    modify_field(vlan_tag.pri, value_1);
    modify_field(ipv4.ttl, value_2);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, value_3);
}

action hop(ttl, egress_port) {
    add_to_field(ttl, -1);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_port);
}

action next_hop_ipv4(egress_port ,srcmac, dstmac) {
    hop(ipv4.ttl, egress_port);
    modify_field(ethernet.srcAddr, srcmac);
    modify_field(ethernet.dstAddr, dstmac);
}

action meter_action_color_aware (egress_port, srcmac, dstmac, idx) {
    next_hop_ipv4(egress_port, srcmac, dstmac);
    execute_meter(meter_2, idx, ipv4.diffserv, ipv4.diffserv);
}

action nop() {
}

action _drop() {
    drop();
}

counter CounterA {
    type : packets;
    instance_count : 1024;
}

action _CounterAAction1(idx) {
    count(CounterA, idx);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, 3);
}

action _CounterAAction2() {
    count(CounterA, 37);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, 3);
}

table _CounterATable {
    reads {
         ethernet.dstAddr : exact;
    }
    actions {
        _CounterAAction1; _CounterAAction2;
    }
    size: 512;
}

table ipv4_routing_select {
    reads {
        ipv4.dstAddr: lpm;
    }
    action_profile : ecmp_action_profile;
    size : 512;
}

field_list ecmp_hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.identification;
    ipv4.protocol;
}

field_list_calculation ecmp_hash {
    input {
        ecmp_hash_fields;
    }
#if defined(BMV2TOFINO)
    algorithm : xxh64;
#else
    algorithm : random;
#endif
    output_width : 64;
}

action_profile ecmp_action_profile {
    actions {
        nhop_set;
        nop;
    }
    size : 1024;
    // optional
    dynamic_action_selection : ecmp_selector;
}

action_selector ecmp_selector {
    selection_key : ecmp_hash; // take a field_list_calculation only
    // optional
    selection_mode : resilient; // ?resilient? or ?non-resilient?
}

action nhop_set(port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
}

action egress_port(egress_port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_port);
}

action keyless_set_egr() {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, 0);
}

action custom_action_3(egress_port, dstAddr, dstIp)
{
    modify_field(ipv4.dstAddr, dstIp);
    modify_field(ethernet.dstAddr, dstAddr);
    hop(ipv4.ttl, egress_port);
}

action custom_action_2(ttl)
{
    modify_field(ipv4.ttl, ttl);
}

action_profile custom_action_3_profile {
    actions {
        nop;
        custom_action_3;
        egress_port;
    }
    size : 1024;
}

action_profile custom_action_2_profile {
    actions {
        nop;
        custom_action_2;
    }
    size : 1024;
}

table exm_indr {
    reads {
        ipv4.dstAddr : exact;
        ipv4.srcAddr : exact;
        tcp.srcPort : exact;
    }

    action_profile : custom_action_3_profile;

    size : 256;
}

table tcam_indr {
    reads {
        ipv4.dstAddr : ternary;
        ipv4.srcAddr : ternary;
        tcp.srcPort : ternary;
    }

    action_profile : custom_action_2_profile;

    size : 256;
}

table exm_dir {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {
        act_1; set_egr; nop;
    }
}

table tcam_dir {
    reads {
        ethernet.dstAddr : ternary;
        ethernet.srcAddr : ternary;
    }
    actions {
        act_1; set_egr; nop;
    }
}

table keyless_table {
    actions {
        keyless_action;
    }
    default_action: keyless_action(1901, 3, 32, 56);
}

table meter_tbl_direct {
    reads {
        ipv4.dstAddr : exact;
        ipv4.srcAddr : exact;
    }
    actions {
        nop;
        next_hop_ipv4;
    }
}

table meter_tbl_color_aware_indirect {
    reads {
        ipv4.dstAddr : exact;
        ipv4.srcAddr : exact;
    }
    actions {
        nop;
        meter_action_color_aware;
    }
}

action prepare_keyless(egr_port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egr_port);
    modify_field(tcp.srcPort, 9006);
}

table set_egr_exm {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        prepare_keyless;
        nop;
    }
    default_action : prepare_keyless;
}

table set_egr_tcam {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        prepare_keyless;
        nop;
    }
    default_action : prepare_keyless(1);
}

@pragma alpm 1
table set_egr_alpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        prepare_keyless;
        nop;
    }
    default_action : prepare_keyless(2);
}

@pragma clpm_prefix ipv4.dstAddr
@pragma clpm_prefix_length 1 7 512
@pragma clpm_prefix_length 8 1024
@pragma clpm_prefix_length 9 32 512
table set_egr_clpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        prepare_keyless;
        nop;
    }
    default_action : prepare_keyless(3);
    size : 2048;
}

action set_ipv4_dst(x) {
    modify_field(ipv4.dstAddr, x);
}

table keyless_direct {
    actions {
        set_ipv4_dst;
        nop;
    }
    default_action : set_ipv4_dst(127);
}

table keyless_direct_2 {
    actions {
        set_ipv4_dst;
    }
    default_action : nop;
}

action_profile indirect_action_profile {
    actions {
        egress_port;
    }
    size : 1;
}
table keyless_indirect {
    action_profile : indirect_action_profile;
}

counter keyless_cntr {
   type : packets;
   static : keyless_indirect_resources;
   instance_count : 512;
}

register keyless_reg {
    width  : 32;
    instance_count: 512;
}

blackbox stateful_alu r_alu {
    reg: keyless_reg;
    initial_register_lo_value: 1;
    update_lo_1_value: register_lo + 5;
}

action keyless_counts(stat_idx, stful_idx) {
    count(keyless_cntr, stat_idx);
    r_alu.execute_stateful_alu(stful_idx);
}

table keyless_indirect_resources {
    actions {
        keyless_counts;
    }
    default_action : keyless_counts(1, 2);
}

table pure_keyless {
    actions {
        keyless_set_egr;
    }
    default_action: keyless_set_egr();
}

control ingress {
    if (tcp.srcPort == 9001) {
        apply(keyless_table);
        apply(exm_dir);
        apply(exm_indr);
        apply(_CounterATable);
        apply(meter_tbl_direct);
        apply(meter_tbl_color_aware_indirect);
        apply(ipv4_routing_select);
        apply(tcam_dir);
        apply(tcam_indr);
        if (ig_intr_md_for_tm.ucast_egress_port != 0) {
            apply(pure_keyless);
        }
    } else if (tcp.srcPort == 9002) {
        apply(set_egr_exm);
    } else if (tcp.srcPort == 9003) {
        apply(set_egr_tcam);
    } else if (tcp.srcPort == 9004) {
        apply(set_egr_alpm);
    } else if (tcp.srcPort == 9005) {
        apply(set_egr_clpm);
    }

    if (tcp.srcPort == 9006) {
        apply(keyless_direct);
        apply(keyless_direct_2);
        apply(keyless_indirect_resources);
        if (ig_intr_md_for_tm.ucast_egress_port == 0) {
            apply(keyless_indirect);
        }
    }
}

control egress {
}

