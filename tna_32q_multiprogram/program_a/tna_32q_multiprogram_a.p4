/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2019-present Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks, Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.  Dissemination of
 * this information or reproduction of this material is strictly forbidden unless
 * prior written permission is obtained from Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a written
 * agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "../common/headers.p4"
#include "../common/util.p4"
#include "custom_headers.p4"

#define FORWARD_TABLE_SIZE 1024
struct metadata_a_t {}

typedef bit<2> pkt_color_t;
const pkt_color_t SWITCH_METER_COLOR_GREEN = 0;
const pkt_color_t SWITCH_METER_COLOR_YELLOW = 1;
const pkt_color_t SWITCH_METER_COLOR_RED = 2;

struct qos_metadata_a_t {
    pkt_color_t color;
}
typedef bit<16> meter_index_t;


// ---------------------------------------------------------------------------
// Ingress parser for program a
// ---------------------------------------------------------------------------
parser SwitchIngressParser_a(
        packet_in pkt,
        out custom_header_t hdr,
        out metadata_a_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Egress parser for program a
// ---------------------------------------------------------------------------
parser SwitchEgressParser_a(
        packet_in pkt,
        out custom_header_t hdr,
        out metadata_a_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition parse_custom_metadata;
    }

    state parse_custom_metadata {
        pkt.extract(hdr.custom_metadata);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser for program a
// ---------------------------------------------------------------------------
control SwitchIngressDeparser_a(
        packet_out pkt,
        inout custom_header_t hdr,
        in metadata_a_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update(
                {hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.diffserv,
                 hdr.ipv4.total_len,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.frag_offset,
                 hdr.ipv4.ttl,
                 hdr.ipv4.protocol,
                 hdr.ipv4.src_addr,
                 hdr.ipv4.dst_addr});

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.custom_metadata);
    }
}


// ---------------------------------------------------------------------------
// Egress Deparser for program a
// ---------------------------------------------------------------------------
control SwitchEgressDeparser_a(packet_out pkt,
                              inout custom_header_t hdr,
                              in metadata_a_t eg_md,
                              in egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md) {
    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update(
                {hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.diffserv,
                 hdr.ipv4.total_len,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.frag_offset,
                 hdr.ipv4.ttl,
                 hdr.ipv4.protocol,
                 hdr.ipv4.src_addr,
                 hdr.ipv4.dst_addr});

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan_tag);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}


// ---------------------------------------------------------------------------
// P4 program a
// Packet travels through different table types (exm, tcam), each of which
// decrement the ipv4 ttl on a table hit.
// Counters and meters are attached to few tables
// ---------------------------------------------------------------------------
control SwitchIngress_a(
        inout custom_header_t hdr,
        inout metadata_a_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    qos_metadata_a_t qos_md;
    Meter<meter_index_t>(512, MeterType_t.BYTES) meter;
    Counter<bit<32>, PortId_t>(
        512, CounterType_t.PACKETS) storm_control_stats;

    action hit() {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action miss() {
        ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    table forward {
        key = {
            hdr.ethernet.dst_addr : exact;
            hdr.ipv4.ttl : exact;
        }

        actions = {
            hit;
            miss;
        }

        const default_action = miss;
        size = FORWARD_TABLE_SIZE;
    }

    action encap_custom_metadata(bit<16> tag) {
        hdr.custom_metadata.setValid();
        hdr.custom_metadata.custom_tag = tag;
    }

    table encap_custom_metadata_hdr {
        key = {
            hdr.ethernet.isValid() : exact;
        }

        actions = {
            encap_custom_metadata;
        }
    }

    action modify_eg_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table pinning {
        key = {
            ig_intr_md.ingress_port : exact;
        }

        actions = {
            NoAction;
            modify_eg_port;
        }

        const default_action = NoAction;
        size = 512;
    }

    action set_color(meter_index_t index) {
        qos_md.color = (bit<2>) meter.execute(index);
    }

    table storm_control {
        key = {
            ig_intr_md.ingress_port : exact;
        }

        actions = {
            NoAction;
            set_color;
        }

        const default_action = NoAction;
        size = 512;
    }

    action count() {
        storm_control_stats.count(ig_intr_md.ingress_port);
    }

    table stats {
        key = {
            qos_md.color : exact;
            ig_intr_md.ingress_port : exact;
        }

        actions = {
            NoAction;
            count;
        }
    }


    apply {
        qos_md.color = 0;
        storm_control.apply();
        stats.apply();
        forward.apply();
        encap_custom_metadata_hdr.apply();
        pinning.apply();
    }
}

control SwitchEgress_a(
    inout custom_header_t hdr,
    inout metadata_a_t eg_md,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprs,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) direct_counter;

    action hit() {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.custom_metadata.custom_tag = hdr.custom_metadata.custom_tag + 1;
        direct_counter.count();
    }

    action miss() {
        eg_intr_md_for_dprs.drop_ctl = 0x1; // Drop packet.
    }

    table forward {
        key = {
            hdr.ipv4.dst_addr : ternary;
            hdr.ipv4.ttl : ternary;
            hdr.custom_metadata.custom_tag: ternary;
        }

        actions = {
            hit;
            @defaultonly miss;
        }

        const default_action = miss;
        size = FORWARD_TABLE_SIZE;
        counters = direct_counter;
    }

    action decap_custom_metadata() {
        hdr.custom_metadata.setInvalid();
    }

    table decap_custom_metadata_hdr {
        key = {
            hdr.custom_metadata.isValid() : exact;
        }

        actions = {
            decap_custom_metadata;
        }
    }

    apply {
        forward.apply();
        decap_custom_metadata_hdr.apply();
    }

}

// Packet comes into ingress program_a which adds an extra custom_metadata_h
// header to the packet. The packet travels to egress program_b, then to
// ingress program_b and finally to egress program_a. The custom_metadata_h
// header is striped off by egress program_b. Value of custom_tag is modified
// as the packet travels.

Pipeline(SwitchIngressParser_a(),
         SwitchIngress_a(),
         SwitchIngressDeparser_a(),
         SwitchEgressParser_a(),
         SwitchEgress_a(),
         SwitchEgressDeparser_a()) profile_a;

Switch(profile_a) main;
