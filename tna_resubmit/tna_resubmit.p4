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

// PortId_t is 9 bits and will go in a 16 bit container.
// Note that the entire container will be resubmitted. 
// While calculating resubmit data size, total container sizes must be added up
// as partial containers cannot be resubmitted.
// For Tofino1 - max allowed resubmit data size is 8 bytes.
header resubmit_h {
    PortId_t port_id; // 9 bits - uses 16 bit container
    bit<48> _pad2;
}

struct metadata_t { 
    resubmit_h resubmit_data;
}


#include "common/headers.p4"
#include "common/util.p4"


// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    // We cannot use the default parser from utils because we have to parse
    // the resubmit header.
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        pkt.extract(ig_md.resubmit_data);
        transition parse_ethernet;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);

        transition accept;
    }
}


control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action resubmit_no_hdr() {
        ig_dprsr_md.resubmit_type = 1;
    }

    action resubmit_add_hdr(PortId_t add_hdr_port_id) {
        ig_dprsr_md.resubmit_type = 2;
        ig_md.resubmit_data.port_id = add_hdr_port_id;
    }


    table resubmit_ctrl {
        actions = {
            NoAction;
            resubmit_no_hdr;
            resubmit_add_hdr;
        }

        default_action = NoAction;
    }

    action set_output_port(PortId_t port_id) {
        ig_md.resubmit_data.port_id = port_id;
    }

    table output_port {
        actions = {
            set_output_port;
        }
    }

    apply {
        if (ig_intr_md.resubmit_flag == 1) {
            // This is the second pass of the ingress pipeline for this packet.
            hdr.ethernet.dst_addr = 2;
        } else {
            // This is the first pass, write default values
            hdr.ethernet.dst_addr = 1;
            output_port.apply();

            // Each packet can only be resubmitted once. Applying the control
            // table in the first pass is therefore sufficient.
            resubmit_ctrl.apply();
        }

        // Packet will not be resubmitted, prepare it to be send out a port.
        if (ig_dprsr_md.resubmit_type == 0) {
            if (ig_md.resubmit_data.port_id != 0) {
                ig_tm_md.ucast_egress_port = ig_md.resubmit_data.port_id;
            } else {
                ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
            }

            // No need for egress processing, skip it and use empty controls for egress.
            ig_tm_md.bypass_egress = 1w1;
        }
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(packet_out pkt,
                              inout header_t hdr,
                              in metadata_t ig_md,
                              in ingress_intrinsic_metadata_for_deparser_t
                                ig_intr_dprsr_md
                              ) {

    Resubmit() resubmit;

    apply {
        if (ig_intr_dprsr_md.resubmit_type == 1) {
            resubmit.emit();
        } else if (ig_intr_dprsr_md.resubmit_type == 2) {
            resubmit.emit(ig_md.resubmit_data);
        }

        pkt.emit(hdr);
    }
}

Pipeline(SwitchIngressParser(),
       SwitchIngress(),
       SwitchIngressDeparser(),
       EmptyEgressParser(),
       EmptyEgress(),
       EmptyEgressDeparser()) pipe;

Switch(pipe) main;
