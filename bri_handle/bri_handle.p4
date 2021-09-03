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

#include <tna.p4>

#define MATCH_COUNT 128
#define STATS_COUNT MATCH_COUNT
#define STATEFUL_COUNT MATCH_COUNT
#define METER_COUNT MATCH_COUNT
#define ACTION_COUNT MATCH_COUNT

#define SELECTOR_COUNT MATCH_COUNT
#define SELECTOR_MAX_GROUP_SIZE 16

#define ATCAM_NUMBER_OF_PARTITIONS 2
#define ALPM_NUMBER_OF_PARTITIONS 2
#define ALPM_SUBTREES_PER_PARTITION 2

struct port_metadata_t {
  bit<1> dummy_field;
}

struct metadata_t {
  port_metadata_t port_md;
  PortId_t port;
}

struct pair {
    bit<32>     first;
    bit<32>     second;
}

header ethernet_h {
  bit<48> dmac;
  bit<48> smac;
  bit<16> etype;
}

header ipv4_h {
  bit<4>  version;
  bit<4>  ihl;
  bit<8>  tos;
  bit<16> total_len;
  bit<16> identification;
  bit<3>  flags;
  bit<13> frag_offset;
  bit<8>  ttl;
  bit<8>  protocol;
  bit<16> cksm;
  bit<32> src;
  bit<32> dst;
}

header ipv6_h {
  bit<4>   version;
  bit<8>   tc;
  bit<20>  flow_label;
  bit<16>  payload_len;
  bit<8>   next_hdr;
  bit<8>   hop_limit;
  bit<128> src;
  bit<128> dst;
}

header data_t {
  bit<16> f16;
  bit<8> f8;
}

struct header_t {
  ethernet_h ethernet;
  ipv4_h ipv4;
  ipv6_h ipv6;
  data_t data;
}

struct pvs_data {
  bit<16> f16;
  bit<8> f8;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser IngPrsr(
        packet_in pkt,
        out header_t hdr,
        out metadata_t md,
        out ingress_intrinsic_metadata_t intr_md) {
  value_set<pvs_data>(4) data_value;
  state start {
    pkt.extract(intr_md);
    md.port_md = port_metadata_unpack<port_metadata_t>(pkt);
    pkt.extract(hdr.ethernet);
    transition select(hdr.ethernet.etype) {
      0x0800 : parse_ipv4;
      0x86DD : parse_ipv6;
      default: accept;
    }
  }
  state parse_ipv4 {
    pkt.extract(hdr.ipv4);
    transition accept;
  }
  state parse_ipv6 {
    pkt.extract(hdr.ipv6);
    pkt.extract(hdr.data);
    transition select(hdr.data.f16, hdr.data.f8) {
        data_value : accept;
        _ : reject;
    }
  }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control IngDprsr(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.cksm = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.tos,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src,
            hdr.ipv4.dst});

         pkt.emit(hdr);
    }
}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser EgrPrsr(
        packet_in pkt,
        out header_t hdr,
        out metadata_t md,
        out egress_intrinsic_metadata_t intr_md) {
  state start {
    transition reject;
  }
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control EgrDprsr(packet_out pkt,
                 inout header_t hdr,
                 in metadata_t md,
                 in egress_intrinsic_metadata_for_deparser_t intr_dprs_md) {
  apply {}
}

control C1(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

   // Create indirect counter
    Counter<bit<32>, bit<32>>(
        STATS_COUNT, CounterType_t.PACKETS_AND_BYTES) cntr;

    // Create indirect meter
    Meter<bit<32>>(METER_COUNT, MeterType_t.BYTES) mtr;

    // Create indirect WRED
    Wred<bit<8>, bit<16>>(500, 0, 255) wred;

    Register<pair, bit<32>>(STATEFUL_COUNT) reg;
    // A simple dual-width 32-bit register action that will increment the two
    // 32-bit sections independently and return the value of one half before the
    // modification.
    RegisterAction<pair, bit<32>, bit<32>>(reg) reg_action = {
        void apply(inout pair value, out bit<32> read_value){
            read_value = value.second;
            value.first = value.first + 1;
            value.second = value.second + 100;
        }
    };

// resources end

// action tables
    Atcam(ATCAM_NUMBER_OF_PARTITIONS) atm;

    Alpm(number_partitions = ALPM_NUMBER_OF_PARTITIONS,
         subtrees_per_partition = ALPM_SUBTREES_PER_PARTITION) algo_lpm;

    Hash<bit<16>>(HashAlgorithm_t.CRC16) sel_hash;
    ActionProfile(ACTION_COUNT) action_profile;
    ActionSelector(action_profile, // action profile
                   sel_hash, // hash extern
                   SelectorMode_t.FAIR, // Selector algorithm
                   SELECTOR_MAX_GROUP_SIZE, // max group size
                   SELECTOR_COUNT // max number of groups
                   ) action_selector;

////// Declaration section end


/////  Actions begin
    action ipsa_modify(bit<32> sa, PortId_t port, bit<32> stat_idx,
                       bit<32> stful_idx) {
      cntr.count(stat_idx);
      reg_action.execute(stful_idx);

      hdr.ipv4.src = sa;
      ig_tm_md.ucast_egress_port = port;
    }

    action ipda_modify(bit<32> da, PortId_t port) {
     hdr.ipv4.dst = da;
      ig_tm_md.ucast_egress_port = port;
    }

    action ipds_modify(bit<8> diffserv, PortId_t port) {
     hdr.ipv4.tos = diffserv;
      ig_tm_md.ucast_egress_port = port;
    }

    action ipttl_modify(bit<8> ttl, PortId_t port) {
     hdr.ipv4.ttl = ttl;
      ig_tm_md.ucast_egress_port = port;
    }

    action metric(bit<32> sa, PortId_t port, bit<32>meter_idx) {
      hdr.ipv4.tos = mtr.execute(meter_idx);
    }

    action mark_wred(bit<16> wred_idx) {
      hdr.ipv4.ttl = wred.execute(hdr.ipv4.tos, wred_idx);
    }

    action drop() {
      ig_dprsr_md.drop_ctl = 0x1; // drop pkt
    }
/////  Actions end


    // Expose cntr and reg
    table match_tbl {
        key = {
            hdr.ipv4.dst : exact;
            hdr.ipv4.src : lpm;
            hdr.ipv4.isValid() : exact;
        }
        actions = {
            ipsa_modify;
            ipda_modify;
            ipds_modify;
            ipttl_modify;
        }
        size = MATCH_COUNT;
   }

    // Expose indirect meters
    table meter_tbl {
        key = {
            hdr.ipv4.dst : exact;
            hdr.ipv4.src : lpm;
            hdr.ipv4.isValid() : exact;
        }
        actions = {
            metric;
            ipttl_modify;
        }

        size = MATCH_COUNT;

        idle_timeout = true;
    }

    // Expose WRED
    table wred_tbl {
        key = {
          hdr.ipv4.src : exact;
        }
        actions = { mark_wred; }
        filters = wred;
        size = MATCH_COUNT;
    }

    // Expose selector and action profile
    table selec_tbl {
        key = {
            hdr.ipv4.dst : exact;
            hdr.ipv4.src : lpm;
            hdr.ipv4.isValid() : exact;

            hdr.ipv4.src : selector;
            hdr.ipv4.dst : selector;
            hdr.ipv4.identification : selector;
            hdr.ipv4.protocol : selector;
        }
        actions = {
            ipda_modify;
            ipds_modify;
            ipttl_modify;
        }

        implementation = action_selector; // selector

        size = MATCH_COUNT; // match_tbl table size

        atcam = atm;

        alpm = algo_lpm;
   }
 
    apply {
        match_tbl.apply();
        meter_tbl.apply();
        wred_tbl.apply();
        selec_tbl.apply();

        // No need for egress processing, skip it and use empty controls for egress.
        ig_tm_md.bypass_egress = 1w1;
    }
}

control Ing(
        inout header_t hdr,
        inout metadata_t md,
        in ingress_intrinsic_metadata_t intr_md,
        in ingress_intrinsic_metadata_from_parser_t intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t intr_dprs_md,
        inout ingress_intrinsic_metadata_for_tm_t intr_tm_md) {

  C1() c1;

  apply {
    intr_tm_md.ucast_egress_port = intr_md.ingress_port;
    intr_tm_md.bypass_egress = 1;
    c1.apply(hdr, md, intr_md, intr_prsr_md, intr_dprs_md, intr_tm_md);
  }
}

control Egr(
        inout header_t hdr,
        inout metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {}
}

Pipeline(IngPrsr(),
         Ing(),
         IngDprsr(),
         EgrPrsr(),
         Egr(),
         EgrDprsr()) pipe;

Switch(pipe) main;

