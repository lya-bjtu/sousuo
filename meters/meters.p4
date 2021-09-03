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

#include "tofino/intrinsic_metadata.p4"
#include "tofino/constants.p4"
#include "tofino/lpf_blackbox.p4"

/* Sample P4 program */
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
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


header ethernet_t ethernet;
header ipv4_t ipv4;

parser start {
    extract(ethernet);
    extract(ipv4);
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

@pragma calculated_field_update_location ingress
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

header_type metadata_t {
    fields {
        run_meter_tbl : 1;
        run_meter_tbl_direct : 1;
        run_meter_tbl_color_aware_indirect : 1;
        run_match_tbl_lpf : 1;
        run_match_tbl_tcam_lpf : 1;
        run_match_tbl_lpf_direct : 1;
        run_match_tbl_tcam_lpf_direct : 1;
        run_ts : 1;
        run_color_match : 1;
        idx : 32;
    }
}
metadata metadata_t md;

action nop() {
}


meter meter_0 {
    type : bytes;
    static : meter_tbl;
    result : ipv4.diffserv;
    instance_count : 500;
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

blackbox lpf meter_lpf {
    filter_input : ipv4.srcAddr;
    instance_count : 500;
}


blackbox lpf meter_lpf_tcam {
   filter_input : ipv4.srcAddr;
   static : match_tbl_tcam_lpf;
   instance_count : 500;
}

blackbox lpf meter_lpf_direct {
    filter_input : ipv4.srcAddr;
    direct : match_tbl_lpf_direct;
}

blackbox lpf meter_lpf_tcam_direct {
    filter_input : ipv4.srcAddr;
    direct : match_tbl_tcam_lpf_direct;
}

action meter_action(idx) {
    modify_field(md.idx, idx);
    execute_meter(meter_0, idx, ipv4.diffserv);
}

action meter_action_color_aware(idx) {
    execute_meter(meter_2, idx, ipv4.diffserv, ipv4.diffserv);
}

action meter_action_color_unaware(idx) {
    execute_meter(meter_2, idx, ipv4.diffserv);
}

action count_color(color_idx) {
    count(colorCntr, color_idx);
}

action lpf_indirect(lpf_idx) {
    meter_lpf.execute(ipv4.srcAddr, lpf_idx);
}

action lpf_tcam_indirect(lpf_idx) {
    meter_lpf_tcam.execute(ipv4.srcAddr, lpf_idx);
}

action direct_lpf() {
    meter_lpf_direct.execute(ipv4.srcAddr);
}

action lpf_direct_tcam() {
    meter_lpf_tcam_direct.execute(ipv4.srcAddr);
}

counter colorCntr {
    type : packets;
    static : color_match;
    instance_count : 100;
}

@pragma stage 1
table ts {
    actions {
        write_ts;
    }
    default_action : write_ts();
}
action write_ts() {
    modify_field(ethernet.dstAddr, ig_intr_md_from_parser_aux.ingress_global_tstamp);
}

@pragma stage 1
table meter_tbl {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        meter_action;
    }
}

@pragma stage 1
table meter_tbl_direct {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        nop;
    }
}

@pragma stage 2
table meter_tbl_color_aware_indirect {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        meter_action_color_aware;
        meter_action_color_unaware;
    }
}


@pragma stage 4
table match_tbl_lpf {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        lpf_indirect;
    }
    default_action : nop();
}

@pragma stage 4
table match_tbl_tcam_lpf {
    reads {
        ipv4.dstAddr : ternary;
    }
    actions {
        lpf_tcam_indirect;
    }
    default_action : nop();
}


@pragma stage 4
table match_tbl_lpf_direct {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        direct_lpf;
    }
    default_action : nop();
}

@pragma stage 4
table match_tbl_tcam_lpf_direct {
    reads {
        ipv4.dstAddr : ternary;
    }
    actions {
        lpf_direct_tcam;
    }
    default_action : nop();
}

@pragma stage 5
table color_match {
    reads {
        md.idx : exact;
        ipv4.diffserv: exact;
    }
    actions {
        count_color;
    }
    size : 256;
}

@pragma stage 0
table test_select {
  actions {
     ExmMeterIndirect;  /* meter_tbl */
     ExmMeterDirect;    /* meter_tbl_direct */
     ExmMeterColorAwareIndirect; /* meter_tbl_color_aware_indirect */
     MeterOmnet; /* meter_tbl, color_match */
     GetTimeForLPFTest;
     ExmLpfIndirect; /* match_tbl_lpf */
     TCAMLpfIndirect; /* match_tbl_tcam_lpf */
     ExmLpfDirect; /* match_tbl_lpf_direct */
     TCAMLpfDirect; /* match_tbl_tcam_lpf_direct */
  }
  default_action : ExmMeterIndirect;
}
action ExmMeterIndirect() {
    modify_field(md.run_meter_tbl,                      1);
    modify_field(md.run_meter_tbl_direct,               0);
    modify_field(md.run_meter_tbl_color_aware_indirect, 0);
    modify_field(md.run_match_tbl_lpf,                  0);
    modify_field(md.run_match_tbl_tcam_lpf,             0);
    modify_field(md.run_match_tbl_lpf_direct,           0);
    modify_field(md.run_match_tbl_tcam_lpf_direct,      0);
    modify_field(md.run_ts,                             0);
    modify_field(md.run_color_match,                    0);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, ig_intr_md.ingress_port);
    bypass_egress();
}
action ExmMeterDirect() {
    modify_field(md.run_meter_tbl,                      0);
    modify_field(md.run_meter_tbl_direct,               1);
    modify_field(md.run_meter_tbl_color_aware_indirect, 0);
    modify_field(md.run_match_tbl_lpf,                  0);
    modify_field(md.run_match_tbl_tcam_lpf,             0);
    modify_field(md.run_match_tbl_lpf_direct,           0);
    modify_field(md.run_match_tbl_tcam_lpf_direct,      0);
    modify_field(md.run_ts,                             0);
    modify_field(md.run_color_match,                    0);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, ig_intr_md.ingress_port);
    bypass_egress();
}
action ExmMeterColorAwareIndirect() {
    modify_field(md.run_meter_tbl,                      0);
    modify_field(md.run_meter_tbl_direct,               0);
    modify_field(md.run_meter_tbl_color_aware_indirect, 1);
    modify_field(md.run_match_tbl_lpf,                  0);
    modify_field(md.run_match_tbl_tcam_lpf,             0);
    modify_field(md.run_match_tbl_lpf_direct,           0);
    modify_field(md.run_match_tbl_tcam_lpf_direct,      0);
    modify_field(md.run_ts,                             0);
    modify_field(md.run_color_match,                    0);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, ig_intr_md.ingress_port);
    bypass_egress();
}
action MeterOmnet() {
    modify_field(md.run_meter_tbl,                      1);
    modify_field(md.run_meter_tbl_direct,               0);
    modify_field(md.run_meter_tbl_color_aware_indirect, 0);
    modify_field(md.run_match_tbl_lpf,                  0);
    modify_field(md.run_match_tbl_tcam_lpf,             0);
    modify_field(md.run_match_tbl_lpf_direct,           0);
    modify_field(md.run_match_tbl_tcam_lpf_direct,      0);
    modify_field(md.run_ts,                             0);
    modify_field(md.run_color_match,                    1);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, ig_intr_md.ingress_port);
    bypass_egress();
}
action GetTimeForLPFTest() {
    modify_field(md.run_meter_tbl,                      0);
    modify_field(md.run_meter_tbl_direct,               0);
    modify_field(md.run_meter_tbl_color_aware_indirect, 0);
    modify_field(md.run_match_tbl_lpf,                  0);
    modify_field(md.run_match_tbl_tcam_lpf,             0);
    modify_field(md.run_match_tbl_lpf_direct,           0);
    modify_field(md.run_match_tbl_tcam_lpf_direct,      0);
    modify_field(md.run_ts,                             1);
    modify_field(md.run_color_match,                    0);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, ig_intr_md.ingress_port);
    bypass_egress();
}
action ExmLpfIndirect() {
    modify_field(md.run_meter_tbl,                      0);
    modify_field(md.run_meter_tbl_direct,               0);
    modify_field(md.run_meter_tbl_color_aware_indirect, 0);
    modify_field(md.run_match_tbl_lpf,                  1);
    modify_field(md.run_match_tbl_tcam_lpf,             0);
    modify_field(md.run_match_tbl_lpf_direct,           0);
    modify_field(md.run_match_tbl_tcam_lpf_direct,      0);
    modify_field(md.run_ts,                             0);
    modify_field(md.run_color_match,                    0);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, ig_intr_md.ingress_port);
    bypass_egress();
}
action TCAMLpfIndirect() {
    modify_field(md.run_meter_tbl,                      0);
    modify_field(md.run_meter_tbl_direct,               0);
    modify_field(md.run_meter_tbl_color_aware_indirect, 0);
    modify_field(md.run_match_tbl_lpf,                  0);
    modify_field(md.run_match_tbl_tcam_lpf,             1);
    modify_field(md.run_match_tbl_lpf_direct,           0);
    modify_field(md.run_match_tbl_tcam_lpf_direct,      0);
    modify_field(md.run_ts,                             0);
    modify_field(md.run_color_match,                    0);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, ig_intr_md.ingress_port);
    bypass_egress();
}
action ExmLpfDirect() {
    modify_field(md.run_meter_tbl,                      0);
    modify_field(md.run_meter_tbl_direct,               0);
    modify_field(md.run_meter_tbl_color_aware_indirect, 0);
    modify_field(md.run_match_tbl_lpf,                  0);
    modify_field(md.run_match_tbl_tcam_lpf,             0);
    modify_field(md.run_match_tbl_lpf_direct,           1);
    modify_field(md.run_match_tbl_tcam_lpf_direct,      0);
    modify_field(md.run_ts,                             0);
    modify_field(md.run_color_match,                    0);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, ig_intr_md.ingress_port);
    bypass_egress();
}
action TCAMLpfDirect() {
    modify_field(md.run_meter_tbl,                      0);
    modify_field(md.run_meter_tbl_direct,               0);
    modify_field(md.run_meter_tbl_color_aware_indirect, 0);
    modify_field(md.run_match_tbl_lpf,                  0);
    modify_field(md.run_match_tbl_tcam_lpf,             0);
    modify_field(md.run_match_tbl_lpf_direct,           0);
    modify_field(md.run_match_tbl_tcam_lpf_direct,      1);
    modify_field(md.run_ts,                             0);
    modify_field(md.run_color_match,                    0);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, ig_intr_md.ingress_port);
    bypass_egress();
}

/* Main control flow */
control ingress {
    apply(test_select);
    if (md.run_ts == 1) {
        apply(ts);
    }

    if (md.run_meter_tbl == 1) {
        apply(meter_tbl);
    } else if (md.run_meter_tbl_direct == 1) {
        if (md.run_meter_tbl_direct == 1) {
            apply(meter_tbl_direct);
        }
    }

    if (md.run_meter_tbl_color_aware_indirect == 1) {
        apply(meter_tbl_color_aware_indirect);
    }

    if (md.run_match_tbl_lpf == 1) {
        apply(match_tbl_lpf);
    } else if (md.run_match_tbl_tcam_lpf == 1) {
        apply(match_tbl_tcam_lpf);
    } else if (md.run_match_tbl_lpf_direct == 1) {
        if (md.run_match_tbl_lpf_direct == 1) {
            apply(match_tbl_lpf_direct);
        }
    } else if (md.run_match_tbl_tcam_lpf_direct == 1) {
        apply(match_tbl_tcam_lpf_direct);
    }

    if (md.run_color_match == 1) {
        apply(color_match);
    }
}

control egress {
}
