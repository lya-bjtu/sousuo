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
#include "tofino/stateful_alu_blackbox.p4"

action n() {}
action N(x) {modify_field(ig_intr_md_for_tm.rid, x);}

table p0 {
  reads {
    ig_intr_md.ingress_port : exact;
  }
  actions {N;}
  default_action: N(0);
  size: 288;
}
// Control plane operations are tested with this table.
@pragma dont_trim
table exm {
  reads {
    ig_intr_md.ingress_port : exact;
  }
  actions {n;}
}
// Control plane operations are tested with this table.
@pragma dont_trim
table tcam {
  reads {
    ig_intr_md.ingress_port : ternary;
  }
  actions {n;}
}
@pragma use_hash_action 1
table ha {
  reads {
    ig_intr_md.ingress_port : exact;
  }
  actions {n;}
  default_action : n();
  size: 512;
}
counter ha_cntr {
  type: packets;
  direct: ha;
}

@pragma alpm 1
table alpm {
  reads {
    ig_intr_md.ingress_port : lpm;
  }
  actions {n;}
  size: 1024;
}

/*
 * Shared Counter
 */
counter cntr {
    type: packets_and_bytes;
    instance_count: 1000;
    min_width : 32;
}

/*
 * Shared Selection Table w/ Counter
 */
action a(x) {
  modify_field(ig_intr_md_for_tm.ucast_egress_port, x);
}
action b(x,i) {
  modify_field(ig_intr_md_for_tm.ucast_egress_port, x);
  count(cntr, i);
}
action c(x) {
  a(x);
  count(cntr, 1);
}
action d(x,y,i) {
  modify_field(ipv6.srcAddr, x);
  modify_field(ipv6.flowLabel, y);
  count(cntr, i);
}
action e() {
  count(cntr, 0);
}
action_profile sel_ap {
  actions { a;b;c;d;e; }
  dynamic_action_selection : sel_as;
}
action_selector sel_as {
  selection_key : sel_as_hash;
}
field_list_calculation sel_as_hash {
    input { sel_as_hash_fields; }
    algorithm : crc32;
    output_width : 29;
}
field_list sel_as_hash_fields {
    ethernet.dstAddr;
    ethernet.srcAddr;
}

table exm_sel {
  reads {
    ipv6.valid : exact;
    ipv6.srcAddr : exact;
    ipv6.dstAddr : exact;
  }
  action_profile : sel_ap;
}
table tcam_sel {
  reads {
    ipv6.valid : exact;
    ipv6.srcAddr : exact;
    ipv6.dstAddr : lpm;
  }
  action_profile : sel_ap;
}

/*
 * Shared Indirect Action w/ Counter
 */
action_profile ap {
  actions { a;b;c;d;e; }
}
table exm_ap {
  reads {
    ipv6.valid : exact;
    ipv6.srcAddr : exact;
    ipv6.dstAddr : exact;
  }
  action_profile : ap;
}
table tcam_ap {
  reads {
    ipv6.valid : exact;
    ipv6.srcAddr : exact;
    ipv6.dstAddr : lpm;
  }
  action_profile : ap;
}

/*
 * Keyless table with direct register.
 */
register r0 {
  width : 32;
  direct : r;
}
blackbox stateful_alu r0_alu {
  reg: r0;
  update_lo_1_value: register_lo + 1;
}
table r {
  actions {r0_inc; r0_inc_duplicate;}
  default_action: r0_inc;
  size: 1;
}
action r0_inc() {
  r0_alu.execute_stateful_alu();
}
action r0_inc_duplicate() {
  r0_alu.execute_stateful_alu();
}


/*
 * Keyless tables with action params.
 */
table e_keyless {
  reads { ethernet.dstAddr : exact; }
  actions { set_dmac; }
  size : 10;
}
table t_keyless {
  reads { ethernet.srcAddr : ternary; }
  actions { set_smac; }
  size : 10;
}
action set_dmac(d) {
  modify_field(ethernet.dstAddr, d);
}
action set_smac(s) {
  modify_field(ethernet.srcAddr, s);
}


header_type ethernet_t {
  fields {
    dstAddr : 48;
    srcAddr : 48;
    etherType : 16;
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
header ethernet_t ethernet;
header ipv6_t ipv6;
parser start {
  extract(ethernet);
  extract(ipv6);
  return ingress;
}
control ingress {
  if (0 == ig_intr_md.resubmit_flag) {
    apply(p0);
  }
  apply(exm);
  apply(tcam);
  apply(ha);
  apply(alpm);
  if (ig_intr_md.ingress_port == 0) {
    apply(exm_sel);
  } else if (ig_intr_md.ingress_port == 1) {
    apply(tcam_sel);
  } else if (ig_intr_md.ingress_port == 2) {
    apply(exm_ap);
  } else if (ig_intr_md.ingress_port == 3) {
    apply(tcam_ap);
  }
  apply(r);
  apply(e_keyless);
  apply(t_keyless);
}
