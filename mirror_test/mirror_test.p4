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
#include <tofino2/intrinsic_metadata.p4>
#else
#include <tofino/intrinsic_metadata.p4>
#endif
#include <tofino/constants.p4>

header_type ethernet_t {
  fields {
    dstAddr : 48;
    srcAddr : 48;
    etherType : 16;
  }
}
header ethernet_t ethernet;

parser start {
  return parse_ethernet;
}

parser parse_ethernet {
  extract(ethernet);
  return ingress;
}

header_type metadata_t {
  fields {
    do_ing_mirroring : 1;
    do_egr_mirroring : 1;
    ing_mir_ses : 10;
    egr_mir_ses : 10;
  }
}

metadata metadata_t md;

table p0 {
  reads   { ig_intr_md.ingress_port : exact; }
  actions { set_md; }
  default_action: set_md(0, 0, 0, 0, 0);
  size : 288;
}

action set_md(dest_port, ing_mir, ing_ses, egr_mir, egr_ses) {
  modify_field(ig_intr_md_for_tm.ucast_egress_port, dest_port);
  modify_field(md.do_ing_mirroring, ing_mir);
  modify_field(md.do_egr_mirroring, egr_mir);
  modify_field(md.ing_mir_ses, ing_ses);
  modify_field(md.egr_mir_ses, egr_ses);
}

table ing_mir {
  actions { do_ing_mir; }
  default_action : do_ing_mir;
  size : 1;
}
table egr_mir {
  actions { do_egr_mir; }
  default_action : do_egr_mir;
  size : 1;
}

//field_list no_fields {}

action do_ing_mir() {
  //clone_ingress_pkt_to_egress(md.ing_mir_ses, no_fields);
#if __TARGET_TOFINO__ == 2
  modify_field(ig_intr_md_for_mb.mirror_hash, 2);
  modify_field(ig_intr_md_for_mb.mirror_multicast_ctrl, 0);
  modify_field(ig_intr_md_for_mb.mirror_io_select, 0);
#endif
  clone_ingress_pkt_to_egress(md.ing_mir_ses);
}
action do_egr_mir() {
  //clone_egress_pkt_to_egress(md.egr_mir_ses, no_fields);
#if __TARGET_TOFINO__ == 2
  modify_field(eg_intr_md_for_mb.mirror_hash, 2);
  modify_field(eg_intr_md_for_mb.mirror_multicast_ctrl, 0);
  modify_field(eg_intr_md_for_mb.mirror_io_select, 1);
#endif
  clone_egress_pkt_to_egress(md.egr_mir_ses);
  modify_field(eg_intr_md_for_oport.drop_ctl, 1);
}

action n() {}
action n1(x) {modify_field(ig_intr_md_for_tm.mcast_grp_a, x);}

@pragma dont_trim
table tcam {
  reads {
    ig_intr_md.ingress_port : ternary;
  }
  actions {n;n1;}
  default_action: n;
  size : 1024;
}

control ingress {
  if (0 == ig_intr_md.resubmit_flag) {
    apply(p0);
  }
  if (1 == md.do_ing_mirroring) {
    apply(ing_mir);
  }
  apply(tcam);
}
control egress {
  if (1 == md.do_egr_mirroring) {
    apply(egr_mir);
  }
}
