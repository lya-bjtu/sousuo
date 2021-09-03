#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>

#define VLAN_DEPTH             2
#define ETHERTYPE_VLAN         0x8100
#define ETHERTYPE_IPV4         0x0800

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type vlan_tag_t {
    fields {
        pcp : 3;
        cfi : 1;
        vid : 12;
        etherType : 16;
    }
}

header_type new_tag_24t {
    fields {
        t24_f1_6b : 6;
        t24_f2_12b : 12;
        t24_f3_14b : 14;
    }
}

header_type new_tag_32t {
    fields {
        t32_f1_16b : 16;
        t32_f2_16b : 16;
    }
}

header_type new_tag_48t {
    fields {
        t48_f1_16b : 16;
        t48_f2_32b : 32;
    }
}

header_type new_tag_64t {
    fields {
        t64_f1_48b : 48;
        t64_f2_16b : 16;
    }
}

header ethernet_t ethernet;
header vlan_tag_t vlan_tag_;
header new_tag_24t new_tag24_;
header new_tag_32t new_tag32_;
header new_tag_48t new_tag48_;
header new_tag_64t new_tag64_;
header new_tag_64t new_tag64_2_;

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

parser start {
    return parse_ethernet;
}

@pragma parser_value_set_size 5
parser_value_set pvs1;
@pragma parser_value_set_size 6
parser_value_set pvs2;
@pragma parser_value_set_size 9
parser_value_set pvs3;
@pragma parser_value_set_size 2
parser_value_set pvs4;
@pragma parser_value_set_size 5
parser_value_set pvs5;

@pragma packet_entry
parser start_i2e_mirrored {
    extract(ethernet);
    return select(latest.etherType) {
        pvs5 : parse_vlan;
        default : ingress;
    }
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        pvs2 : parse_vlan;
        default : ingress;
    }
}

parser parse_vlan {
    extract(vlan_tag_);
    return select(latest.etherType) {
	pvs1 : parse_ipv4;
        default : ingress;
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
header ipv4_t ipv4;

parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}

// Example of using PVS along with constant select value
parser parse_hdr_pvs1 {
    extract(new_tag24_);
    return select(latest.t24_f1_6b, latest.t24_f3_14b) {
      pvs3 : parse_hdr_pvs3;
      199: parse_hdr_pvs4;
      default: ingress;
    }
}

parser parse_hdr_pvs2 {
    extract(new_tag32_);
    return ingress;
}

parser parse_hdr_pvs3 {
    extract(new_tag48_);
    return select(latest.t48_f2_32b) {
      pvs4: parse_hdr_pvs4;
      default: ingress;
    }
}

parser parse_hdr_pvs4 {
    extract(new_tag64_);
    // Expected to get compile error when branch condition value is > 32bits
    //return select(latest.t64_f1_48b) {
    //  6700: parse_hdr_pvs5;
    //  default: ingress;
    //}
    return ingress;
}

parser parse_hdr_pvs5 {
    extract(new_tag64_2_);
    return ingress;
}


action vlan_miss(egress_port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_port);
}

action vlan_hit(egress_port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_port);
}

action noop() {
    no_op();
}

action mod_vid(val) {
    modify_field(vlan_tag_.vid, val);
}

action mod_ttl(val) {
    modify_field(ipv4.ttl, val);
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
  default_action: set_md(0, 0, 0, 0);
  size : 288;
}

action set_md(ing_mir, ing_ses, egr_mir, egr_ses) {
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

action do_ing_mir() {
  clone_ingress_pkt_to_egress(md.ing_mir_ses);
}

table read_ttl {
    reads {
	ipv4.ttl : exact;
        ipv4 : valid;
    }
    actions {
        mod_ttl;
    }
    size : 512;
}

table vlan {
    reads {
        vlan_tag_.vid: exact;
	vlan_tag_ : valid;
    }
    actions {
        vlan_miss;
        vlan_hit;
    }
    size : 512;
}

table vlan2 {
    reads {
	vlan_tag_.vid: exact;
	vlan_tag_ : valid;
    }
    actions {
	mod_vid;
     	noop;
    }
    size : 512;
}


control ingress {
    if (0 == ig_intr_md.resubmit_flag) {
        apply(p0);
    }
    if (1 == md.do_ing_mirroring) {
        apply(ing_mir);
    }
    apply(vlan);
}

control egress {
    apply(vlan2);
    apply(read_ttl);
}
