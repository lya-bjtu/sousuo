#include "tofino/intrinsic_metadata.p4"

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

header_type udp_t {
    fields {
      srcPort : 16;
	    dstPort : 16;
	    len_ : 16;
	    chksum : 16;
    }
}

header_type pay_t {
   fields  {
       some_zeros : 120;
       marker : 8;
   }
}


header ethernet_t ethernet;
header ipv4_t ipv4;
header udp_t udp;
@pragma not_parsed ingress
//@pragma pa_disable_deparse_0_optimization ingress pay
header pay_t pay;

parser start {
    return parse_ethernet;
}


parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        0x800 : parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.protocol) {
        0x11 : parse_udp;
	default : ingress;
    }
}

parser parse_udp {
    extract(udp);
    return select(udp.srcPort){
        default : ingress;
	0x123 : parse_pay;  // dummy, will be added
    }
}

parser parse_pay {
   extract(pay);
   return ingress;
}


action set_p(p){
    modify_field(ig_intr_md_for_tm.ucast_egress_port, p);
    add_header(pay);
    modify_field(pay.marker, 1);
    modify_field(pay.some_zeros, 0);
    add_to_field(ipv4.totalLen, 16);
    add_to_field(udp.len_, 16);
}

action do_nothing(){}

table table_1 {
    reads {
        ipv4.dstAddr : exact;
    }
    actions {
        set_p;
        do_nothing;
    }
}

control ingress {
    if (valid(udp)){
        apply(table_1);
    }
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
