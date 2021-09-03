#include <tofino/intrinsic_metadata.p4>

#define ETHERTYPE_IPV4    0x0800
#define ETHERTYPE_IPV6    0x86dd
#define UDP_PROTO         0x11

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
        length_ : 16;
        checksum : 16;
    }
}


header ethernet_t ethernet;
header ipv4_t ipv4;
header udp_t  udp;

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4    : parse_ipv4;
        default           : ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        UDP_PROTO : parse_udp;
        default   : ingress;
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

parser parse_udp {
    extract(udp);
    return ingress;
}

action do_nothing(){}

action set_egress_port(port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
}

action drop_packet() {
    drop();
}

table egress_port {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        set_egress_port;
        drop_packet;
        do_nothing;
    }
    default_action: do_nothing;
    size : 100;
}

control ingress {
    apply(egress_port);
}

control egress {}
