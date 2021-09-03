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

header_type tcp_t {
  fields {
    srcPort : 16;
    dstPort : 16;
    seqNo : 32;
    ackNo : 32;
    dataOffset : 4;
    res : 4;
    flags : 8;
    window : 16;
    checksum : 16;
    urgentPtr : 16;
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

header_type some_filler_t {
    fields {
        a : 32;
        b : 32;
        c : 32;
        d : 32;
        e : 32;
        f : 16;
    }
}

header_type some_payload_t {
    fields {
        a : 16;
        b : 16;
        c : 16;
        d : 16;
    }
}


header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;
header udp_t udp;
header some_filler_t some_filler;
header some_payload_t some_payload;

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
    return select(latest.protocol) {
        6 : parse_tcp;
        17 : parse_udp;
        default : ingress;
    }
}

parser parse_tcp {
    extract(tcp);
    return ingress;
}

parser parse_udp {
    extract(udp);
    return parse_filler;
}

parser parse_filler {
    extract(some_filler);
    return parse_some_payload;
}

parser parse_some_payload {
    extract(some_payload);
    return ingress;
}


action do_nothing(){}

action drop_it(){
    drop();
}

action set_p(p){
    modify_field(ig_intr_md_for_tm.ucast_egress_port, p);
}

action set_byte_d(d){
    modify_field(some_payload.d, d);
}

table table_1 {
    reads {
        some_payload.a : exact;
        some_payload.b : exact;
        some_payload.c : exact;
        some_payload.d : exact;
    }
    actions {
        set_byte_d;
        do_nothing;
    }
}

table port_table {
    reads {
        udp.srcPort : exact;
    }
    actions {
        set_p;
        do_nothing;
    }
}

table drop_table {
    actions {
        drop_it;
    }
    default_action : drop_it();
}


control ingress {
    if (ig_intr_md_from_parser_aux.ingress_parser_err == 0){
        if (valid(udp)){
            apply(table_1);
        }
        apply(port_table);
    } else {
        apply(drop_table);
    }
}
