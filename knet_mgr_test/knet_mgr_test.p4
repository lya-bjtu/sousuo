// This is P4 sample source for basic_switching

#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include "includes/headers.p4"
#include "includes/parser.p4"

#define CPU_PORT 64

action add_cpu_header(pad1, fabric_color, fabric_qos, dst_device, dst_port_or_group, reserved1, ingress_ifindex, ingress_bd, reason_code) {
    add_header(fabric_header);
    modify_field(fabric_header.packetType, FABRIC_HEADER_TYPE_CPU);
    modify_field(fabric_header.headerVersion, 0);
    modify_field(fabric_header.packetVersion, 0);
    modify_field(fabric_header.pad1, pad1);
    modify_field(fabric_header.fabricColor, fabric_color);
    modify_field(fabric_header.fabricQos, fabric_qos);
    modify_field(fabric_header.dstDevice, dst_device);
    modify_field(fabric_header.dstPortOrGroup, dst_port_or_group);
    add_header(fabric_header_cpu);
    modify_field(fabric_header_cpu.reserved, reserved1);
    modify_field(fabric_header_cpu.ingressIfindex, ingress_ifindex);
    modify_field(fabric_header_cpu.ingressBd, ingress_bd);
    modify_field(fabric_header_cpu.reasonCode, reason_code);
    modify_field(fabric_header_cpu.ingressPort, ig_intr_md.ingress_port);
    add_header(fabric_payload_header);
    modify_field(fabric_payload_header.etherType, ethernet.etherType);
    modify_field(ethernet.etherType, ETHERTYPE_BF_FABRIC);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, CPU_PORT);
}

table port_tbl {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        add_cpu_header;
    }
#ifdef __p4c__
    // p4c supports const default_action for actions that can not modify their
    // parameters from the control plane
    default_action: add_cpu_header(0, 0, 0, 0, 0, 0, 0, 0, 0);
#else
    default_action: add_cpu_header;
#endif
    size : 288;
}

action set_egress_port() {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, fabric_header_cpu.ingressPort);
}

table fabric_tbl {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        set_egress_port;
    }
    default_action: set_egress_port;
    size : 288;
}

control process_ingress_knet {
    if (ig_intr_md.ingress_port != CPU_PORT) {
       apply(port_tbl);
    } else {
       apply(fabric_tbl);
    }
}

control ingress {
  process_ingress_knet();
}

control egress {
}
