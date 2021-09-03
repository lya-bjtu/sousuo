/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/* constants */
const bit<16> ETHERTYPE_XXNET1 = 0x4321;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
// 使用ipv6的以太网类型
const bit<16> ETHERTYPE_XXNET = 0x86dd;
const bit<9>  ONOS_PORT = 192;

/* Table Sizes */
const int XXNET_UID_SIZE = 12288;
const int XXNET_NID_SIZE = 12288;
const int XXNET_MAP_SIZE = 12288;

/* xxnet header next header */
const bit<8> PROTO_TCP    = 6;
const bit<8> PROTO_UDP    = 17;
const bit<8> PROTO_NID    = 200;

/* field type define */
typedef bit<9>   port_num_t;
typedef bit<48>  mac_addr_t;
typedef bit<128> uid_addr_t;
typedef bit<32>  nid_addr_t;

/* header definitions */
header ethernet_t {
    mac_addr_t  dst_addr;
    mac_addr_t  src_addr;
    bit<16>     ether_type;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    transfer_mode;
    bit<20>   flow_label;
    bit<16>   payload_len;
    bit<8>    next_hdr;
    bit<8>    hop_limit;
    bit<128>  src_addr;
    bit<128>  dst_addr;
}

header xxnet_uid_t {
    bit<4>    version;
    bit<8>    traffic_class;
    bit<20>   flow_label;
    bit<16>   payload_len;
    bit<8>    next_hdr;
    bit<8>    hop_limit;
    uid_addr_t  src_uid;
    uid_addr_t  dst_uid;
}


header xxnet_nid_t {
    bit<8>    next_hdr;
    bit<24>   reserve;
    nid_addr_t nid_addr; 
}

@controller_header("packet_in")
header cpu_in_header_t {
    port_num_t  ingress_port;
    bit<7>      _pad;
}

@controller_header("packet_out")
header cpu_out_header_t {
    port_num_t  egress_port;
    bit<7>      _pad;
}

struct my_ingress_headers_t {
    cpu_out_header_t cpu_out;
    cpu_in_header_t   cpu_in;
    ethernet_t      ethernet;
    xxnet_uid_t    xxnet_uid;
    xxnet_nid_t    xxnet_nid;
}

struct my_ingress_metadata_t  {
  
    bool        has_nid; 
    bit<8> uid_next_hdr;
    bit<8> nid_next_hdr;
}


/* parser */
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition select(ig_intr_md.ingress_port) {
            ONOS_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        pkt.extract(hdr.cpu_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_XXNET:  parse_xxnet_uid;
            default: accept;
        }
    }

    state parse_xxnet_uid {
        pkt.extract(hdr.xxnet_uid);
        meta.uid_next_hdr = hdr.xxnet_uid.next_hdr;
        transition select(hdr.xxnet_uid.next_hdr) {
            PROTO_NID: parse_xxnet_nid;
            default: accept;
        }
    }

    state parse_xxnet_nid {
        pkt.extract(hdr.xxnet_nid);
        meta.has_nid = true ;
        meta.nid_next_hdr = hdr.xxnet_nid.next_hdr;
        transition accept;
    }


}

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{

    
    //丢弃
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }
    //设置转发端口
    action set_egress_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    } 
    // //设置下一跳mac地址
    // action set_next_hop(mac_addr_t dst_addr) {
    //     hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
    //     hdr.ethernet.dst_addr = dmac;
    //     // Decrement TTL
    //     hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    // }
     
    //发送至onos查询
    action send_to_cpu() {
       ig_tm_md.ucast_egress_port = ONOS_PORT; 
    }

    action add_nid(nid_addr_t nid_addr) {
        hdr.xxnet_nid.setValid();
        hdr.xxnet_nid.next_hdr = meta.uid_next_hdr;
        hdr.xxnet_uid.next_hdr = PROTO_NID;
        hdr.xxnet_nid.nid_addr = nid_addr;
    }

    action remove_nid(){
        hdr.xxnet_uid.next_hdr = meta.nid_next_hdr ;
        hdr.xxnet_nid.setInvalid();
    }



    //uid转发表（本域对象匹配）前提：本域的设备，route一定能转发。
    table uid_fwd {
        key = { hdr.xxnet_uid.dst_uid: exact; }
        actions = { set_egress_port; NoAction; }
        size = XXNET_UID_SIZE;
        //未匹配说明该uid不在本域
        const default_action = NoAction();
    }

    //uid -> nid 映射表 （本域对象出域转发，根据uid查nid，增加nid扩展包头）
    table enable_nid {
        key = { hdr.xxnet_uid.dst_uid: exact;  }
        actions = { add_nid; send_to_cpu; }
        size = XXNET_MAP_SIZE;
        const default_action = send_to_cpu;
    }

    //nid转发表（目的对象不在本域，依据nid路由转发; 若为本设备nid，解封装）
    table nid_fwd {
        key = { hdr.xxnet_nid.nid_addr: exact; }
        actions = { remove_nid; set_egress_port; send_to_cpu; }
        size = XXNET_NID_SIZE;
        const default_action = send_to_cpu;
    }
    
    apply {
        
        //转发，或解封装
        if(meta.has_nid){
            nid_fwd.apply();
        }else{
            if(!uid_fwd.apply().hit){
            enable_nid.apply(); 
            nid_fwd.apply();
            }
        }

        



        // if(hdr.xxnet_uid.isValid()){
        //     if(!uid_fwd.apply().hit){
        //         enable_nid.apply();
        //         nid_fwd.apply();
        //     }
        // }

    }
}

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;

