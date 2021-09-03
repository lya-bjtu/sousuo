/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
const bit<16> TYPE_AID = 0x1234;
const bit<16> TYPE_RID = 0x1235;
const bit<48> MAC_EDGE1 = 0x080000000100;
const bit<48> MAC_EDGE2 = 0x080000000200;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<48> macAddr_t;
typedef bit<9>  egressSpec_t;  
typedef bit<16> rid_s_t;
typedef bit<16> rid_d_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header aid_t {
    bit<4>    version;
    bit<6>    user_level;
    bit<6>    service_type;
    bit<16>   flow_flag;
    bit<16>   payload_len;
    bit<1>    F;     
    bit<7>    hop_limit;
    bit<8>    next_hdr;
    bit<32>   aid_s;
    bit<32>   aid_d;   
}

header rid_t {
    bit<4>    version;
    bit<6>    user_level;
    bit<6>    service_type;
    bit<16>   flow_flag;
    bit<16>   payload_len;
    bit<1>    F;     
    bit<7>    hop_limit;
    bit<8>    next_hdr;
    bit<16>   rid_s;    
    bit<16>   rid_d;    
}

struct headers {
    ethernet_t   ethernet;
    aid_t        aid;
    rid_t        rid;
}



struct metadata {
    bit<16> myrid;
    bit<7>  hop;
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/

 parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_AID: parse_aid;
            TYPE_RID: parse_rid;
            default: accept;
        }
    }

    state parse_aid {
        packet.extract(hdr.aid);
        transition accept;
        
    }

    state parse_rid {
        packet.extract(hdr.rid);
        meta.myrid = hdr.rid.rid_d;
        transition parse_aid;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

/******************************action***********************************************************/
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    //接入网默认操作
    action Adefault(egressSpec_t port){  
        standard_metadata.egress_spec = port;
    }

    //在接入网内根据aid转发 
    action aid_forward( egressSpec_t port) {   //port和aid_d需要在json文件中指定 
        standard_metadata.egress_spec = port; 
        // hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        // hdr.ethernet.dstAddr = dstAddr;
        hdr.aid.hop_limit = hdr.aid.hop_limit - 1; 
    }

    //在核心网内根据rid转发
    action rid_forward(macAddr_t dstAddr , egressSpec_t port) {   
        standard_metadata.egress_spec = port; 
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.rid.hop_limit = hdr.rid.hop_limit - 1;
        hdr.aid.hop_limit = hdr.rid.hop_limit;
    }

    //aid_s-->rid_s的转换
    action swap( rid_s_t RID_s , rid_d_t RID_d ){  
        hdr.rid.setValid();
        hdr.rid.rid_s = RID_s;   
        hdr.rid.rid_d = RID_d;
        meta.myrid = hdr.rid.rid_d;
        hdr.rid.version = hdr.aid.version;
        hdr.rid.user_level = hdr.aid.user_level;
        hdr.rid.service_type = hdr.aid.service_type;
        hdr.rid.flow_flag = 0;
        hdr.rid.next_hdr = 1;
        hdr.rid.F = 1;
        hdr.rid.hop_limit = hdr.aid.hop_limit;
        hdr.rid.payload_len = hdr.aid.payload_len;
    }

  

/******************************table***********************************************************/

    //aid--> rid 查找json文件中定义的表，找到对应的rid（写在data里）
    table change{
        key = {
            hdr.aid.aid_s : exact;
            hdr.aid.aid_d : exact ;
        }
        actions = {
            swap;
            drop;
        }
        size = 1024;
        default_action = drop();  
    }
    
    
    //接入网转发
    table AID_forward{  
        key = {
            hdr.aid.aid_d : exact;
        }
        actions = {
            aid_forward;
            Adefault;
        }
        size = 1024;  
        default_action = Adefault(2);  
    }

    //核心网转发（不包括封装、解封装）
    table RID_forward{  
        key = {
            meta.myrid : exact;
        }
        actions = {
            rid_forward;
            drop;
        }
        size = 1024; 
        default_action = drop();
    }

    

    apply {
        if((hdr.ethernet.dstAddr == MAC_EDGE1 || hdr.ethernet.dstAddr == MAC_EDGE2) ){
            if(!hdr.rid.isValid()){
                change.apply();
                hdr.ethernet.etherType =  0x1235;
                RID_forward.apply();
                
            }else if(hdr.rid.isValid()){
                hdr.rid.setInvalid();
                hdr.aid.hop_limit = hdr.rid.hop_limit;
                hdr.ethernet.etherType =  0x1234;
                AID_forward.apply();
            }
            
        }else if(hdr.rid.isValid()){
            RID_forward.apply();
            
        }else if(hdr.aid.isValid()&& hdr.aid.hop_limit==10){
            AID_forward.apply();
        }  
        
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    }     
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.rid);
        packet.emit(hdr.aid);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

