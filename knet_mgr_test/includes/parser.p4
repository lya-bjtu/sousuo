#define ETHERTYPE_BF_FABRIC     0x9000
#define FABRIC_HEADER_TYPE_CPU 5

header ethernet_t ethernet;
header fabric_header_t fabric_header;
header fabric_header_cpu_t fabric_header_cpu;
header fabric_payload_header_t fabric_payload_header;

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_BF_FABRIC : parse_fabric_header;
        default: ingress;
    }
}

parser parse_fabric_header {
  extract(fabric_header);
  return select(latest.packetType)  {
  	default : parse_fabric_header_cpu;
  }
}

parser parse_fabric_header_cpu {
  extract(fabric_header_cpu);
  return select(latest.ingressPort) {
  	default: parse_fabric_payload_header;
  }
}

parser parse_fabric_payload_header {
  extract(fabric_payload_header);
  return select(latest.etherType) {
	  default: ingress;
  }
}
