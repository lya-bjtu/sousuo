// Template parser.p4 file for pcie_pkt_test
// Edit this file as needed for your P4 program

// This parses an ethernet header

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return ingress;
}

