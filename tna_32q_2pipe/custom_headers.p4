/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2019-present Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks, Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.  Dissemination of
 * this information or reproduction of this material is strictly forbidden unless
 * prior written permission is obtained from Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a written
 * agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

#ifndef _CUSTOM_HEADERS_
#define _CUSTOM_HEADERS_

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"



header custom_metadata_h {
// Value of the tag during pipeline processing:
//  VALUE  - PIPELINE
//   x     - set to user defined value in ingress pipeline_profile_a
//   x+1   - pipeline_profile_b egress
//   x+2   - pipeline_profile_b ingress
//   x+3   - pipeline_profile_a egress
    bit<16> custom_tag;
}

struct custom_header_t {
    ethernet_h ethernet;
    vlan_tag_h vlan_tag;
    ipv4_h ipv4;
    ipv6_h ipv6;
    tcp_h tcp;
    udp_h udp;

    // Add more headers here.
    custom_metadata_h custom_metadata;
}

struct digest_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
}

#endif /* _CUSTOM_HEADERS_ */
