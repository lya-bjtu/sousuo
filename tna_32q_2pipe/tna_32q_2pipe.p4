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

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "pipeline_profile_a.p4"
#include "pipeline_profile_b.p4"

#include "common/headers.p4"
#include "common/util.p4"



// Packet comes into ingress profile_a which adds an extra custom_metadata_h
// header to the packet. The packet travels to egress profile_b, then to
// ingress profile_b and finally to egress profile_a. The custom_metadata_h
// header is striped off by egress profile_b. Value of custom_tag is modified
// as the packet travels.

Pipeline(SwitchIngressParser_a(),
         SwitchIngress_a(),
         SwitchIngressDeparser_a(),
         SwitchEgressParser_a(),
         SwitchEgress_a(),
         SwitchEgressDeparser_a()) pipeline_profile_a;

Pipeline(SwitchIngressParser_b(),
         SwitchIngress_b(),
         SwitchIngressDeparser_b(),
         SwitchEgressParser_b(),
         SwitchEgress_b(),
         SwitchEgressDeparser_b()) pipeline_profile_b;

Switch(pipeline_profile_a, pipeline_profile_b) main;
