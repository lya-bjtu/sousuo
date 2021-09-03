################################################################################
# BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
#
# Copyright (c) 2019-present Barefoot Networks, Inc.
#
# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to Barefoot Networks, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in
# process, and are protected by trade secret or copyright law.  Dissemination of
# this information or reproduction of this material is strictly forbidden unless
# prior written permission is obtained from Barefoot Networks, Inc.
#
# No warranty, explicit or implicit is provided, unless granted under a written
# agreement with Barefoot Networks, Inc.
#
################################################################################

import logging

import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as client
import base64
import itertools

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())


class MeterBytecountAdjustTest(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        p4_name = "tna_meter_bytecount_adjust"
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def runTest(self):
        # Get bfrt_info and set it as part of the test
        bfrt_info = self.interface.bfrt_info_get()
        meter_table = bfrt_info.table_get("SwitchIngress.meter")
        direct_meter_color_table = bfrt_info.table_get("SwitchIngress.direct_meter_color")

        target = client.Target(device_id=0, pipe_id=0xffff)

        logger.info("set byte count adjust for meter table")
        meter_table.attribute_meter_bytecount_adjust_set(target, -12)
        resp = meter_table.attribute_get(target, "MeterByteCountAdjust")
        for d in resp:
            assert d["byte_count_adjust"] == -12

        logger.info("set byte count adjust for MatchAction_Direct meter table")
        direct_meter_color_table.attribute_meter_bytecount_adjust_set(target, 20)
        resp = direct_meter_color_table.attribute_get(target, "MeterByteCountAdjust")
        for d in resp:
            assert d["byte_count_adjust"] == 20
