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

from ptf import config
from ptf.thriftutils import *
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as client

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)
    swports.sort()

if swports == []:
    swports = list(range(9))


class DynHashingTest(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        p4_name = "tna_dyn_hashing"
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def runTest(self):
        # Get bfrt_info and set it as part of the test
        bfrt_info = self.interface.bfrt_info_get("tna_dyn_hashing")
        hash_config_table = bfrt_info.table_get("IngressP.hash_1.$CONFIGURE")

        logger.info("=============== Testing Dyn Hashing entry operation===============")
        target = client.Target(device_id=0, pipe_id=0xffff)
        logger.info("Modify entry")
        hash_config_table.entry_add(
            target,
            None,
            [hash_config_table.make_data([client.DataTuple('hdr.ipv4.proto.$PRIORITY', 0),
                                          client.DataTuple('hdr.ipv4.sip.$PRIORITY', 2),
                                          client.DataTuple('hdr.ipv4.dip.$PRIORITY', 1),
                                          client.DataTuple('hdr.tcp.sPort.$PRIORITY', 3),
                                          client.DataTuple('hdr.tcp.dPort.$PRIORITY', 4)])])
        logger.info("Read entry")
        resp = hash_config_table.entry_get(target, None, {"from_hw": False})
        data_dict = next(resp)[0].to_dict()
        logger.info("data_dict = %s", str(data_dict))
        assert (data_dict['hdr.ipv4.proto.$PRIORITY'] == 0)
        assert (data_dict['hdr.ipv4.sip.$PRIORITY'] == 2)
        assert (data_dict['hdr.ipv4.dip.$PRIORITY'] == 1)
        assert (data_dict['hdr.tcp.sPort.$PRIORITY'] == 3)
        assert (data_dict['hdr.tcp.dPort.$PRIORITY'] == 4)

        logger.info("set dyn hashing attribute")
        hash_config_table.attribute_dyn_hashing_set(target,
                                                    alg_hdl=587202560,
                                                    seed=0x12345)
        resp = hash_config_table.attribute_get(target, "DynamicHashing")
        for d in resp:
            assert d["alg"] == 587202560
            assert d["seed"] == 0x12345

