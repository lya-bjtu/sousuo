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
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as client

g_arch        = testutils.test_param_get("arch").lower()
g_is_tofino2  = ( g_arch == "tofino2" )

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)
    swports.sort()

class SnapshotTest(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        p4_name = "tna_snapshot"
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def runTest(self):
        ig_port = swports[1]
        eg_port = swports[2]
        dmac = '11:22:33:44:55:66'
        sip = "1.2.3.4"
        dip = "5.6.7.8"
        start_stage = 0
        end_stage = 2
        snap_enable = True
        ethernet_valid = 1

        # Get bfrt_info and set it as part of the test
        bfrt_info = self.interface.bfrt_info_get("tna_snapshot")
        snapshot_ingress_liveness_table = bfrt_info.table_get("$SNAPSHOT_INGRESS_LIVENESS")
        snapshot_ingress_table = bfrt_info.table_get("$SNAPSHOT_INGRESS")
        forward_table = bfrt_info.table_get("forward")
        forward_table.info.key_field_annotation_add("hdr.ethernet.dst_addr", "mac")
        snapshot_ingress_table.info.key_field_annotation_add("hdr.ethernet.dst_addr", "mac")
        snapshot_ingress_table.info.data_field_annotation_add("hdr.ethernet.dst_addr", None, "mac")
        snapshot_ingress_table.info.key_field_annotation_add("hdr.ipv4.src_addr", "ipv4")
        snapshot_ingress_table.info.data_field_annotation_add("hdr.ipv4.src_addr", None, "ipv4")

        pkt = testutils.simple_tcp_packet(eth_dst=dmac, ip_dst=dip, ip_src=sip)
        exp_pkt = pkt

        target = client.Target(device_id=0, pipe_id=0xffff, direction=0)
        target_0 = client.Target(device_id=0, pipe_id=0, direction=0)

        logger.info("Check for snapshot trigger field scope")
        scope_resp = snapshot_ingress_liveness_table.entry_get(
                                          target_0,
                                          [snapshot_ingress_liveness_table.make_key(
                                            [client.KeyTuple('$SNAPSHOT_LIVENESS_FIELD_NAME', 'hdr.ipv4.src_addr')])])

        logger.info("Parsing snapshot field scope response")
        field_stage_validated = 0
        # Go over the response data
        for data,key in scope_resp:
            data_dict = data.to_dict()
            valid_stages = data_dict["$SNAPSHOT_LIVENESS_VALID_STAGES"]
            logger.info("Valid Stages : %s", str(valid_stages))
            # Make sure start and end stage exists in the returned stage list
            for stage_val in valid_stages:
                if stage_val == start_stage or stage_val == end_stage:
                    field_stage_validated += 1
        # Field should be present in both start and end stage
        assert field_stage_validated == 2
        logger.info("-- Snapshot field scope validated --")

        logger.info("Inserting fwding entry")
        forward_table.entry_add(
            target,
            [forward_table.make_key([client.KeyTuple('hdr.ethernet.dst_addr', dmac)])],
            [forward_table.make_data([client.DataTuple('port', eg_port)],
            'SwitchIngress.hit')]
        )

        if g_is_tofino2:
            # ipv4 src addr field is a mocha phv on tofino2, skip it
            snapshot_key = snapshot_ingress_table.make_key([client.KeyTuple('$SNAPSHOT_TRIGGER_STAGE', start_stage),
                 client.KeyTuple('$SNAPSHOT_END_STAGE', end_stage),
                 client.KeyTuple('hdr.ethernet.dst_addr', dmac, dmac),
                 client.KeyTuple('hdr.ethernet.$valid', ethernet_valid, ethernet_valid)])
        else:
            snapshot_key = snapshot_ingress_table.make_key([client.KeyTuple('$SNAPSHOT_TRIGGER_STAGE', start_stage),
                 client.KeyTuple('$SNAPSHOT_END_STAGE', end_stage),
                 client.KeyTuple('hdr.ipv4.src_addr', sip, sip),
                 client.KeyTuple('hdr.ethernet.dst_addr', dmac, dmac),
                 client.KeyTuple('hdr.ethernet.$valid', ethernet_valid, ethernet_valid)])

        logger.info("Setting up the snapshot")
        snapshot_ingress_table.entry_add(
            target,
            [snapshot_key],
            [snapshot_ingress_table.make_data([client.DataTuple('$SNAPSHOT_ENABLE', bool_val=snap_enable)])])

        time.sleep(2)
        logger.info("Sending packet on port %d", ig_port)
        testutils.send_packet(self, ig_port, pkt)

        logger.info("Expecting packet on port %d", eg_port)
        testutils.verify_packets(self, exp_pkt, [eg_port])
        time.sleep(1)

        logger.info("Getting the captured snapshot data")
        resp = snapshot_ingress_table.entry_get(
                                    target_0,
                                    [snapshot_key])

        logger.info("Parsing snapshot data")
        # Iterate over the response data
        for data, key in resp:
            # Get Snapshot enable state
            key_dict = key.to_dict()
            data_dict = data.to_dict()
            enable_val = data_dict["$SNAPSHOT_ENABLE"]
            logger.info("Snapshot Enable state: %d", enable_val)
            if enable_val != False:
                logger.info("Snapshot did not get triggered, skipping parse data")
                assert (enable_val == False)

            # Field info container list
            field_info_dict_list = data_dict["$SNAPSHOT_FIELD_INFO"]
            logger.info("Field-info")
            # Go over the field-info container items
            for field_info_dict in field_info_dict_list:
                stage_val = field_info_dict["$SNAPSHOT_STAGE_ID"]
                logger.info("  ")
                logger.info("  -- Snapshot stage: 0x%x -- ", stage_val)
                assert dmac == field_info_dict["hdr.ethernet.dst_addr"]
                logger.info("  Verified captured destination mac in stage %d", stage_val)
                if (not g_is_tofino2):
                    assert sip == field_info_dict["hdr.ipv4.src_addr"]
                    logger.info("  Verified captured ipv4 src addr in stage %d", stage_val)
                assert 1 == field_info_dict["hdr.ipv4.$valid"]
                logger.info("  Verified captured ipv4_valid bit in stage %d", stage_val)

            # Control info container list
            ctrl_info_dict_list = data_dict["$SNAPSHOT_CONTROL_INFO"]
            logger.info("\n\nControl-info:")
            # Go over control info containers
            for ctrl_info_dict in ctrl_info_dict_list:
                stage_val = ctrl_info_dict["$SNAPSHOT_STAGE_ID"]
                logger.info("\n  -- Snapshot stage: 0x%x -- ", stage_val)

                # Table info is again a list of containers hence taking 0th index
                tbl_name = ctrl_info_dict["$SNAPSHOT_TABLE_INFO"][0]["$SNAPSHOT_TABLE_NAME"]
                logger.info("Table found : %s", tbl_name)
                table_hit = ctrl_info_dict["$SNAPSHOT_TABLE_INFO"][0]["$SNAPSHOT_TABLE_HIT"]
                logger.info("%s was %s", tbl_name, "hit" if table_hit else "miss")
                # Only forward table should be hit
                assert table_hit if tbl_name == "SwitchIngress_forward" else not table_hit

                # Verify that local stage trigger is only true for start stage
                local_stage_trigger = ctrl_info_dict["$SNAPSHOT_LOCAL_STAGE_TRIGGER"]
                assert local_stage_trigger if stage_val == start_stage else not local_stage_trigger

                # Verify that previous stage trigger is true for all except start stage
                prev_stage_trigger = ctrl_info_dict["$SNAPSHOT_PREV_STAGE_TRIGGER"]
                assert not prev_stage_trigger if stage_val == start_stage else prev_stage_trigger
        logger.info("-- Snapshot capture field values validated --")

        logger.info("Deleting table entry")
        forward_table.entry_del(
            target,
            [forward_table.make_key([client.KeyTuple('hdr.ethernet.dst_addr', dmac)])])
        logger.info("Deleting the snapshot")
        snapshot_ingress_table.entry_del(
            target,
            [])

        logger.info("Check if entry was deleted in clear call")
        resp = snapshot_ingress_table.entry_get(target_0, [snapshot_key])
        try:
            # If entry is not there exception will be raised on following line
            for data, key in resp:
                print("Stub print")
        except Exception:
            print("Entry deleted - PASS")
        else:
            raise AssertionError("Entry not deleted")
