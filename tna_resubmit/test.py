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

from ptf import config, mask
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc

dev_id = 0
p4_program_name = "tna_resubmit"

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)
    swports.sort()


class NoResubmitTest(BfRuntimeTest):
    """@brief Verify if the program forwards packets correctly.
    """

    def setUp(self):
        client_id = 0
        BfRuntimeTest.setUp(self, client_id, p4_program_name)

    def runTest(self):
        target = gc.Target(device_id=0, pipe_id=0xffff)
        # Get bfrt_info and set it as part of the test
        bfrt_info = self.interface.bfrt_info_get(p4_program_name)

        # Set default output port
        table_output_port = bfrt_info.table_get("SwitchIngress.output_port")
        action_data = table_output_port.make_data(
            action_name="SwitchIngress.set_output_port",
            data_field_list_in=[gc.DataTuple(name="port_id", val=swports[1])]
        )
        table_output_port.default_entry_set(
            target=target,
            data=action_data)

        try:
            ipkt = testutils.simple_tcp_packet(eth_dst='11:11:11:11:11:11',
                                               eth_src='22:33:44:55:66:77',
                                               ip_src='1.2.3.4',
                                               ip_dst='100.99.98.97',
                                               ip_id=101,
                                               ip_ttl=64,
                                               tcp_sport=0x1234,
                                               tcp_dport=0xabcd,
                                               with_tcp_chksum=True)

            # Expected result:
            # One pipeline pass: eth_dst
            # No port selected through action, no resubmit header is used
            epkt = testutils.simple_tcp_packet(eth_dst='00:00:00:00:00:01',
                                               eth_src='22:33:44:55:66:77',
                                               ip_src='1.2.3.4',
                                               ip_dst='100.99.98.97',
                                               ip_id=101,
                                               ip_ttl=64,
                                               tcp_sport=0x1234,
                                               tcp_dport=0xabcd,
                                               with_tcp_chksum=True)

            testutils.send_packet(self, swports[0], ipkt)
            testutils.verify_packet(self, epkt, swports[1])
        finally:
            table_output_port.default_entry_reset(target)


class ResubmitTest(BfRuntimeTest):
    """@brief Resubmit a packet without a resubmit-header.
    """

    def setUp(self):
        client_id = 0
        BfRuntimeTest.setUp(self, client_id, p4_program_name)

    def runTest(self):
        target = gc.Target(device_id=0, pipe_id=0xffff)
        # Get bfrt_info and set it as part of the test
        bfrt_info = self.interface.bfrt_info_get(p4_program_name)

        # Set default output port
        table_output_port = bfrt_info.table_get("SwitchIngress.output_port")
        action_data = table_output_port.make_data(
            action_name="SwitchIngress.set_output_port",
            data_field_list_in=[gc.DataTuple(name="port_id", val=swports[1])]
        )
        table_output_port.default_entry_set(
            target=target,
            data=action_data)

        # Resubmit packets, but do not add an resubmit header.
        table_resubmit_ctl = bfrt_info.table_get("SwitchIngress.resubmit_ctrl")

        action_data = table_resubmit_ctl.make_data(
            [],
            action_name="SwitchIngress.resubmit_no_hdr"
        )

        table_resubmit_ctl.default_entry_set(
            target=target,
            data=action_data)

        try:
            ipkt = testutils.simple_tcp_packet(eth_dst='11:11:11:11:11:11',
                                               eth_src='22:33:44:55:66:77',
                                               ip_src='1.2.3.4',
                                               ip_dst='100.99.98.97',
                                               ip_id=101,
                                               ip_ttl=64,
                                               tcp_sport=0x1234,
                                               tcp_dport=0xabcd,
                                               with_tcp_chksum=True)

            # Expected result:
            # Two pipeline passes: eth_dst
            # No port selected through action, no resubmit header is used
            epkt = testutils.simple_tcp_packet(eth_dst='00:00:00:00:00:02',
                                               eth_src='22:33:44:55:66:77',
                                               ip_src='1.2.3.4',
                                               ip_dst='100.99.98.97',
                                               ip_id=101,
                                               ip_ttl=64,
                                               tcp_sport=0x1234,
                                               tcp_dport=0xabcd,
                                               with_tcp_chksum=True)

            testutils.send_packet(self, swports[0], ipkt)
            testutils.verify_packet(self, epkt, swports[0])
        finally:
            table_output_port.default_entry_reset(target)
            table_resubmit_ctl.default_entry_reset(target)


class ResubmitAddHdrTest(BfRuntimeTest):
    """@brief Resubmit a packet with a resubmit-header.
    """

    def setUp(self):
        client_id = 0
        BfRuntimeTest.setUp(self, client_id, p4_program_name)

    def runTest(self):
        target = gc.Target(device_id=0, pipe_id=0xffff)
        # Get bfrt_info and set it as part of the test
        bfrt_info = self.interface.bfrt_info_get(p4_program_name)
        # Set default output port
        table_output_port = bfrt_info.table_get("SwitchIngress.output_port")
        action_data = table_output_port.make_data(
            action_name="SwitchIngress.set_output_port",
            data_field_list_in=[gc.DataTuple(name="port_id", val=swports[1])]
        )
        table_output_port.default_entry_set(
            target=target,
            data=action_data)

        # Resubmit each packet once and add a resubmit header.
        table_resubmit_ctl = bfrt_info.table_get("SwitchIngress.resubmit_ctrl")

        action_data = table_resubmit_ctl.make_data(
            [gc.DataTuple(name="add_hdr_port_id", val=5)],
            action_name="SwitchIngress.resubmit_add_hdr"
        )

        table_resubmit_ctl.default_entry_set(
            target=target,
            data=action_data)

        try:
            ipkt = testutils.simple_tcp_packet(eth_dst='11:11:11:11:11:11',
                                               eth_src='22:33:44:55:66:77',
                                               ip_src='1.2.3.4',
                                               ip_dst='100.99.98.97',
                                               ip_id=101,
                                               ip_ttl=64,
                                               tcp_sport=0x1234,
                                               tcp_dport=0xabcd,
                                               with_tcp_chksum=True)

            # Expected result:
            # Two pipeline passes: eth_dst
            # Selected port two in the action: swports
            epkt = testutils.simple_tcp_packet(eth_dst='00:00:00:00:00:02',
                                               eth_src='22:33:44:55:66:77',
                                               ip_src='1.2.3.4',
                                               ip_dst='100.99.98.97',
                                               ip_id=101,
                                               ip_ttl=64,
                                               tcp_sport=0x1234,
                                               tcp_dport=0xabcd,
                                               with_tcp_chksum=True)

            testutils.send_packet(self, swports[0], ipkt)
            testutils.verify_packet(self, epkt, swports[5])
        finally:
            table_output_port.default_entry_reset(target)
            table_resubmit_ctl.default_entry_reset(target)
