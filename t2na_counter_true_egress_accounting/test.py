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
import bfrt_grpc.client as gc

##### Required for Thrift #####
import pd_base_tests

##### ******************* #####

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)
    swports.sort()

if swports == []:
    swports = range(9)


def _add_entry(table, target, smac, smac_mask, priority, c_bytes, c_pkts, act):
    table.entry_add(
        target,
        [table.make_key(
            [gc.KeyTuple('hdr.ethernet.src_addr', smac, smac_mask),
             gc.KeyTuple('$MATCH_PRIORITY', priority)])],
        [table.make_data(
            [gc.DataTuple('$COUNTER_SPEC_BYTES', c_pkts),
             gc.DataTuple('$COUNTER_SPEC_PKTS', c_bytes)],
             act)])

def _setup_match(target, table, act_name, smac, smac_mask):
    table.info.key_field_annotation_add("hdr.ethernet.src_addr", "mac")

    _add_entry(table, target, smac, smac_mask, 0, 0, 0, act_name)

def _read_counter(table, target, name, smac, smac_mask):
    resp = table.entry_get(target,
                           [table.make_key([gc.KeyTuple('hdr.ethernet.src_addr', smac, smac_mask),
                                                    gc.KeyTuple('$MATCH_PRIORITY', 0)])],
                           {"from_hw": True},
                           table.make_data(
                               [gc.DataTuple("$COUNTER_SPEC_BYTES"),
                                gc.DataTuple("$COUNTER_SPEC_PKTS")],
                               name, get=True)
                           )

    # parse resp to get the counter
    data_dict = next(resp)[0].to_dict()
    recv_pkts = data_dict["$COUNTER_SPEC_PKTS"]
    recv_bytes = data_dict["$COUNTER_SPEC_BYTES"]
    return (recv_pkts, recv_bytes)

class TrueEgressAccountingTest(BfRuntimeTest):
    """@brief Simple test for true egress accounting.
       The same SMAC key is installed into table "count_src" and "count_src_teop",
       both of which count the number of bytes in the packet. The difference is
       that "count_src_teop" performs the packet truncation and its counter
       produces the true egress byte count.
    """

    def setUp(self):
        client_id = 0
        p4_name = "t2na_counter_true_egress_accounting"
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def runTest(self):
        target = gc.Target(device_id=0, pipe_id=0xffff)
        ig_port = swports[1]

        # Get bfrt_info and set it as part of the test
        bfrt_info = self.interface.bfrt_info_get("t2na_counter_true_egress_accounting")

        smac = '11:33:55:77:99:00'
        smac_mask = 'ff:ff:ff:ff:ff:ff'
        dmac = '00:11:22:33:44:55'

        count_src = bfrt_info.table_get("SwitchEgress.count_src")
        count_src_teop = bfrt_info.table_get("SwitchEgress.count_src_teop")

        # Install the same SMAC key into both tables so the same packet counts in both tables
        _setup_match(target, count_src, 'SwitchEgress.hit_src', smac, smac_mask)
        _setup_match(target, count_src_teop, 'SwitchEgress.hit_src_teop', smac, smac_mask)

        # Create input and expected packets
        eth = Ether(dst=dmac, src=smac, type=0x800)
        ip = IP()
        pkt = eth/ip
        pkt /= ("D" * (100 - len(pkt)))

        exp_pkt = Ether(dst=dmac, src=smac, type=0xffff) 
        exp_pkt /= ("D" * (100 - len(ip) - len(exp_pkt)))

        # The packet created above does not include the Ethernet FCS so add an additional
        # four bytes to the expected size to account for it.
        inp_pkt_size = len(pkt) + 4
        exp_pkt_size = len(exp_pkt) + 4

        num_pkts = 2;
        num_bytes = num_pkts * inp_pkt_size 
        num_bytes_teop = num_pkts * exp_pkt_size 

        logger.info("Sending packets on port %d", ig_port)

        for i in range(0, num_pkts):
            testutils.send_packet(self, ig_port, str(pkt))
            testutils.verify_packet(self, exp_pkt, ig_port)

        logger.info("Expecting packets on port %d", ig_port)

        recv_pkts, recv_bytes = _read_counter(count_src, target, 'SwitchEgress.hit_src', smac, smac_mask)
        recv_pkts_teop, recv_bytes_teop = _read_counter(count_src_teop, target, 'SwitchEgress.hit_src_teop', smac, smac_mask)

        # Verify packet count
        if (num_pkts != recv_pkts or recv_pkts != recv_pkts_teop):
            logger.error("Error! packets sent = %s received count = %s", str(num_pkts), str(recv_pkts))
            assert 0;
        else:
            logger.info("packets received = %s", str(recv_pkts))

        # Verify byte count
        if (num_bytes != recv_bytes):
            logger.error("Error! bytes sent = %s received count = %s", str(num_bytes), str(recv_bytes))
            assert 0;
        else:
            logger.info("bytes received = %s", str(recv_bytes))

        # Verify byte count (true egress accounting)
        if (num_bytes_teop != recv_bytes_teop):
            logger.error("Error! bytes sent = %s received count = %s (true egress)", str(num_bytes_teop), str(recv_bytes_teop))
            assert 0;
        else:
            logger.info("bytes received = %s (true egress)", str(recv_bytes_teop))

        # Clean up
        count_src.entry_del(target) 
        count_src_teop.entry_del(target) 
