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

import ptf
from ptf import config
import ptf.testutils as testutils
from ptf.testutils import *
from bfruntime_client_base_tests import BfRuntimeTest, BaseTest
import bfrt_grpc.client as gc

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)
    swports.sort()

if swports == []:
    swports = list(range(9))


def port_to_pipe(port):
    local_port = port & 0x7F
    assert (local_port < 72)
    pipe = (port >> 7) & 0x3
    assert (port == ((pipe << 7) | local_port))
    return pipe


swports_0 = []
swports_1 = []
swports_2 = []
swports_3 = []
for port in swports:
    pipe = port_to_pipe(port)
    if pipe == 0:
        swports_0.append(port)
    elif pipe == 1:
        swports_1.append(port)
    elif pipe == 2:
        swports_2.append(port)
    elif pipe == 3:
        swports_3.append(port)

field_to_byte_len = 2


def get_ig_eg_ports_profA(pipe0):
    if pipe0 == 0:
        ig_port0 = swports_0[0]
        eg_port0 = swports_0[1]
    elif pipe0 == 1:
        ig_port0 = swports_1[0]
        eg_port0 = swports_1[1]
    elif pipe0 == 2:
        ig_port0 = swports_2[0]
        eg_port0 = swports_2[1]
    elif pipe0 == 3:
        ig_port0 = swports_3[0]
        eg_port0 = swports_3[1]
    return ig_port0, eg_port0


def get_ig_eg_ports_profB(pipe1):
    if pipe1 == 0:
        ig_port1 = swports_0[0]
        eg_port1 = swports_0[0]
    elif pipe1 == 1:
        ig_port1 = swports_1[0]
        eg_port1 = swports_1[0]
    elif pipe1 == 2:
        ig_port1 = swports_2[0]
        eg_port1 = swports_2[0]
    elif pipe1 == 3:
        ig_port1 = swports_3[0]
        eg_port1 = swports_3[0]
    return ig_port1, eg_port1


def get_internal_or_external_pipe(self, is_internal):
    for pipe in (0, 4):
        if pipe == 0:
            port = swports_0[0]
        elif pipe == 1:
            port = swports_1[0]
        elif pipe == 2:
            port = swports_2[0]
        elif pipe == 3:
            port = swports_3[0]
        result = testutils.pal.pal_is_port_internal(dev_id, port)
        if (is_internal) and (result):
            return pipe
        if (not is_internal) and (not result):
            return pipe
    assert (0)


def verify_cntr_inc(self, all_devtgt, all_pipes, all_ports, all_ttl, all_macs, all_ip, all_custom_tags, num_pkts):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports
    ig_ttl0, eg_ttl1, ig_ttl1, eg_ttl0 = all_ttl
    dmac, smac = all_macs
    dip, sip = all_ip
    ig_tag0, eg_tag1, ig_tag1, eg_tag0 = all_custom_tags

    logger.info("Verifying counter got incremented on pipe0 egress")

    logger.info("  Get Table entry")
    resp = self.a.e_forward_table.entry_get(target,
                                            [self.a.e_forward_table.make_key(
                                                [gc.KeyTuple('hdr.ipv4.dst_addr', dip, dip),
                                                 gc.KeyTuple('hdr.ipv4.ttl', eg_ttl0, eg_ttl0),
                                                 gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag0, eg_tag0),
                                                 gc.KeyTuple('$MATCH_PRIORITY', 0)])],
                                            {"from_hw": True},
                                            self.a.e_forward_table.make_data(
                                                [gc.DataTuple("$COUNTER_SPEC_BYTES"),
                                                 gc.DataTuple("$COUNTER_SPEC_PKTS")],
                                                'SwitchEgress_a.hit')
                                            )

    # parse resp to get the counter
    data_dict = next(resp)[0].to_dict()
    recv_pkts = data_dict["$COUNTER_SPEC_PKTS"]
    recv_bytes = data_dict["$COUNTER_SPEC_BYTES"]

    if (num_pkts != recv_pkts):
        logger.error("Error! packets sent = %s received count = %s", str(num_pkts), str(recv_pkts))
        assert 0

    # Default packet size is 100 bytes and model adds 4 bytes of CRC
    # Add 2 bytes for the custom metadata header
    pkt_size = 100 + 4 + 2
    num_bytes = num_pkts * pkt_size

    if (num_bytes != recv_bytes):
        logger.error("Error! bytes sent = %s received count = %s", str(num_bytes), str(recv_bytes))
        assert 0


def program_pinning(self, all_devtgt, all_pipes, all_ports):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports

    logger.info("Programming pinning entries")

    logger.info(" Programming pinning entries on ingress pipe %d ", pipe0)
    self.a.pinning_table.entry_add(
        target,
        [self.a.pinning_table.make_key(
            [gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])],
        [self.a.pinning_table.make_data(
            [gc.DataTuple('port', eg_port1)],
            'SwitchIngress_a.modify_eg_port')]
    )

    logger.info(" Programming pinning entries on ingress pipe %d ", pipe1)
    self.b.pinning_table.entry_add(
        target,
        [self.b.pinning_table.make_key(
            [gc.KeyTuple('ig_intr_md.ingress_port', ig_port1)])],
        [self.b.pinning_table.make_data(
            [gc.DataTuple('port', eg_port0)],
            'SwitchIngress_b.modify_eg_port')]
    )


def delete_pinning(self, all_devtgt, all_pipes, all_ports):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports

    logger.info("Deleting pinning entries")

    logger.info(" Deleting pinning entries on ingress pipe %d ", pipe0)
    self.a.pinning_table.entry_del(
        target,
        [self.a.pinning_table.make_key(
            [gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])])

    logger.info(" Deleting pinning entries on ingress pipe  %d ", pipe1)
    self.b.pinning_table.entry_del(
        target,
        [self.b.pinning_table.make_key(
            [gc.KeyTuple('ig_intr_md.ingress_port', ig_port1)])])


def program_entries(self, all_devtgt, all_pipes, all_ports, all_ttl, all_macs, all_ip, all_custom_tags):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports
    ig_ttl0, eg_ttl1, ig_ttl1, eg_ttl0 = all_ttl
    dmac, smac = all_macs
    dip, sip = all_ip
    ig_tag0, eg_tag1, ig_tag1, eg_tag0 = all_custom_tags
    meter_idx = 1
    color = 0

    logger.info("Programming table entries")

    logger.info(" Programming table entries on ingress pipe %d ", pipe0)
    logger.info("    Table: storm_control")
    self.a.storm_control_table.entry_add(
        target,
        [self.a.storm_control_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])],
        [self.a.storm_control_table.make_data(
            [gc.DataTuple('index', meter_idx)],
            'SwitchIngress_a.set_color')]
    )
    logger.info("    Table: stats")
    self.a.stats_table.entry_add(
        target,
        [self.a.stats_table.make_key(
            [gc.KeyTuple('qos_md.color', color),
             gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])],
        [self.a.stats_table.make_data([], "SwitchIngress_a.count")]
    )

    logger.info("    Table: forward")
    self.a.i_forward_table.entry_add(
        target,
        [self.a.i_forward_table.make_key(
            [gc.KeyTuple('hdr.ethernet.dst_addr', dmac),
             gc.KeyTuple('hdr.ipv4.ttl', ig_ttl0)])],
        [self.a.i_forward_table.make_data([], "SwitchIngress_a.hit")]
    )
    logger.info("    Table: encap_custom_metadata_hdr")
    self.a.encap_custom_metadata_hdr_table.entry_add(
        target,
        [self.a.encap_custom_metadata_hdr_table.make_key(
            [gc.KeyTuple('hdr.ethernet.$valid', 1)])],
        [self.a.encap_custom_metadata_hdr_table.make_data(
            [gc.DataTuple('tag', ig_tag0)],
            'SwitchIngress_a.encap_custom_metadata')]
    )

    logger.info(" Programming table entries on egress pipe %d ", pipe1)
    logger.info("    Table: forward")
    self.b.e_forward_table.entry_add(
        target,
        [self.b.e_forward_table.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', dip, prefix_len=31),
             gc.KeyTuple('hdr.ipv4.ttl', eg_ttl1),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag1)])],
        [self.b.e_forward_table.make_data([], 'SwitchEgress_b.hit')]
    )

    logger.info(" Programming table entries on ingress pipe %d ", pipe1)
    logger.info("    Table: forward")
    self.b.i_forward_table.entry_add(
        target,
        [self.b.i_forward_table.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', dip),
             gc.KeyTuple('hdr.ipv4.ttl', ig_ttl1),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', ig_tag1)])],
        [self.b.i_forward_table.make_data([], 'SwitchIngress_b.hit')]
    )
    # No need to program learning table as default action is to learn

    logger.info(" Programming table entries on egress pipe %d ", pipe0)
    logger.info("    Table: forward")
    self.a.e_forward_table.entry_add(
        target,
        [self.a.e_forward_table.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', dip, dip),
             gc.KeyTuple('hdr.ipv4.ttl', eg_ttl0, eg_ttl0),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag0, eg_tag0),
             gc.KeyTuple('$MATCH_PRIORITY', 0)])],
        [self.a.e_forward_table.make_data(
            [gc.DataTuple('$COUNTER_SPEC_BYTES', 0),
             gc.DataTuple('$COUNTER_SPEC_PKTS', 0)],
            'SwitchEgress_a.hit')]
    )

    logger.info("    Table: decap_custom_metadata_hdr")
    self.a.decap_custom_metadata_hdr_table.entry_add(
        target,
        [self.a.decap_custom_metadata_hdr_table.make_key(
            [gc.KeyTuple('hdr.custom_metadata.$valid', 1)])],
        [self.a.decap_custom_metadata_hdr_table.make_data(
            [],
            'SwitchEgress_a.decap_custom_metadata')]
    )


def delete_entries(self, all_devtgt, all_pipes, all_ports, all_ttl, all_macs, all_ip, all_custom_tags):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports
    ig_ttl0, eg_ttl1, ig_ttl1, eg_ttl0 = all_ttl
    dmac, smac = all_macs
    dip, sip = all_ip
    ig_tag0, eg_tag1, ig_tag1, eg_tag0 = all_custom_tags
    meter_idx = 1
    color = 0

    logger.info("Deleting table entries")

    logger.info(" Deleting table entries on ingress pipe %d ", pipe0)
    logger.info("    Table: storm_control")
    self.a.storm_control_table.entry_del(
        target,
        [self.a.storm_control_table.make_key(
            [gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])])

    logger.info("    Table: stats")
    self.a.stats_table.entry_del(
        target,
        [self.a.stats_table.make_key([gc.KeyTuple('qos_md.color', color),
                                      gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])])

    logger.info("    Table: forward")
    self.a.i_forward_table.entry_del(
        target,
        [self.a.i_forward_table.make_key(
            [gc.KeyTuple('hdr.ethernet.dst_addr', dmac),
             gc.KeyTuple('hdr.ipv4.ttl', ig_ttl0)])])

    logger.info("    Table: encap_custom_metadata_hdr")
    self.a.encap_custom_metadata_hdr_table.entry_del(
        target,
        [self.a.encap_custom_metadata_hdr_table.make_key(
            [gc.KeyTuple('hdr.ethernet.$valid', 1)])])

    logger.info(" Deleting table entries on egress pipe %d ", pipe1)
    logger.info("    Table: forward")
    self.b.e_forward_table.entry_del(
        target,
        [self.b.e_forward_table.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', dip, prefix_len=31),
             gc.KeyTuple('hdr.ipv4.ttl', eg_ttl1),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag1)])])

    logger.info(" Deleting table entries on ingress pipe %d ", pipe1)
    logger.info("    Table: forward")
    self.b.i_forward_table.entry_del(
        target,
        [self.b.i_forward_table.make_key([gc.KeyTuple('hdr.ipv4.dst_addr', dip),
                                          gc.KeyTuple('hdr.ipv4.ttl', ig_ttl1),
                                          gc.KeyTuple('hdr.custom_metadata.custom_tag', ig_tag1)])])

    logger.info(" Deleting table entries on %d egress pipe ", pipe0)
    logger.info("    Table: forward")
    self.a.e_forward_table.entry_del(
        target,
        [self.a.e_forward_table.make_key([gc.KeyTuple('hdr.ipv4.dst_addr', dip, dip),
                                          gc.KeyTuple('hdr.ipv4.ttl', eg_ttl0, eg_ttl0),
                                          gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag0, eg_tag0),
                                          gc.KeyTuple('$MATCH_PRIORITY', 0)])])

    logger.info("    Table: decap_custom_metadata_hdr")
    self.a.decap_custom_metadata_hdr_table.entry_del(
        target,
        [self.a.decap_custom_metadata_hdr_table.make_key(
            [gc.KeyTuple('hdr.custom_metadata.$valid', 1)])])


class MultiProgramTest(BaseTest):
    class ProgramA(BfRuntimeTest):
        def setUp(self, client_id, p4_name="tna_32q_multiprogram_a"):
            BfRuntimeTest.setUp(self, client_id, p4_name)

        def runTest(self):
            logger.info("")

        def tearDown(self):
            BfRuntimeTest.tearDown(self)

        def setUpTables(self):
            """@brief this function sets up a certain set of tables
                in the program tna_32q_multiprogram_a
            """
            self.bfrt_info = self.interface.bfrt_info_get("tna_32q_multiprogram_a")
            self.storm_control_table = self.bfrt_info.table_get("SwitchIngress_a.storm_control")
            self.stats_table = self.bfrt_info.table_get("SwitchIngress_a.stats")
            self.encap_custom_metadata_hdr_table = self.bfrt_info.table_get(
                "SwitchIngress_a.encap_custom_metadata_hdr")
            self.decap_custom_metadata_hdr_table = self.bfrt_info.table_get(
                "SwitchEgress_a.decap_custom_metadata_hdr")
            self.pinning_table = self.bfrt_info.table_get("SwitchIngress_a.pinning")
            self.i_forward_table = self.bfrt_info.table_get("SwitchIngress_a.forward")
            self.e_forward_table = self.bfrt_info.table_get("SwitchEgress_a.forward")

            self.i_forward_table.info.key_field_annotation_add("hdr.ethernet.dst_addr", "mac")
            self.e_forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")

    class ProgramB(BfRuntimeTest):
        def setUp(self, client_id, p4_name="tna_32q_multiprogram_b"):
            BfRuntimeTest.setUp(self, client_id, p4_name)

        def runTest(self):
            logger.info("")

        def tearDown(self):
            BfRuntimeTest.tearDown(self)

        def setUpTables(self):
            """@brief this function sets up a certain set of tables
                in the program tna_32q_multiprogram_b
            """
            self.bfrt_info = self.interface.bfrt_info_get("tna_32q_multiprogram_b")
            self.pinning_table = self.bfrt_info.table_get("SwitchIngress_b.pinning")
            self.i_forward_table = self.bfrt_info.table_get("SwitchIngress_b.forward")
            self.e_forward_table = self.bfrt_info.table_get("SwitchEgress_b.forward")

            self.i_forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
            self.e_forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")

    def setUp(self):
        # Open 2 connections to the grpc server as 2 separate clients. Client
        # 1 (self.a) is in-charge of program "tna_32q_multiprogram_a" while
        # client 2 (self.b) is in-charge of program "tna_32q_multiprogram_b"
        # Thus any operation on a table in tna_32q_multiprogram_a needs to be
        # called on self.a and any operation on a table in
        # tna_32q_multiprogram_b needs to be called on self.b
        self.a = self.ProgramA()
        self.b = self.ProgramB()
        self.a.setUp(1)
        self.b.setUp(2)

        self.a.setUpTables()
        self.b.setUpTables()

        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

    def tearDown(self):
        self.a.tearDown()
        self.b.tearDown()
        BaseTest.tearDown(self)

    def runTest(self):
        logger.info("")
        if test_param_get('target') == "hw":
            # Pal API not available in BRI, hard-code pipes till then
            ''' 
            # Get External pipe (should be either pipe 0 or 2, profileA)
            pipe0 = get_internal_or_external_pipe(self, 0)
            assert(pipe0 == 0 or pipe0 == 2)
            # Get Internal pipe (should be either pipe 1 or 3, profileB)
            pipe1 = get_internal_or_external_pipe(self, 1)
            assert(pipe1 == 1 or pipe1 == 3)
            '''
            pipe0 = 0
            pipe1 = 1
        else:
            pipe0 = 0
            pipe1 = 1

        logger.info("Pipe0 %d, Pipe1 %d", pipe0, pipe1)

        assert (pipe0 != pipe1)

        ig_port0, eg_port0 = get_ig_eg_ports_profA(pipe0)
        logger.info("ig_port0 %d, eg_port0 %d", ig_port0, eg_port0)

        ig_port1, eg_port1 = get_ig_eg_ports_profB(pipe1)
        logger.info("ig_port1 %d, eg_port1 %d", ig_port1, eg_port1)

        ig_ttl0 = 64
        eg_ttl1 = 63
        ig_ttl1 = 62
        eg_ttl0 = 61
        invalid_port = 511
        dmac = '22:33:44:55:66:77'
        smac = "00:11:22:33:44:55"
        dip = "5.6.7.8"
        sip = "1.2.3.4"
        ig_tag0 = 1
        eg_tag1 = 1  # Same as ig_tag0 as it is just set in ingress
        ig_tag1 = 2
        eg_tag0 = 3

        target = gc.Target(device_id=0, pipe_id=0xffff)
        all_devtgt = target
        all_pipes = pipe0, pipe1
        all_ports = ig_port0, eg_port0, ig_port1, eg_port1, invalid_port
        all_ttl = ig_ttl0, eg_ttl1, ig_ttl1, eg_ttl0
        all_macs = dmac, smac
        all_ip = dip, sip
        all_custom_tags = ig_tag0, eg_tag1, ig_tag1, eg_tag0

        # Program entries
        try:
            program_entries(self, all_devtgt, all_pipes, all_ports, all_ttl, all_macs, all_ip, all_custom_tags)
            program_pinning(self, all_devtgt, all_pipes, all_ports)

            logger.info("Sending packet on port %d", ig_port0)
            pkt = testutils.simple_tcp_packet(eth_dst=dmac,
                                              eth_src=smac,
                                              ip_src=sip,
                                              ip_dst=dip,
                                              ip_ttl=ig_ttl0)
            testutils.send_packet(self, ig_port0, pkt)

            pkt.ttl = pkt.ttl - 4
            exp_pkt = pkt
            logger.info("Expecting packet on port %d", eg_port0)
            testutils.verify_packets(self, exp_pkt, [eg_port0])

            verify_cntr_inc(self, all_devtgt, all_pipes, all_ports, all_ttl, all_macs, all_ip, all_custom_tags, 1)

        except Exception as e:
            logger.info("!!!!MultiProgram Test Failed!!!!")
            import traceback
            traceback.print_exc()
            raise e

        finally:
            delete_entries(self, all_devtgt, all_pipes, all_ports, all_ttl, all_macs, all_ip, all_custom_tags)
            delete_pinning(self, all_devtgt, all_pipes, all_ports)

            logger.info("")
            logger.info("Sending another packet on port %d", ig_port0)
            pkt = testutils.simple_tcp_packet(eth_dst=dmac,
                                              eth_src=smac,
                                              ip_src=sip,
                                              ip_dst=dip,
                                              ip_ttl=ig_ttl0)
            testutils.send_packet(self, ig_port0, pkt)

            logger.info("Packet is expected to get dropped.")
            testutils.verify_no_other_packets(self)

class MultiProgramFixedComponentTest(BaseTest):
    """@brief This test demonstrates accessing "fixed" tables through 2
        separate programs on the same device.
    """
    class ProgramA(BfRuntimeTest):
        def setUp(self, client_id, p4_name="tna_32q_multiprogram_a"):
            BfRuntimeTest.setUp(self, client_id, p4_name)

        def runTest(self):
            logger.info("")

        def tearDown(self):
            BfRuntimeTest.tearDown(self)

        def setUpTables(self):
            """@brief this function sets up a certain set of tables
                in the program tna_32q_multiprogram_a
            """
            self.bfrt_info = self.interface.bfrt_info_get("tna_32q_multiprogram_a")
            # Get all PRE table objects
            self.mgid_table = self.bfrt_info.table_get("$pre.mgid")
            self.node_table = self.bfrt_info.table_get("$pre.node")

    class ProgramB(BfRuntimeTest):
        def setUp(self, client_id, p4_name="tna_32q_multiprogram_b"):
            BfRuntimeTest.setUp(self, client_id, p4_name)

        def runTest(self):
            logger.info("")

        def tearDown(self):
            BfRuntimeTest.tearDown(self)

        def setUpTables(self):
            """@brief this function sets up a certain set of tables
                in the program tna_32q_multiprogram_b
            """
            self.bfrt_info = self.interface.bfrt_info_get("tna_32q_multiprogram_b")
            # Get all PRE table objects
            self.mgid_table = self.bfrt_info.table_get("$pre.mgid")
            self.node_table = self.bfrt_info.table_get("$pre.node")

    def addMgidEntry(self, program, target, mgid_list):
        key_list = []
        data_list = []
        for mgid in mgid_list:
            key_list.append(program.mgid_table.make_key(
                    [gc.KeyTuple('$MGID', (mgid & 0xFFFF))]))
            data_list.append(program.mgid_table.make_data([
                    gc.DataTuple('$MULTICAST_NODE_ID', int_arr_val=[]),
                    gc.DataTuple('$MULTICAST_NODE_L1_XID_VALID', bool_arr_val=[]),
                    gc.DataTuple('$MULTICAST_NODE_L1_XID', int_arr_val=[]),
                    gc.DataTuple('$MULTICAST_ECMP_ID', int_arr_val=[]),
                    gc.DataTuple('$MULTICAST_ECMP_L1_XID_VALID', bool_arr_val=[]),
                    gc.DataTuple('$MULTICAST_ECMP_L1_XID', int_arr_val=[])]))

        program.mgid_table.entry_add(target, key_list, data_list)
        return key_list, data_list

    def addNodeEntry(self, program, target, mgid_list, l2_node_ports_list):
        l1_id = 1
        key_list = []
        data_list = []
        for mgid in mgid_list:
            rid = (~mgid) & 0xFFFF
            key_list += [program.node_table.make_key([
                    gc.KeyTuple('$MULTICAST_NODE_ID', l1_id)])]
            data_list += [program.node_table.make_data([
                    gc.DataTuple('$MULTICAST_RID', rid),
                    gc.DataTuple('$MULTICAST_LAG_ID', int_arr_val=[]),
                    gc.DataTuple('$DEV_PORT', int_arr_val=l2_node_ports_list[l1_id-1])])]
            l1_id += 1
        program.node_table.entry_add(target, key_list, data_list)
        return key_list, data_list

    def getMgidEntry(self, program, target, verify_data_list, verify_key_list):
        resp = program.mgid_table.entry_get(target)
        i = 0
        for data, key in resp:
            assert data == verify_data_list[i], "Received %s expected %s" %(str(data), str(verify_data_list[i]))
            assert key == verify_key_list[i], "Received %s expected %s" %(str(key), str(verify_key_list[i]))
            i += 1
        assert i == len(verify_key_list), "Received %d, expected %d" % (i, len(verify_key_list))

    def getNodeEntry(self, program, target, verify_data_list, verify_key_list):
        resp = program.node_table.entry_get(target)
        i = 0
        for data, key in resp:
            assert data == verify_data_list[i], "Received %s expected %s" %(str(data), str(verify_data_list[i]))
            assert key == verify_key_list[i], "Received %s expected %s" %(str(key), str(verify_key_list[i]))
            i += 1
        assert i == len(verify_key_list), "Received %d, expected %d" % (i, len(verify_key_list))

    def clearTable(self, table, target):
        key_list = []
        resp = table.entry_get(target)
        for data, key in resp:
            key_list.append(key)
        for k in key_list:
            table.entry_del(target, [k])

    def setUp(self):
        # Open 2 connections to the grpc server as 2 separate clients. Client
        # 1 (self.a) is in-charge of program "tna_32q_multiprogram_a" while
        # client 2 (self.b) is in-charge of program "tna_32q_multiprogram_b"
        # Thus any operation on a table in tna_32q_multiprogram_a needs to be
        # called on self.a and any operation on a table in
        # tna_32q_multiprogram_b needs to be called on self.b
        self.a = self.ProgramA()
        self.b = self.ProgramB()
        self.a.setUp(1)
        self.b.setUp(2)

        self.a.setUpTables()
        self.b.setUpTables()


    def tearDown(self):
        print("Clearing tables")
        self.clearTable(self.b.mgid_table, self.target)
        self.clearTable(self.a.node_table, self.target)
        self.a.tearDown()
        self.b.tearDown()
        BaseTest.tearDown(self)

    def runTest(self):
        target = gc.Target(device_id=0, pipe_id=0xffff)
        self.target = target
        num_mgid = 20
        mgid_list = sorted(random.sample(range(0, 0x10000), num_mgid))
        l2_node_ports_list = [sorted(random.sample(swports, random.randint(0, len(swports)))) for mgid in mgid_list]

        # Add MGID entries though A
        # Add Node entries though B
        mgid_key_list, mgid_data_list = self.addMgidEntry(self.a, target, mgid_list)
        node_key_list, node_data_list = self.addNodeEntry(self.b, target, mgid_list, l2_node_ports_list)

        # Get and verify MGID entries though B
        self.getMgidEntry(self.b, target, mgid_data_list, mgid_key_list)
        # Get and Verify Node entries though A
        self.getNodeEntry(self.a, target, node_data_list, node_key_list)
