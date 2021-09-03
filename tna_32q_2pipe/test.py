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
import grpc

from ptf import config
from ptf.thriftutils import *
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
import codecs

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


def get_port_metadata_table_name(profile):
    if profile == 0:
        return "pipeline_profile_a.SwitchIngressParser_a.$PORT_METADATA"
    elif profile == 1:
        return "pipeline_profile_b.SwitchIngressParser_b.$PORT_METADATA"
    else:
        assert (0)


def to_bytes_right_pad(n):
    """ Convert integers to right padded bytearray """
    if testutils.test_param_get("arch") == "tofino":
        length = 8
    elif testutils.test_param_get("arch") == "tofino2":
        length = 16
    else:
        assert (0)
    h = '%x' % n
    s = codecs.decode(('0' * (len(h) % 2) + h).ljust(length * 2, '0'), "hex")
    return bytearray(s)


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


def get_internal_or_external_pipe(is_internal):
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


def verify_cntr_inc(test, all_devtgt, all_pipes, all_ports, all_ttl, all_macs, all_ip, all_custom_tags, num_pkts):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports
    ig_ttl0, eg_ttl1, ig_ttl1, eg_ttl0 = all_ttl
    dmac, smac = all_macs
    dip, sip = all_ip
    ig_tag0, eg_tag1, ig_tag1, eg_tag0 = all_custom_tags

    logger.info("Verifying counter got incremented on pipe0 egress")

    logger.info("  Get Table entry")
    resp = test.a_forward_e.entry_get(target,
                                      [test.a_forward_e.make_key(
                                          [gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(dip),
                                                       gc.ipv4_to_bytes(dip)),
                                           gc.KeyTuple('hdr.ipv4.ttl', eg_ttl0, eg_ttl0),
                                           gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag0, eg_tag0),
                                           gc.KeyTuple('$MATCH_PRIORITY', 0)])],
                                      {"from_hw": True},
                                      test.a_forward_e.make_data(
                                          [gc.DataTuple("$COUNTER_SPEC_BYTES"),
                                           gc.DataTuple("$COUNTER_SPEC_PKTS")],
                                          'SwitchEgress_a.hit',
                                          get=True))

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


def get_all_tables(test):
    test.a_pinning = test.bfrt_info.table_get("SwitchIngress_a.pinning")
    # Some of these tables can be retrieved using a lesser qualified name lke storm_control
    # since it is not present in any other control block of the P4 program like pinning or
    # or forward.
    test.a_storm_control = test.bfrt_info.table_get("storm_control")
    test.a_stats = test.bfrt_info.table_get("stats")
    test.a_forward_i = test.bfrt_info.table_get("SwitchIngress_a.forward")
    test.a_forward_e = test.bfrt_info.table_get("SwitchEgress_a.forward")
    test.a_encap = test.bfrt_info.table_get("encap_custom_metadata_hdr")
    test.a_decap = test.bfrt_info.table_get("decap_custom_metadata_hdr")

    test.b_pinning = test.bfrt_info.table_get("SwitchIngress_b.pinning")
    test.b_forward_i = test.bfrt_info.table_get("SwitchIngress_b.forward")
    test.b_forward_e = test.bfrt_info.table_get("SwitchEgress_b.forward")


def program_pinning(test, all_devtgt, all_pipes, all_ports):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports

    logger.info("Programming pinning entries")

    logger.info(" Programming pinning entries on ingress pipe %d ", pipe0)
    test.a_pinning.entry_add(
        target,
        [test.a_pinning.make_key([gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])],
        [test.a_pinning.make_data(
            [gc.DataTuple('port', eg_port1)],
            'SwitchIngress_a.modify_eg_port')])

    logger.info(" Programming pinning entries on ingress pipe %d ", pipe1)
    test.b_pinning.entry_add(
        target,
        [test.b_pinning.make_key([gc.KeyTuple('ig_intr_md.ingress_port', ig_port1)])],
        [test.b_pinning.make_data([gc.DataTuple('port', eg_port0)],
                                  'SwitchIngress_b.modify_eg_port')])


def delete_pinning(test, all_devtgt, all_pipes, all_ports):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports

    logger.info("Deleting pinning entries")

    logger.info(" Deleting pinning entries on ingress pipe %d ", pipe0)
    test.a_pinning.entry_del(
        target,
        [test.a_pinning.make_key([gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])])

    logger.info(" Deleting pinning entries on ingress pipe  %d ", pipe1)
    test.b_pinning.entry_del(
        target,
        [test.b_pinning.make_key([gc.KeyTuple('ig_intr_md.ingress_port', ig_port1)])])


def program_entries(test, all_devtgt, all_pipes, all_ports, all_ttl, all_macs, all_ip, all_custom_tags):
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
    test.a_storm_control.entry_add(
        target,
        [test.a_storm_control.make_key(
            [gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])],
        [test.a_storm_control.make_data(
            [gc.DataTuple('index', meter_idx)],
            'SwitchIngress_a.set_color')])

    logger.info("    Table: stats")
    test.a_stats.entry_add(
        target,
        [test.a_stats.make_key(
            [gc.KeyTuple('qos_md.color', color),
             gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])],
        [test.a_stats.make_data([], "SwitchIngress_a.count")])

    logger.info("    Table: forward")
    test.a_forward_i.entry_add(
        target,
        [test.a_forward_i.make_key(
            [gc.KeyTuple('hdr.ethernet.dst_addr', gc.mac_to_bytes(dmac)),
             gc.KeyTuple('hdr.ipv4.ttl', ig_ttl0)])],
        [test.a_forward_i.make_data([], 'SwitchIngress_a.hit')])

    logger.info("    Table: encap_custom_metadata_hdr")
    test.a_encap.entry_add(
        target,
        [test.a_encap.make_key(
            [gc.KeyTuple('hdr.ethernet.$valid', 1)])],
        [test.a_encap.make_data(
            [gc.DataTuple('tag', ig_tag0)],
            'SwitchIngress_a.encap_custom_metadata')])

    logger.info(" Programming table entries on egress pipe %d ", pipe1)
    logger.info("    Table: forward")
    test.b_forward_e.entry_add(
        target,
        [test.b_forward_e.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(dip), prefix_len=31),
             gc.KeyTuple('hdr.ipv4.ttl', eg_ttl1),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag1)])],
        [test.b_forward_e.make_data([], "SwitchEgress_b.hit")])

    logger.info(" Programming table entries on ingress pipe %d ", pipe1)
    logger.info("    Table: forward")
    test.b_forward_i.entry_add(
        target,
        [test.b_forward_i.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(dip)),
             gc.KeyTuple('hdr.ipv4.ttl', ig_ttl1),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', ig_tag1)])],
        [test.b_forward_i.make_data([], "SwitchIngress_b.hit")])

    # No need to program learning table as default action is to learn
    logger.info(" Programming table entries on egress pipe %d ", pipe0)
    logger.info("    Table: forward")
    test.a_forward_e.entry_add(
        target,
        [test.a_forward_e.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(dip), gc.ipv4_to_bytes(dip)),
             gc.KeyTuple('hdr.ipv4.ttl', eg_ttl0, eg_ttl0),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag0, eg_tag0),
             gc.KeyTuple('$MATCH_PRIORITY', 0)])],
        [test.a_forward_e.make_data(
            [gc.DataTuple('$COUNTER_SPEC_BYTES', 0),
             gc.DataTuple('$COUNTER_SPEC_PKTS', 0)],
            'SwitchEgress_a.hit')])

    logger.info("    Table: decap_custom_metadata_hdr")
    test.a_decap.entry_add(
        target,
        [test.a_decap.make_key(
            [gc.KeyTuple('hdr.custom_metadata.$valid', 1)])],
        [test.a_decap.make_data([], 'SwitchEgress_a.decap_custom_metadata')])


def delete_entries(test, all_devtgt, all_pipes, all_ports, all_ttl, all_macs, all_ip, all_custom_tags):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports
    ig_ttl0, eg_ttl1, ig_ttl1, eg_ttl0 = all_ttl
    dmac, smac = all_macs
    dip, sip = all_ip
    ig_tag0, eg_tag1, ig_tag1, eg_tag0 = all_custom_tags
    color = 0

    logger.info("Deleting table entries")

    logger.info(" Deleting table entries on ingress pipe %d ", pipe0)
    logger.info("    Table: storm_control")
    test.a_storm_control.entry_del(
        target,
        [test.a_storm_control.make_key(
            [gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])])

    logger.info("    Table: stats")
    test.a_stats.entry_del(
        target,
        [test.a_stats.make_key(
            [gc.KeyTuple('qos_md.color', color),
             gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])])

    logger.info("    Table: forward")
    test.a_forward_i.entry_del(
        target,
        [test.a_forward_i.make_key(
            [gc.KeyTuple('hdr.ethernet.dst_addr', gc.mac_to_bytes(dmac)),
             gc.KeyTuple('hdr.ipv4.ttl', ig_ttl0)])])

    logger.info("    Table: encap_custom_metadata_hdr")
    test.a_encap.entry_del(
        target,
        [test.a_encap.make_key(
            [gc.KeyTuple('hdr.ethernet.$valid', 1)])])

    logger.info(" Deleting table entries on egress pipe %d ", pipe1)
    logger.info("    Table: forward")
    test.b_forward_e.entry_del(
        target,
        [test.b_forward_e.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(dip), prefix_len=31),
             gc.KeyTuple('hdr.ipv4.ttl', eg_ttl1),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag1)])])

    logger.info(" Deleting table entries on ingress pipe %d ", pipe1)
    logger.info("    Table: forward")
    test.b_forward_i.entry_del(
        target,
        [test.b_forward_i.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(dip)),
             gc.KeyTuple('hdr.ipv4.ttl', ig_ttl1),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', ig_tag1)])])

    logger.info(" Deleting table entries on %d egress pipe ", pipe0)
    logger.info("    Table: forward")
    test.a_forward_e.entry_del(
        target,
        [test.a_forward_e.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(dip), gc.ipv4_to_bytes(dip)),
             gc.KeyTuple('hdr.ipv4.ttl', eg_ttl0, eg_ttl0),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag0, eg_tag0),
             gc.KeyTuple('$MATCH_PRIORITY', 0)])])

    logger.info("    Table: decap_custom_metadata_hdr")
    test.a_decap.entry_del(
        target,
        [test.a_decap.make_key([gc.KeyTuple('hdr.custom_metadata.$valid', 1)])])


# Symmetric table test. Program tables in both pipeline profiles symmetrically.
# Send packet on pipe 0 ingress and expect it to go to pipe 1 and then finally
# egress on pipe 0 egress.
# Pipe0 ingrss -> Pipe 1 Egress -> Pipe 1 Ingress -> Pipe 0 Egress
class Sym32Q(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        p4_name = "tna_32q_2pipe"
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def runTest(self):
        logger.info("")
        if testutils.test_param_get('target') == "hw":
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

        # Get bfrt_info and set it as part of the test
        self.bfrt_info = self.interface.bfrt_info_get("tna_32q_2pipe")

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

        get_all_tables(self)
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


class PortMetadataTest(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        p4_name = "tna_32q_2pipe"
        BfRuntimeTest.setUp(self, client_id, p4_name)
        self.target = gc.Target(device_id=0, pipe_id=0xffff)

    def runTest(self):
        # Get bfrt_info and set it as part of the test
        bfrt_info = self.interface.bfrt_info_get("tna_32q_2pipe")

        # Try Adding entry in a port in profile a
        igr_port, egr_port = get_ig_eg_ports_profA(0)
        phase0data = 0x1122334455667788
        phase0data_padded = to_bytes_right_pad(phase0data)
        logger.info("Adding PORT_METADATA table entry for igr port %d in profile A", igr_port)
        pmtable_1 = bfrt_info.table_get(get_port_metadata_table_name(0))
        pmtable_1.info.data_field_annotation_add("$DEFAULT_FIELD", None, "bytes")
        pmtable_1.entry_add(
            self.target,
            [pmtable_1.make_key([gc.KeyTuple("ig_intr_md.ingress_port", igr_port)])],
            [pmtable_1.make_data([gc.DataTuple("$DEFAULT_FIELD", phase0data_padded)])])

        # Read and verify the entry
        resp = pmtable_1.entry_get(self.target,
                                   [pmtable_1.make_key([gc.KeyTuple("ig_intr_md.ingress_port", igr_port)])],
                                   {"from_hw": True})
        fields = next(resp)[0].to_dict()
        logger.info("Verifying entry for igr port in profile a %d", igr_port)
        recv_data = fields["$DEFAULT_FIELD"]
        assert recv_data == phase0data_padded, "Exp data : %s : Rcv data : %s" \
                                               % (phase0data_padded, recv_data)

        # Now Try Adding entry in a port in profile b
        igr_port, egr_port = get_ig_eg_ports_profB(1)
        phase0data = 0x8877665544332211
        phase0data_padded = to_bytes_right_pad(phase0data)

        pmtable_2 = bfrt_info.table_get(get_port_metadata_table_name(1))
        pmtable_2.info.data_field_annotation_add("$DEFAULT_FIELD", None, "bytes")
        logger.info("Adding PORT_METADATA table entry for igr port %d in profile B", igr_port)
        pmtable_2.entry_add(
            self.target,
            [pmtable_2.make_key([gc.KeyTuple("ig_intr_md.ingress_port", igr_port)])],
            [pmtable_2.make_data([gc.DataTuple('$DEFAULT_FIELD', phase0data_padded)])])

        # Read and verify the entry
        resp = pmtable_2.entry_get(self.target,
                                   [pmtable_2.make_key([gc.KeyTuple("ig_intr_md.ingress_port", igr_port)])],
                                   {"from_hw": True})
        fields = next(resp)[0].to_dict()
        logger.info("Verifying entry for igr port in profile b %d", igr_port)
        recv_data = fields["$DEFAULT_FIELD"]
        assert recv_data == phase0data_padded, "Exp data : %s : Rcv data : %s" \
                                               % (phase0data_padded, recv_data)
