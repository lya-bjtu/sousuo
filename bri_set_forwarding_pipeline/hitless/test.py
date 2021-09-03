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
from ptf.testutils import *
from bfruntime_client_base_tests import BfRuntimeTest, BaseTest
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc
import scapy.all

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

base_pick_path = testutils.test_param_get("base_pick_path")
binary_name = testutils.test_param_get("arch")
if binary_name is not "tofino2" and binary_name is not "tofino":
    assert 0, "%s is unknown arch" % (binary_name)

if not base_pick_path:
    base_pick_path = "install/share/" + binary_name + "pd/"

base_put_path = testutils.test_param_get("base_put_path")
if not base_put_path:
    base_put_path = "install/share/" + binary_name + "pd/forwarding"

logger.info("\nbase_put_path=%s \nbase_pick_path=%s", base_pick_path, base_put_path)

swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)
    swports.sort()

if swports == []:
    swports = range(9)

swports_0 = []
swports_1 = []
swports_2 = []
swports_3 = []
def port_to_pipe(port):
    local_port = port & 0x7F
    assert (local_port < 72)
    pipe = (port >> 7) & 0x3
    assert (port == ((pipe << 7) | local_port))
    return pipe
# the following method categorizes the ports in ports.json file as belonging to either of the pipes (0, 1, 2, 3)
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

def create_path_bf_rt(base_path, p4_name_to_use):
    return base_path + "/" + p4_name_to_use + "/bf-rt.json"
def create_path_context(base_path, p4_name_to_use, profile_name):
    return base_path + "/" + p4_name_to_use + "/" + profile_name + "/context.json"
def create_path_tofino(base_path, p4_name_to_use, profile_name):
    return base_path + "/" + p4_name_to_use + "/" + profile_name + "/" + binary_name + ".bin"

def put_program_on_device(test):
    if not test.p4_name:
        test.p4_name = "tna_exact_match"
    p4_name_to_put = p4_name_to_pick = test.p4_name
    profile_name_to_put = "pipe"
    profile_name_to_pick = "pipe"

    logger.info("Sending Verify and warm_init_begin and warm_init_end for %s", p4_name_to_put)
    action = bfruntime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_WARM_INIT_BEGIN_AND_END
    success = test.interface.send_set_forwarding_pipeline_config_request( \
        action,
        base_put_path,
        [gc.ForwardingConfig(p4_name_to_put,
                             create_path_bf_rt(base_pick_path, p4_name_to_pick),
                             [gc.ProfileInfo(profile_name_to_put,
                                             create_path_context(base_pick_path, p4_name_to_pick,
                                                                 profile_name_to_pick),
                                             create_path_tofino(base_pick_path, p4_name_to_pick,
                                                                profile_name_to_pick),
                                             [0, 1, 2, 3])]
                             )])
    if not success:
        raise RuntimeError("Failed to setFwd")
    test.interface.bind_pipeline_config(test.p4_name)

def start_hitless(test):
    logger.info("Start warm init hitless")
    if not test.p4_name:
        test.p4_name = "tna_exact_match"
    p4_name_to_put = p4_name_to_pick = test.p4_name 
    profile_name_to_put = "pipe"
    profile_name_to_pick = "pipe"
    config_list = [\
        gc.ForwardingConfig(p4_name_to_put,
            create_path_bf_rt(base_pick_path, p4_name_to_pick),
            [gc.ProfileInfo(profile_name_to_put,
                create_path_context(base_pick_path, p4_name_to_pick, profile_name_to_pick),
                create_path_tofino(base_pick_path, p4_name_to_pick, profile_name_to_pick),
                [0,1,2,3])]
        )
    ]
    action = bfruntime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_WARM_INIT_BEGIN
    init_mode = bfruntime_pb2.SetForwardingPipelineConfigRequest.HITLESS
    success = test.interface.send_set_forwarding_pipeline_config_request(\
            action,
            base_put_path,
            config_list,
            dev_init_mode=init_mode,
            timeout = 30)
    if not success:
        raise RuntimeError("Failed to get response for setfwd")

def end_hitless(test):
    logger.info("warm init hitless end")
    action = bfruntime_pb2.SetForwardingPipelineConfigRequest.WARM_INIT_END
    success = test.interface.send_set_forwarding_pipeline_config_request(\
            action,
            base_put_path,
            timeout = 20)
    if not success:
        raise RuntimeError("Failed to get response for setfwd")


class HitlessBaseTest(BfRuntimeTest):
    '''
    This acts as the Base test for all HA tests and provides the following template
    to write HA tests.
    setUp()
    1. Client Subscribes to server with master privileges
    2. Send a SetForwardingPipelineConfig msg to put the program on the device first
    3. Wait for WARM_INIT_FINISHED
    runTest()
    4. BINDS to program with SetForwardingPipelineConfig msg
    5. Add entries, send traffic
    6. Send a WARM_INIT_BEGIN SetForwardingPipelineConfig msg with HITLESS
    7. Wait for WARM_INIT_STARTED
    8. Replay entries
    9. Send a WARM_INIT_END msg and wait for WARM_INIT_FINISHED
    10. verify entries, Send traffic
    '''
    def setup_tables(self):
        pass

    def setup_test_data(self):
        pass

    def add_entries(self):
        pass

    def send_traffic(self):
        pass

    def replay_entries(self):
        logger.info("replaying entries")
        self.add_entries()

    def get_entries_and_verify(self):
        pass

    def setUp(self):
        self.client_id = 0
        # Setup as master
        BfRuntimeTest.setUp(self, self.client_id, is_master=True, perform_bind=False)
        # Send a Verify_and_warm_init_begin_and_end
        put_program_on_device(self)

        # set up tables
        self.bfrt_info = self.interface.bfrt_info_get()

        self.seed = random.randint(0, 65535)
        logger.info("Seed used  %d", self.seed)
        random.seed(self.seed)

    def runTest(self):
        self.setup_tables()
        self.setup_test_data()

        self.add_entries()
        self.send_traffic()
        self.get_entries_and_verify()

        start_hitless(self)
        self.replay_entries()
        end_hitless(self)

        self.get_entries_and_verify()
        self.send_traffic()

class HitlessTnaExactMatch(HitlessBaseTest):

    def setup_tables(self):
        self.forward_table = self.bfrt_info.table_get("SwitchIngress.forward")
        self.forward_table.info.key_field_annotation_add("hdr.ethernet.dst_addr", "mac")

    def setup_test_data(self):
        self.dmac = '22:22:22:22:22:22'
        self.ig_port = swports[1]
        self.eg_port = swports[2]
        self.target = gc.Target(device_id=0, pipe_id=0xffff)

    def add_entries(self):
        key_list = [self.forward_table.make_key([gc.KeyTuple('hdr.ethernet.dst_addr', self.dmac)])]
        data_list = [self.forward_table.make_data([gc.DataTuple('port', self.eg_port)],
                                             "SwitchIngress.hit")]
        self.forward_table.entry_add(self.target, key_list, data_list)

    def send_traffic(self):
        pkt = testutils.simple_tcp_packet(eth_dst=self.dmac)
        exp_pkt = pkt
        logger.info("Sending packet on port %d", self.ig_port)
        testutils.send_packet(self, self.ig_port, str(pkt))
        logger.info("Expecting packet on port %d", self.eg_port)
        testutils.verify_packets(self, exp_pkt, [self.eg_port])

    def get_entries_and_verify(self):
        resp = self.forward_table.entry_get(self.target)
        for data, key in resp:
            data_dict = data.to_dict()
            key_dict = key.to_dict()
            assert data_dict["port"] == self.eg_port
            assert key_dict["hdr.ethernet.dst_addr"]["value"] == self.dmac

    def setUp(self):
        self.p4_name = "tna_exact_match"
        HitlessBaseTest.setUp(self)


class HitlessTnaExactMatchEntryUserDefinedScope(HitlessBaseTest):
    '''
    Test User defined Scope asymmetric Match table
    '''

    def setup_tables(self):
        self.forward_table = self.bfrt_info.table_get("SwitchIngress.forward")
        self.forward_table.info.key_field_annotation_add("hdr.ethernet.dst_addr", "mac")

    def setup_test_data(self):
        self.dmac = '22:22:22:22:22:22'
        self.ig_port = swports[1]
        self.eg_port = swports[2]
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.target0 = gc.Target(device_id=0, pipe_id=0x00)
        # Set pipes 0 and 1 in scope 1 and pipes 2 and 3 in scope 2
        # Note this cannot be done during replay again, since
        # "changing" entry scope while entries are present isn't
        # allowed.
        self.forward_table.attribute_entry_scope_set(self.target,
                predefined_pipe_scope=False, user_defined_pipe_scope_val=0xc03)

    def add_entries(self):
        key_list = [self.forward_table.make_key([gc.KeyTuple('hdr.ethernet.dst_addr', self.dmac)])]
        data_list = [self.forward_table.make_data([gc.DataTuple('port', self.eg_port)],
                                             "SwitchIngress.hit")]
        self.forward_table.entry_add(self.target0, key_list, data_list)

    def send_traffic(self):
        def send_and_verify_packet(self, ingress_port, egress_port, pkt, exp_pkt):
            logger.info("Sending packet on port %d", ingress_port)
            testutils.send_packet(self, ingress_port, pkt)
            logger.info("Expecting packet on port %d", egress_port)
            testutils.verify_packet(self, exp_pkt, egress_port)

        def send_and_verify_no_other_packet(self, ingress_port, pkt):
            logger.info("Sending packet on port %d (negative test); expecting no packet", ingress_port)
            testutils.send_packet(self, ingress_port, pkt)
            testutils.verify_no_other_packets(self)
        pkt = testutils.simple_tcp_packet(eth_dst=self.dmac)
        exp_pkt = pkt
        # Since we have installed the entry in scope 1 (pipe 0 and 1) only,
        # we expect the packet to hit the entries in pipes 0 and 1
        # and miss in pipes 2 and 3
        send_and_verify_packet(self, swports_0[0], self.eg_port, pkt, exp_pkt)
        send_and_verify_packet(self, swports_0[1], self.eg_port, pkt, exp_pkt)
        send_and_verify_packet(self, swports_0[2], self.eg_port, pkt, exp_pkt)
        send_and_verify_packet(self, swports_1[1], self.eg_port, pkt, exp_pkt)
        send_and_verify_packet(self, swports_1[2], self.eg_port, pkt, exp_pkt)
        send_and_verify_no_other_packet(self, swports_2[0], pkt)
        send_and_verify_no_other_packet(self, swports_3[0], pkt)

    def get_entries_and_verify(self):
        resp = self.forward_table.attribute_get(self.target, "EntryScope")
        for d in resp:
            logger.info("received %s", str(d))
            assert d["gress_scope"]["predef"] == bfruntime_pb2.Mode.ALL
            assert "predef" not in d["pipe_scope"]
            assert d["pipe_scope"]["user_defined"] == 0xc03
            assert d["prsr_scope"]["predef"] == bfruntime_pb2.Mode.ALL
        resp = self.forward_table.entry_get(self.target)
        for data, key in resp:
            data_dict = data.to_dict()
            key_dict = key.to_dict()
            assert data_dict["port"] == self.eg_port
            assert key_dict["hdr.ethernet.dst_addr"]["value"] == self.dmac


    def runTest(self):
        ######## Disabling this test. Remove this function to enable back #########
        pass

    def setUp(self):
        self.p4_name = "tna_exact_match"
        HitlessBaseTest.setUp(self)

class HitlessTnaExactMatchEntrySingleScope(HitlessBaseTest):
    '''
    Test only Single Scope asymmetric Match table
    '''

    def setup_tables(self):
        self.forward_table = self.bfrt_info.table_get("SwitchIngress.forward")
        self.forward_table.info.key_field_annotation_add("hdr.ethernet.dst_addr", "mac")

    def setup_test_data(self):
        self.dmac = '22:22:22:22:22:22'
        self.ig_port = swports[1]
        self.eg_port = swports[2]
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.target0 = gc.Target(device_id=0, pipe_id=0x00)
        # Set all pipes to be in different scopes. Also known as Single scope
        self.forward_table.attribute_entry_scope_set(self.target,
                predefined_pipe_scope=True,
                predefined_pipe_scope_val=bfruntime_pb2.Mode.SINGLE)

    def add_entries(self):
        key_list = [self.forward_table.make_key([gc.KeyTuple('hdr.ethernet.dst_addr', self.dmac)])]
        data_list = [self.forward_table.make_data([gc.DataTuple('port', self.eg_port)],
                                             "SwitchIngress.hit")]
        self.forward_table.entry_add(self.target0, key_list, data_list)

    def send_traffic(self):
        def send_and_verify_packet(self, ingress_port, egress_port, pkt, exp_pkt):
            logger.info("Sending packet on port %d", ingress_port)
            testutils.send_packet(self, ingress_port, pkt)
            logger.info("Expecting packet on port %d", egress_port)
            testutils.verify_packet(self, exp_pkt, egress_port)

        def send_and_verify_no_other_packet(self, ingress_port, pkt):
            logger.info("Sending packet on port %d (negative test); expecting no packet", ingress_port)
            testutils.send_packet(self, ingress_port, pkt)
            testutils.verify_no_other_packets(self)
        pkt = testutils.simple_tcp_packet(eth_dst=self.dmac)
        exp_pkt = pkt
        # Since we have installed the entry in pipe0 only as single scope, we expect
        # the packet to get dropped in pther pipes
        send_and_verify_packet(self, swports_0[0], self.eg_port, pkt, exp_pkt)
        send_and_verify_packet(self, swports_0[1], self.eg_port, pkt, exp_pkt)
        send_and_verify_packet(self, swports_0[2], self.eg_port, pkt, exp_pkt)
        send_and_verify_no_other_packet(self, swports_1[1], pkt)
        send_and_verify_no_other_packet(self, swports_1[2], pkt)
        send_and_verify_no_other_packet(self, swports_2[0], pkt)
        send_and_verify_no_other_packet(self, swports_3[0], pkt)

    def get_entries_and_verify(self):
        resp = self.forward_table.attribute_get(self.target, "EntryScope")
        for d in resp:
            logger.info("received %s", str(d))
            assert d["gress_scope"]["predef"] == bfruntime_pb2.Mode.ALL
            assert d["pipe_scope"]["predef"] == bfruntime_pb2.Mode.SINGLE
            assert d["prsr_scope"]["predef"] == bfruntime_pb2.Mode.ALL
        resp = self.forward_table.entry_get(self.target)
        for data, key in resp:
            data_dict = data.to_dict()
            key_dict = key.to_dict()
            assert data_dict["port"] == self.eg_port
            assert key_dict["hdr.ethernet.dst_addr"]["value"] == self.dmac


    def setUp(self):
        self.p4_name = "tna_exact_match"
        HitlessBaseTest.setUp(self)

class HitlessTnaTernaryMatch(HitlessBaseTest):
    '''
    '''

    def setup_tables(self):
        self.forward_table = self.bfrt_info.table_get("SwitchIngress.forward")
        self.forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")

    def setup_test_data(self):
        tuple_list = []
        self.ig_port = swports[1]
        self.eg_port = swports[2]
        self.key_list = []
        self.data_list = []
        self.num_entries = 100
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.ip_random_list = self.generate_random_ip_list(self.num_entries, self.seed)
        prio = random.randint(1, 5000)
        for i in range(self.num_entries):
            self.key_list.append(
                    self.forward_table.make_key(
                        [gc.KeyTuple('$MATCH_PRIORITY', prio),
                         gc.KeyTuple('vrf', 0),
                         gc.KeyTuple('hdr.ipv4.dst_addr', getattr(self.ip_random_list[i], "ip"), getattr(self.ip_random_list[i], "mask"))]))

            self.data_list.append(self.forward_table.make_data([gc.DataTuple('port', self.eg_port)],
                                                         'SwitchIngress.hit'))

    def add_entries(self):
        self.forward_table.entry_add(self.target, self.key_list, self.data_list)

    def send_traffic(self):
        def send_and_verify_packet(self, ingress_port, egress_port, pkt, exp_pkt):
            testutils.send_packet(self, ingress_port, pkt)
            testutils.verify_packet(self, exp_pkt, egress_port)

        logger.info("Sending traffic")
        for i in range(self.num_entries):
            dst_ip = self.key_list[i].to_dict()["hdr.ipv4.dst_addr"]["value"]
            pkt = testutils.simple_tcp_packet(ip_dst=dst_ip)
            exp_pkt = pkt
            send_and_verify_packet(self, self.ig_port, self.eg_port, pkt, exp_pkt)

    def get_entries_and_verify(self):
        resp = self.forward_table.entry_get(self.target)
        i=0
        for data, key in resp:
            self.key_list[i].apply_mask()
            assert key == self.key_list[i], "received %s expected %s" %(str(key), str(self.key_list[i]))
            assert data == self.data_list[i]
            i+=1

    def setUp(self):
        self.p4_name = "tna_ternary_match"
        HitlessBaseTest.setUp(self)

class HitlessTnaTernaryMatchAtcam(HitlessBaseTest):
    '''
    '''

    def setup_tables(self):
        self.forward_atcam_table = self.bfrt_info.table_get("SwitchIngress.forward_atcam")
        self.set_partition_table = self.bfrt_info.table_get("SwitchIngress.set_partition")
        self.forward_atcam_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")

    def setup_test_data(self):
        tuple_list = []
        self.ig_port = swports[1]
        self.eg_port = swports[2]
        self.key_list_1 = []
        self.key_list_2 = []
        self.data_list = []
        self.num_entries = 30
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.ip_random_list = self.generate_random_ip_list(self.num_entries, self.seed)
        self.atcam_dict = {}
        for i in range(self.num_entries):
            self.key_list_1.append(
                    self.forward_atcam_table.make_key(
                        [gc.KeyTuple('$MATCH_PRIORITY', 0),
                         gc.KeyTuple('ig_md.partition.partition_index', 3),
                         gc.KeyTuple('hdr.ipv4.dst_addr', getattr(self.ip_random_list[i], "ip"), getattr(self.ip_random_list[i], "mask"))]))
            self.key_list_2.append(
                    self.forward_atcam_table.make_key(
                        [gc.KeyTuple('$MATCH_PRIORITY', 0),
                         gc.KeyTuple('ig_md.partition.partition_index', 1),
                         gc.KeyTuple('hdr.ipv4.dst_addr', getattr(self.ip_random_list[i], "ip"), getattr(self.ip_random_list[i], "mask"))]))


            self.data_list.append(self.forward_atcam_table.make_data([gc.DataTuple('port', self.eg_port)], 'SwitchIngress.hit'))
            self.key_list_1[-1].apply_mask()
            self.key_list_2[-1].apply_mask()
            self.atcam_dict[self.key_list_1[-1]] = self.data_list[-1]
            self.atcam_dict[self.key_list_2[-1]] = self.data_list[-1]
        self.partition_key_1 = self.set_partition_table.make_key([gc.KeyTuple('hdr.ipv4.protocol', 6)])
        self.partition_data_1 = self.set_partition_table.make_data([gc.DataTuple('p_index', 3)], 'SwitchIngress.init_index')
        self.partition_key_2 = self.set_partition_table.make_key([gc.KeyTuple('hdr.ipv4.protocol', 17)])
        self.partition_data_2 = self.set_partition_table.make_data([gc.DataTuple('p_index', 1)], 'SwitchIngress.init_index')

    def add_entries(self):
        self.set_partition_table.entry_add(self.target, [self.partition_key_1], [self.partition_data_1])
        self.set_partition_table.entry_add(self.target, [self.partition_key_2], [self.partition_data_2])

        self.forward_atcam_table.entry_add(self.target, self.key_list_1, self.data_list)
        self.forward_atcam_table.entry_add(self.target, self.key_list_2, self.data_list)

    def send_traffic(self):
        def send_and_verify_packet(self, ingress_port, egress_port, pkt, exp_pkt):
            testutils.send_packet(self, ingress_port, pkt)
            testutils.verify_packet(self, exp_pkt, egress_port)

        logger.info("Sending traffic")
        for i in range(self.num_entries):
            dst_ip = self.key_list_1[i].to_dict()["hdr.ipv4.dst_addr"]["value"]
            pkt = testutils.simple_tcp_packet(ip_dst=dst_ip)
            exp_pkt = pkt
            send_and_verify_packet(self, self.ig_port, self.eg_port, pkt, exp_pkt)

            dst_ip = self.key_list_2[i].to_dict()["hdr.ipv4.dst_addr"]["value"]
            pkt = testutils.simple_tcp_packet(ip_dst=dst_ip)
            exp_pkt = pkt
            send_and_verify_packet(self, self.ig_port, self.eg_port, pkt, exp_pkt)


    def get_entries_and_verify(self):
        resp = self.forward_atcam_table.entry_get(self.target)
        atcam_dict = self.atcam_dict.copy()
        for data, key in resp:
            assert atcam_dict[key] == data
            atcam_dict.pop(key)
        assert len(atcam_dict) == 0

    def setUp(self):
        self.p4_name = "tna_ternary_match"
        HitlessBaseTest.setUp(self)


class HitlessTnaTernaryMatchIndirect(HitlessBaseTest):
    '''
    HA test for ternary indirect match table
    P4 program = tna_ternary_match
    '''

    def setup_tables(self):
        self.action_profile_table = self.bfrt_info.table_get("SwitchIngress.action_profile")
        self.tcam_direct_lpf_table = self.bfrt_info.table_get("SwitchIngress.tcam_direct_lpf")
        self.action_profile_table.info.data_field_annotation_add("srcAddr", "SwitchIngress.change_ipsrc", "ipv4")
        self.action_profile_table.info.data_field_annotation_add("dstAddr", "SwitchIngress.change_ipdst", "ipv4")
        self.tcam_direct_lpf_table.info.key_field_annotation_add("hdr.ethernet.dst_addr", "mac")
        self.tcam_direct_lpf_table.info.key_field_annotation_add("hdr.ethernet.src_addr", "mac")

    def setup_test_data(self):
        logger.info("Setting up test data")
        tuple_list = []
        self.num_entries = 100

        self.ig_ports = [random.choice(swports) for x in range(self.num_entries)]
        self.all_ports = swports_0 + swports_1 + swports_2 + swports_3
        self.eg_ports = [random.choice(self.all_ports) for x in range(self.num_entries)]
        self.action_key_list = []
        self.action_data_list = []
        self.tcam_key_list = []
        self.tcam_data_list = []

        self.srcMac_dict = {}
        self.dstMac_dict = {}
        self.srcMacAddrs = []
        self.dstMacAddrs = []
        self.srcMacAddrsMask = []
        self.dstMacAddrsMask = []
        self.priorities = [x for x in range(self.num_entries)]
        random.shuffle(self.priorities)

        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        action_choices = ['SwitchIngress.change_ipsrc', 'SwitchIngress.change_ipdst']
        self.action = [action_choices[random.randint(0, 1)] for x in range(self.num_entries)]

        self.action_mbr_ids = [x + 1 for x in range(self.num_entries)]

        self.ipDstAddrs = ["%d.%d.%d.%d" % (
            random.randint(1, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)) for x in
            range(self.num_entries)]
        self.ipSrcAddrs = ["%d.%d.%d.%d" % (
            random.randint(1, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)) for x in
            range(self.num_entries)]

        self.lpf_types = [random.choice(["RATE", "SAMPLE"]) for x in range(self.num_entries)]

        self.gain_time = [round(random.uniform(1, 1000), 2) for x in range(self.num_entries)]
        self.decay_time = self.gain_time
        self.out_scale = [random.randint(1, 31) for x in range(self.num_entries)]

        self.srcMacAddrtuple = self.generate_random_mac_list(self.num_entries, self.seed)
        self.dstMacAddrtuple = self.generate_random_mac_list(self.num_entries, self.seed)

        self.srcMacAddrs = [getattr(each, "mac") for each in self.srcMacAddrtuple]
        self.srcMacAddrsMask = [getattr(each, "mask") for each in self.srcMacAddrtuple]

        self.dstMacAddrs = [getattr(each, "mac") for each in self.dstMacAddrtuple]
        self.dstMacAddrsMask = [getattr(each, "mask") for each in self.dstMacAddrtuple]

        for x in range(self.num_entries):
            if self.action[x] == 'SwitchIngress.change_ipsrc':
                self.action_key_list += [self.action_profile_table.make_key([gc.KeyTuple('$ACTION_MEMBER_ID', self.action_mbr_ids[x])])]
                self.action_data_list += [self.action_profile_table.make_data([gc.DataTuple('dst_port', self.eg_ports[x]),
                                                     gc.DataTuple('srcAddr', self.ipSrcAddrs[x])],
                                                    'SwitchIngress.change_ipsrc')]
            elif self.action[x] == 'SwitchIngress.change_ipdst':
                self.action_key_list += [self.action_profile_table.make_key([gc.KeyTuple('$ACTION_MEMBER_ID', self.action_mbr_ids[x])])]
                self.action_data_list += [self.action_profile_table.make_data([gc.DataTuple('dst_port', self.eg_ports[x]),
                                                     gc.DataTuple('dstAddr', self.ipDstAddrs[x])],
                                                        'SwitchIngress.change_ipdst')]
            self.tcam_key_list += [self.tcam_direct_lpf_table.make_key([gc.KeyTuple('$MATCH_PRIORITY', self.priorities[x]),
                                             gc.KeyTuple('hdr.ethernet.dst_addr',
                                                         self.dstMacAddrs[x],
                                                         self.dstMacAddrsMask[x]),
                                             gc.KeyTuple('hdr.ethernet.src_addr',
                                                         self.srcMacAddrs[x],
                                                         self.srcMacAddrsMask[x])])]
            self.tcam_data_list += [self.tcam_direct_lpf_table.make_data([gc.DataTuple('$ACTION_MEMBER_ID', self.action_mbr_ids[x]),
                                              gc.DataTuple('$LPF_SPEC_TYPE', str_val=self.lpf_types[x]),
                                              gc.DataTuple('$LPF_SPEC_GAIN_TIME_CONSTANT_NS',
                                                           float_val=self.gain_time[x]),
                                              gc.DataTuple('$LPF_SPEC_DECAY_TIME_CONSTANT_NS',
                                                           float_val=self.decay_time[x]),
                                              gc.DataTuple('$LPF_SPEC_OUT_SCALE_DOWN_FACTOR', self.out_scale[x])])]

    def add_entries(self):
        self.action_profile_table.entry_add(self.target, self.action_key_list, self.action_data_list)
        self.tcam_direct_lpf_table.entry_add(self.target, self.tcam_key_list, self.tcam_data_list)

    def send_traffic(self):
        logger.info("Sending traffic")
        for x in range(self.num_entries):
            pkt = testutils.simple_tcp_packet(eth_src=self.srcMacAddrs[x],
                                              eth_dst=self.dstMacAddrs[x],
                                              with_tcp_chksum=False)
            if self.action[x] == 'SwitchIngress.change_ipsrc':
                exp_pkt = testutils.simple_tcp_packet(eth_src=self.srcMacAddrs[x],
                                                      eth_dst=self.dstMacAddrs[x],
                                                      ip_src=self.ipSrcAddrs[x],
                                                      with_tcp_chksum=False)
            elif self.action[x] == 'SwitchIngress.change_ipdst':
                exp_pkt = testutils.simple_tcp_packet(eth_src=self.srcMacAddrs[x],
                                                      eth_dst=self.dstMacAddrs[x],
                                                      ip_dst=self.ipDstAddrs[x],
                                                      with_tcp_chksum=False)
            testutils.send_packet(self, self.ig_ports[x], pkt)
            testutils.verify_packet(self, exp_pkt, self.eg_ports[x])
        testutils.verify_no_other_packets(self, timeout=2)

    def get_entries_and_verify(self):
        resp = self.tcam_direct_lpf_table.entry_get(self.target)
        x = 0
        for data, key in resp:
            data_dict = data.to_dict()
            '''
            assert data_dict["$LPF_SPEC_TYPE"] == self.lpf_types[x], "expected %s received %s" %(str(data_dict["$LPF_SPEC_TYPE"]), self.lpf_types[x])
            assert abs(data_dict["$LPF_SPEC_GAIN_TIME_CONSTANT_NS"] - self.gain_time[x]) <= self.gain_time[x] * 0.02
            assert abs(data_dict["$LPF_SPEC_DECAY_TIME_CONSTANT_NS"] - self.decay_time[x]) <= self.decay_time[x] * 0.02
            assert data_dict["$LPF_SPEC_OUT_SCALE_DOWN_FACTOR"] == self.out_scale[x]
            '''
            x += 1
        resp = self.action_profile_table.entry_get(self.target)
        x = 0
        for data, key in resp:
            data_dict = data.to_dict()
            assert data_dict["action_name"] == self.action[x]
            if data_dict["action_name"] == "SwitchIngress.change_ipsrc":
                assert data_dict["srcAddr"] == self.ipSrcAddrs[x]
            elif data_dict["action_name"] == "SwitchIngress.change_ipdst":
                assert data_dict["dstAddr"] == self.ipDstAddrs[x]
            x += 1

    def setUp(self):
        self.p4_name = "tna_ternary_match"
        HitlessBaseTest.setUp(self)

class HitlessTnaPortMetadata(HitlessBaseTest):
    '''
    HA test for port_metadata tables
    P4 program = tna_port_metadata
    '''

    def setup_tables(self):
        self.port_metadata_table = self.bfrt_info.table_get("SwitchIngressParser.$PORT_METADATA")
        self.port_md_exm_match_table = self.bfrt_info.table_get("SwitchIngress.port_md_exm_match")

    def make_phase0_data(self, field1, field2, field3, field4):
        """@brief Pack all fields into one phase0_data. For tofino 2, it is
        left shifted 64 more because the field is a 128 bit value
        """
        phase0data = (field1 << 48) | (field2 << 24) | (field3 << 8) | field4
        if testutils.test_param_get("arch") == "tofino":
            pass
        elif testutils.test_param_get("arch") == "tofino2":
            phase0data = phase0data << 64
        return phase0data

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.igr_to_egr_port_map = {}
        self.num_entries = 10
        igr_port_list = random.sample(swports, self.num_entries)
        egr_port_list = random.sample(swports, self.num_entries)
        for x in range(self.num_entries):
            self.igr_to_egr_port_map[igr_port_list[x]] = egr_port_list[x]
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.phase0_data_map = {}
        self.key_list = []
        self.data_list = []
        self.pm_dict = {}
        self.exm_key_list = []
        self.exm_data_list = []
        self.exm_dict = {}
        # Initialize the phase0 data map
        for key, value in list(self.igr_to_egr_port_map.items()):
            igr_port = key
            self.phase0_data_map[igr_port] = 0

        for key, value in list(self.igr_to_egr_port_map.items()):
            igr_port = key
            egr_port = value

            # For each igr port add a entry in the port_metadata (phase0) table
            # Form data to be programmed in the phase0 table for this ingress port
            phase0data = 0
            field1 = 0
            field2 = 0
            field3 = 0
            field4 = 0
            while True:
                field1 = random.randint(256, 0xffff)  # 16 bit
                field2 = random.randint(1, 0xffffff)  # 24 bits
                field3 = random.randint(1, 0xffff)  # 16 bits
                field4 = random.randint(1, 0xff)  # 8 bits

                phase0data = self.make_phase0_data(field1, field2, field3, field4)

                if self.phase0_data_map[igr_port] != phase0data:
                    self.phase0_data_map[igr_port] = phase0data
                    break

            self.key_list += [self.port_metadata_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', igr_port)])]
            self.data_list += [self.port_metadata_table.make_data([gc.DataTuple('$DEFAULT_FIELD', phase0data)])]
            self.pm_dict[self.key_list[-1]] = self.data_list[-1]

            # entry for the igr port in the exact match table
            self.exm_key_list += [self.port_md_exm_match_table.make_key(
                    [gc.KeyTuple('ig_md.port_md.field1', field1),
                     gc.KeyTuple('ig_md.port_md.field2', field2),
                     gc.KeyTuple('ig_md.port_md.field3', field3),
                     gc.KeyTuple('ig_md.port_md.field4', field4)])]
            self.exm_data_list += [self.port_md_exm_match_table.make_data(
                    [gc.DataTuple('port', egr_port)],
                    'SwitchIngress.hit')]
            self.exm_dict[self.exm_key_list[-1]] = self.exm_data_list[-1]

    def add_entries(self):
        self.port_metadata_table.entry_add(self.target, self.key_list, self.data_list)
        self.port_md_exm_match_table.entry_add(self.target, self.exm_key_list, self.exm_data_list)

    def send_traffic(self):
        logger.info("Sending traffic")
        pkt = testutils.simple_tcp_packet()
        exp_pkt = pkt
        for key, value in list(self.igr_to_egr_port_map.items()):
            igr_port = key
            egr_port = value
            logger.info("Sending packet on port %d", igr_port)
            testutils.send_packet(self, igr_port, pkt)
            logger.info("Expecting packet on port %d", egr_port)
            testutils.verify_packet(self, exp_pkt, egr_port)
            logger.info("Packet received on port %d as expected", egr_port)

    def get_entries_and_verify(self):
        resp = self.port_metadata_table.entry_get(self.target)
        for data, key in resp:
            assert self.pm_dict[key] == data

        resp = self.port_md_exm_match_table.entry_get(self.target)
        for data, key in resp:
            assert self.exm_dict[key] == data


    def setUp(self):
        self.p4_name = "tna_port_metadata"
        HitlessBaseTest.setUp(self)

class HitlessTnaLpmAlpm(HitlessBaseTest):
    '''
    HA test for ALPM tables
    P4 program = tna_lpm_match
    '''

    def setup_tables(self):
        self.alpm_forward_table = self.bfrt_info.table_get("SwitchIngress.alpm_forward")
        self.alpm_forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
        self.alpm_forward_table.info.data_field_annotation_add("srcMac", "SwitchIngress.route", "mac")
        self.alpm_forward_table.info.data_field_annotation_add("dstMac", "SwitchIngress.route", "mac")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.key_list = []
        self.data_list = []
        self.alpm_dict = {}
        self.num_entries = random.randint(1, 30)
        self.target = gc.Target(device_id=0, pipe_id=0xffff)

        self.ig_port = swports[1]
        ip_list = self.generate_random_ip_list(self.num_entries, self.seed)
        for i in range(0, self.num_entries):
            vrf = 0
            dst_ip = getattr(ip_list[i], "ip")
            p_len = getattr(ip_list[i], "prefix_len")

            srcMac = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple([random.randint(0, 255) for x in range(6)])
            dstMac = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple([random.randint(0, 255) for x in range(6)])
            eg_port = swports[random.randint(1, 4)]

            target = gc.Target(device_id=0, pipe_id=0xffff)
            self.key_list += [self.alpm_forward_table.make_key([gc.KeyTuple('vrf', vrf),
                                              gc.KeyTuple('hdr.ipv4.dst_addr', dst_ip, prefix_len=p_len)])]
            self.data_list += [self.alpm_forward_table.make_data([gc.DataTuple('dst_port', eg_port),
                                               gc.DataTuple('srcMac', srcMac),
                                               gc.DataTuple('dstMac', dstMac)],
                                              'SwitchIngress.route')]
            self.key_list[-1].apply_mask()
            self.alpm_dict[self.key_list[-1]] = self.data_list[-1]

    def add_entries(self):
        self.alpm_forward_table.entry_add(self.target, self.key_list, self.data_list)

    def send_traffic(self):
        logger.info("Sending traffic")
        for k, d in zip(self.key_list, self.data_list):
            key = k.to_dict()
            data = d.to_dict()
            pkt = testutils.simple_tcp_packet(ip_dst=key["hdr.ipv4.dst_addr"]["value"])
            exp_pkt = testutils.simple_tcp_packet(eth_dst=data["dstMac"],
                                                  eth_src=data["srcMac"],
                                                  ip_dst=key["hdr.ipv4.dst_addr"]["value"])
            logger.info("Sending packet on port %d", self.ig_port)
            testutils.send_packet(self, self.ig_port, pkt)

            logger.info("Verifying entry for IP address %s, prefix_length %d" % \
                    (key["hdr.ipv4.dst_addr"]["value"], key["hdr.ipv4.dst_addr"]["prefix_len"]))
            logger.info("Expecting packet on port %d", data["dst_port"])
            testutils.verify_packet(self, exp_pkt, data["dst_port"])

    def get_entries_and_verify(self):
        resp = self.alpm_forward_table.entry_get(self.target)
        for data, key in resp:
            assert self.alpm_dict[key] == data

    def setUp(self):
        self.p4_name = "tna_lpm_match"
        HitlessBaseTest.setUp(self)

class HitlessTnaRange(HitlessBaseTest):
    '''
    HA test for Range tables
    P4 program = tna_range_match
    '''

    def setup_tables(self):
        self.forward_table = self.bfrt_info.table_get("SwitchIngress.forward")
        self.forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.ig_port = swports[1]
        self.eg_ports = [swports[5], swports[3]]
        self.num_entries = 10
        self.target = gc.Target(device_id=0, pipe_id=0xFFFF)

        self.key_list = []
        self.data_list = []

        for i in range(0, self.num_entries):
            vrf = 0
            range_size = random.randint(1, 511)
            dst_ip = "%d.%d.%d.%d" % (
                random.randint(1, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
            pkt_length_start = random.randint(60, 511)
            self.key_list += [self.forward_table.make_key([gc.KeyTuple('$MATCH_PRIORITY', 1),
                                         gc.KeyTuple('hdr.ipv4.dst_addr', dst_ip),
                                         gc.KeyTuple('hdr.ipv4.total_len',
                                                         low=pkt_length_start,
                                                         high=pkt_length_start + range_size)])]
            self.data_list += [self.forward_table.make_data([gc.DataTuple('port', self.eg_ports[0])], 'SwitchIngress.hit')]

    def add_entries(self):
        self.forward_table.entry_add(self.target, self.key_list, self.data_list)

    def send_traffic(self):
        logger.info("Sending traffic")
        for k, d in zip(self.key_list, self.data_list):
            # select a random length between the range
            key = k.to_dict()
            data = d.to_dict()
            eth_hdr_size = 14

            dst_ip = key["hdr.ipv4.dst_addr"]["value"]
            pkt_length_start = key["hdr.ipv4.total_len"]["low"]
            pkt_length_end = key["hdr.ipv4.total_len"]["high"]
            range_size = key["hdr.ipv4.total_len"]["high"] - key["hdr.ipv4.total_len"]["low"]

            pkt_len = random.randint(pkt_length_start, pkt_length_end) + eth_hdr_size
            pkt = testutils.simple_tcp_packet(pktlen=pkt_len, ip_dst=dst_ip)
            exp_pkt = pkt
            logger.info("Sending packet on port %d for with total_len %d", self.ig_port,
                    pkt_len - eth_hdr_size)
            testutils.send_packet(self, self.ig_port, pkt)

            logger.info("Expecting packet on port %d", self.eg_ports[0])
            testutils.verify_packet(self, exp_pkt, self.eg_ports[0])

        for k, d in zip(self.key_list, self.data_list):
            key = k.to_dict()
            data = d.to_dict()
            eth_hdr_size = 14

            dst_ip = key["hdr.ipv4.dst_addr"]["value"]
            pkt_length_start = key["hdr.ipv4.total_len"]["low"]
            pkt_length_end = key["hdr.ipv4.total_len"]["high"]
            range_size = key["hdr.ipv4.total_len"]["high"] - key["hdr.ipv4.total_len"]["low"]
            # select a length more than the range, it should be dropped
            pkt_len = pkt_length_end + eth_hdr_size + 2
            pkt = testutils.simple_tcp_packet(pktlen=pkt_len, ip_dst=dst_ip)
            exp_pkt = pkt
            logger.info("Sending packet on port %d with total_len %d", self.ig_port,
                        pkt_len - eth_hdr_size)
            testutils.send_packet(self, self.ig_port, pkt)

            logger.info("Packet is expected to get dropped.")
            testutils.verify_no_other_packets(self)

    def get_entries_and_verify(self):
        resp = self.forward_table.entry_get(self.target)
        i=0
        for data, key in resp:
            assert key == self.key_list[i], "received %s expected %s" %(str(key), str(self.key_list[i]))
            assert data == self.data_list[i]
            i+=1

    def setUp(self):
        self.p4_name = "tna_range_match"
        HitlessBaseTest.setUp(self)

    def tearDown(self):
        self.interface.clear_all_tables()
        super(HitlessTnaRange, self).tearDown()

class HitlessTnaActionSelector(HitlessBaseTest):
    '''
    HA test for Action Selector tables
    P4 program = tna_action_selector
    '''

    def setup_tables(self):
        self.forward_table = self.bfrt_info.table_get("SwitchIngress.forward")
        self.action_table = self.bfrt_info.table_get("SwitchIngress.example_action_selector_ap")
        self.sel_table = self.bfrt_info.table_get("SwitchIngress.example_action_selector")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.num_entries = 4
        #self.seed = 1076
        #self.seed = 30971
        self.ig_ports = [swports[i] for i in range(self.num_entries)]
        self.target = gc.Target(device_id=0, pipe_id=0xFFFF)
        self.max_grp_size = 7

        self.match_key_list = []
        self.match_data_list = []
        self.action_key_list = []
        self.action_data_list = []
        self.sel_key_list = []
        self.sel_data_list = []

        self.num_act_prof_entries = 1024
        self.num_sel_grps = 100

        self.egress_ports = [swports[random.randint(self.num_entries, self.num_entries+5)] for x in range(self.num_act_prof_entries)]
        self.action_mbr_ids = [x for x in range(self.num_act_prof_entries)]
        self.sel_grp_ids = [x for x in range(self.num_sel_grps)]
        self.status = [True, False]
        self.num_mbrs_in_grps = [random.randint(1, 7) for x in range(self.num_sel_grps)]
        self.mbrs_in_grps = [(random.sample(self.action_mbr_ids, self.num_mbrs_in_grps[x]),
                         [self.status[random.randint(0, 1)]
                          for y in range(self.num_mbrs_in_grps[x])])
                        for x in range(self.num_sel_grps)]

        # Construct input for selector table
        # This list contains dictionaries for each entry
        # dict(grp_id -> dict(act_member -> mem_status) )
        self.mem_dict_dict = {}
        for j in range(self.num_sel_grps):
            members, member_status = self.mbrs_in_grps[j]
            mem_dict = {members[i]: member_status[i]
                        for i in range(0, len(members))}
            self.mem_dict_dict[self.sel_grp_ids[j]] = mem_dict

        logger.info("Making %d entries to action profile table",
                    self.num_act_prof_entries)
        for j in range(self.num_act_prof_entries):
            # Create a new member for each port with the port number as the id.
            self.action_key_list += [self.action_table.make_key([gc.KeyTuple('$ACTION_MEMBER_ID',
                                                    self.action_mbr_ids[j])])]
            self.action_data_list += [self.action_table.make_data([gc.DataTuple('port', self.egress_ports[j])],
                                        'SwitchIngress.hit')]

        # Add the new member to the selection table.
        logger.info("Making %d groups for selector table", self.num_sel_grps)
        for grp_id, mem_dict in self.mem_dict_dict.items():
            self.sel_key_list += [self.sel_table.make_key([gc.KeyTuple('$SELECTOR_GROUP_ID',
                                                 grp_id)])]
            self.sel_data_list += [self.sel_table.make_data([gc.DataTuple('$MAX_GROUP_SIZE',
                                                   self.max_grp_size),
                                      gc.DataTuple('$ACTION_MEMBER_ID',
                                                   int_arr_val=list(mem_dict.keys())),
                                      gc.DataTuple('$ACTION_MEMBER_STATUS',
                                                   bool_arr_val=list(mem_dict.values()))])]
        # Add entry to the forward table
        # Select one out of Action mem ID or Select Grp ID
        for i in range(self.num_entries):
            fwd_data = random.choice(["$SELECTOR_GROUP_ID", "$ACTION_MEMBER_ID"])
            self.match_key_list += [self.forward_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port',
                                                 self.ig_ports[i])])]
            if fwd_data == "$SELECTOR_GROUP_ID":
                self.match_data_list += [self.forward_table.make_data([gc.DataTuple('$SELECTOR_GROUP_ID',
                                                   random.choice(list(self.mem_dict_dict.keys()))
                                                   )])]
            else:
                self.match_data_list += [self.forward_table.make_data([gc.DataTuple('$ACTION_MEMBER_ID',
                                                   random.choice(self.action_mbr_ids)
                                                   )])]

    def add_entries(self):
        self.action_table.entry_add(self.target, self.action_key_list, self.action_data_list)
        self.sel_table.entry_add(self.target, self.sel_key_list, self.sel_data_list)
        self.forward_table.entry_add(self.target, self.match_key_list, self.match_data_list)

    def send_traffic(self):
        logger.info("Sending traffic")
        for i in range(self.num_entries):
            logger.info("Match entry #%d", i)
            data = self.match_data_list[i].to_dict()
            eg_ports = []
            if "$SELECTOR_GROUP_ID" in data:
                # Get the action members which are active and make a list
                # of possible eg_ports
                logger.info("Sending to one of selector entries")
                act_dict = self.mem_dict_dict[data["$SELECTOR_GROUP_ID"]]
                mem_id_list = [mem for mem, status in act_dict.items() if status]
                for mem in mem_id_list:
                    for j in range(self.num_act_prof_entries):
                        if self.action_mbr_ids[j] == mem:
                            eg_ports.append(self.egress_ports[j])
            else:
                for j in range(self.num_act_prof_entries):
                    if self.action_mbr_ids[j] == data["$ACTION_MEMBER_ID"]:
                        eg_ports.append(self.egress_ports[j])
            if len(eg_ports) == 0:
                logger.info("empty eg_ports!")
                continue

            pkt = testutils.simple_tcp_packet()
            exp_pkt = pkt
            logger.info("Sending packet on port %d", self.ig_ports[i])
            testutils.send_packet(self, self.ig_ports[i], pkt)
            logger.info("Expecting packet on one of enabled ports %s", eg_ports)
            testutils.verify_any_packet_any_port(self, [exp_pkt], eg_ports)


    def get_entries_and_verify(self):
        resp = self.forward_table.entry_get(self.target)
        i=0
        for data, key in resp:
            assert key == self.match_key_list[i], "received %s expected %s" %(str(key), str(self.match_key_list[i]))
            #TODO errors out because garbage value in either action_mbr_id or grp_id. Fix it
            #assert data == self.match_data_list[i], "received %s expected %s" %(str(data), str(self.match_data_list[i]))
            i+=1
        resp = self.action_table.entry_get(self.target)
        i=0
        for data, key in resp:
            assert key == self.action_key_list[i], "received %s expected %s" %(str(key), str(self.action_key_list[i]))
            assert data == self.action_data_list[i], "received %s expected %s" %(str(data), str(self.action_data_list[i]))
            i+=1
        resp = self.sel_table.entry_get(self.target)
        i=0
        for data, key in resp:
            assert key == self.sel_key_list[i], "received %s expected %s" %(str(key), str(self.sel_key_list[i]))
            #TODO errors out because the order of the mem_status/mem lists are different for recv and sent. Not extremely
            # harmful but fix it
            #assert data == self.sel_data_list[i], "received %s expected %s" %(str(data), str(self.sel_data_list[i]))
            i+=1

    def runTest(self):
        ######## Disabling this test. Remove this function to enable back #########
        pass

    def setUp(self):
        self.p4_name = "tna_action_selector"
        HitlessBaseTest.setUp(self)

    def tearDown(self):
        self.interface.clear_all_tables()
        super(HitlessTnaActionSelector, self).tearDown()

class HitlessKeyLessTable(HitlessBaseTest):
    '''
    HA test for Keyless table
    P4 program = tna_bridedmd
    '''

    def setup_tables(self):
        self.table_output_port = self.bfrt_info.table_get("SwitchIngress.output_port")
        self.table_bridge_md_ctl= self.bfrt_info.table_get("SwitchIngress.bridge_md_ctrl")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.target = gc.Target(device_id=0, pipe_id=0xFFFF)
        self.eg_port = swports[1]
        self.ig_ports = [swports[x] for x in range(6)]

        self.bridged_data = self.table_bridge_md_ctl.make_data([],
                "SwitchIngress.bridge_add_ig_intr_md")
        self.bridged_key = self.table_bridge_md_ctl.make_key([])

        self.output_data = self.table_output_port.make_data(
            [gc.DataTuple("port_id", self.eg_port)],
            "SwitchIngress.set_output_port")

    def add_entries(self):
        logger.info("Adding entries")
        self.table_bridge_md_ctl.default_entry_set(self.target, self.bridged_data)
        self.table_output_port.default_entry_set(self.target, self.output_data)

    def send_traffic(self):
        logger.info("Sending traffic")

        ipkt = testutils.simple_tcp_packet(eth_dst='11:11:11:11:11:11',
                                           eth_src='22:33:44:55:66:77',
                                           ip_src='1.2.3.4',
                                           ip_dst='100.99.98.97',
                                           ip_id=101,
                                           ip_ttl=64,
                                           tcp_sport=0x1234,
                                           tcp_dport=0xabcd,
                                           with_tcp_chksum=True)

        epkt_tmpl = testutils.simple_tcp_packet(eth_dst='00:00:00:00:00:02',
                                                eth_src='22:33:44:55:66:77',
                                                ip_src='1.2.3.4',
                                                ip_dst='100.99.98.97',
                                                ip_id=101,
                                                ip_ttl=64,
                                                tcp_sport=0x1234,
                                                tcp_dport=0xabcd,
                                                with_tcp_chksum=True)

        epkts = []
        for p in self.ig_ports:
            epkt = epkt_tmpl.copy()[scapy.all.Ether]
            epkt.dst = "00:00:00:00:00:{:02x}".format(p)
            epkts.append(epkt)

        for p in self.ig_ports:
            testutils.send_packet(self, p, ipkt)

        testutils.verify_each_packet_on_each_port(self,
                                                  epkts,
                                                  [self.eg_port] * len(self.ig_ports))


    def get_entries_and_verify(self):
        resp = self.table_bridge_md_ctl.default_entry_get(self.target)
        for data, key in resp:
            assert data == self.bridged_data
        resp = self.table_output_port.default_entry_get(self.target)
        for data, key in resp:
            assert data == self.output_data

    def setUp(self):
        self.p4_name = "tna_bridged_md"
        HitlessBaseTest.setUp(self)

    def tearDown(self):
        self.interface.clear_all_tables()
        super(HitlessKeyLessTable, self).tearDown()

class HitlessHashActionTable(HitlessBaseTest):
    '''
    HA test for Hash action table. Tables which are of size = 2^key_size
    P4 program = tna_mirror
    '''

    def setup_tables(self):
        self.mirror_cfg_table = self.bfrt_info.table_get("$mirror.cfg")
        self.mirror_fwd_table = self.bfrt_info.table_get("mirror_fwd")

    def setup_test_data(self):
        logger.info("Setting up test data")

        if test_param_get("arch") == "tofino":
            MIR_SESS_COUNT = 1024
            MAX_SID_NORM = 1015
            MAX_SID_COAL = 1023
            BASE_SID_NORM = 1
            BASE_SID_COAL = 1016
            self.EXP_LEN1 = 127
            self.EXP_LEN2 = 63
        elif test_param_get("arch") == "tofino2":
            MIR_SESS_COUNT = 256
            MAX_SID_NORM = 255
            MAX_SID_COAL = 255
            BASE_SID_NORM = 0
            BASE_SID_COAL = 0
            self.EXP_LEN1 = 127
            self.EXP_LEN2 = 59

        self.sids = random.sample(range(BASE_SID_NORM, MAX_SID_NORM), len(swports))
        self.sids.sort()

        self.target = gc.Target(device_id=0, pipe_id=0xFFFF)
        self.mirror_fwd_key = []
        self.mirror_fwd_data = []
        self.mirror_cfg_key = []
        self.mirror_cfg_data = []

        for port, sid in zip(swports, self.sids):
            self.mirror_fwd_key += [self.mirror_fwd_table.make_key([
                gc.KeyTuple('ig_intr_md.ingress_port', port)])]
            self.mirror_fwd_data += [self.mirror_fwd_table.make_data([gc.DataTuple('dest_port', 511),
                                          gc.DataTuple('ing_mir', 1),
                                          gc.DataTuple('ing_ses', sid),
                                          gc.DataTuple('egr_mir', 0),
                                          gc.DataTuple('egr_ses', 0)],
                                         'SwitchIngress.set_md')]
            if port % 2 == 0:
                max_len = 128
            else:
                max_len = 64
            self.mirror_cfg_key += [self.mirror_cfg_table.make_key([gc.KeyTuple('$sid', sid)])]
            self.mirror_cfg_data += [self.mirror_cfg_table.make_data([gc.DataTuple('$direction', str_val="INGRESS"),
                                                 gc.DataTuple('$ucast_egress_port', port),
                                                 gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                                 gc.DataTuple('$session_enable', bool_val=True),
                                                 gc.DataTuple('$max_pkt_len', max_len)],
                                                '$normal')]


    def add_entries(self):
        logger.info("Adding entries")
        self.mirror_cfg_table.entry_add(self.target, self.mirror_cfg_key, self.mirror_cfg_data)
        self.mirror_fwd_table.entry_add(self.target, self.mirror_fwd_key, self.mirror_fwd_data)


    def send_traffic(self):
        logger.info("Sending traffic")
        pkt = simple_eth_packet(pktlen=79)
        pkt = simple_eth_packet(pktlen=200)
        rec_pkt1 = simple_eth_packet(pktlen=self.EXP_LEN1)
        rec_pkt2 = simple_eth_packet(pktlen=self.EXP_LEN2)
        for port in swports:
            send_packet(self, port, pkt)
            if port % 2 == 0:
                verify_packet(self, rec_pkt1, port)
            else:
                verify_packet(self, rec_pkt2, port)
        verify_no_other_packets(self)



    def get_entries_and_verify(self):
        resp = self.mirror_fwd_table.entry_get(self.target)
        i=0
        for data, key in resp:
            assert key == self.mirror_fwd_key[i], "received %s expected %s" %(str(key), str(self.mirror_fwd_key[i]))
            assert data == self.mirror_fwd_data[i], "received %s expected %s" %(str(data), str(self.mirror_fwd_data[i]))
            i+=1
        resp = self.mirror_cfg_table.entry_get(self.target)
        i=0
        for data, key in resp:
            assert key == self.mirror_cfg_key[i], "received %s expected %s" %(str(key), str(self.mirror_cfg_key[i]))
            #TODO fix below. server sending more fields than being sent by client. Some are garbage.  Make madatory work
            #assert data == self.mirror_cfg_data[i], "received %s expected %s" %(str(data), str(self.mirror_cfg_data[i]))
            i+=1


    def setUp(self):
        self.p4_name = "tna_mirror"
        HitlessBaseTest.setUp(self)

    def tearDown(self):
        self.interface.clear_all_tables()
        super(HitlessHashActionTable, self).tearDown()

class HitlessPVS(HitlessBaseTest):
    '''
    P4 program = tna_pvs
    '''

    def setup_tables(self):
        self.vs_table = self.bfrt_info.table_get("ParserI.vs")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.target = gc.Target(device_id=0, pipe_id=0xffff, direction=0xff, prsr_id=0xff)
        self.vs_table.attribute_entry_scope_set(self.target,
                                           config_gress_scope=True, predefined_gress_scope_val=bfruntime_pb2.Mode.ALL,
                                           config_pipe_scope=True, predefined_pipe_scope=True,
                                           predefined_pipe_scope_val=bfruntime_pb2.Mode.ALL, pipe_scope_args=0xff,
                                           config_prsr_scope=True, predefined_prsr_scope_val=bfruntime_pb2.Mode.ALL,
                                           prsr_scope_args=0xff)
        self.key_list = []
        for i in [1, 2, 3, 4]:
            f16 = i
            f8 = i + 10
            self.key_list += [self.vs_table.make_key([gc.KeyTuple('f16', f16, 0xffff),
                                   gc.KeyTuple('f8', f8, 0xff)])]

    def add_entries(self):
        logger.info("Adding entries")
        self.vs_table.entry_add(self.target, self.key_list)

    def get_entries_and_verify(self):
        logger.info("Verifying get entry")
        resp = self.vs_table.entry_get(self.target)
        i=0
        for data, key in resp:
            "==============="
            logger.info(key.to_dict())
            logger.info(data.to_dict())
            assert key == self.key_list[i], "received %s expected %s" %(str(key), str(self.key_list[i]))
            i+=1


    def setUp(self):
        self.p4_name = "tna_pvs"
        HitlessBaseTest.setUp(self)

class HitlessDynHashing(HitlessBaseTest):
    '''
    P4 program = tna_dyn_hashing
    '''

    def setup_tables(self):
        self.hash_config_table = self.bfrt_info.table_get("IngressP.hash_1.$CONFIGURE")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.target = gc.Target(device_id=0, pipe_id=0xFFFF)
        self.alg_hdl = 587202560
        self.hash_seed = 0x12345
        self.data_list = [self.hash_config_table.make_data([gc.DataTuple('hdr.ipv4.proto.$PRIORITY', 0),
                                          gc.DataTuple('hdr.ipv4.sip.$PRIORITY', 2),
                                          gc.DataTuple('hdr.ipv4.dip.$PRIORITY', 1),
                                          gc.DataTuple('hdr.tcp.sPort.$PRIORITY', 3),
                                          gc.DataTuple('hdr.tcp.dPort.$PRIORITY', 4)])]

    def add_entries(self):
        logger.info("Adding entries")
        self.hash_config_table.entry_add(self.target, None, self.data_list)
        logger.info("set dyn hashing attribute")
        self.hash_config_table.attribute_dyn_hashing_set(self.target,
                                                    alg_hdl=self.alg_hdl,
                                                    seed=self.hash_seed)


    def get_entries_and_verify(self):
        logger.info("Verifying get entry")
        resp = self.hash_config_table.entry_get(self.target, None, {"from_hw": False})
        i=0
        for data, key in resp:
            assert data == self.data_list[i], "received %s expected %s" %(str(data), str(self.data_list[i]))
            i+=1
        resp = self.hash_config_table.attribute_get(self.target, "DynamicHashing")
        for d in resp:
            assert d["alg"] == self.alg_hdl
            assert d["seed"] == self.hash_seed


    def setUp(self):
        self.p4_name = "tna_dyn_hashing"
        HitlessBaseTest.setUp(self)

class HitlessIndirectMeterTest(HitlessBaseTest):
    '''
    P4 program = tna_meter_lpf_wred
    '''

    def setup_tables(self):
        self.meter_table = self.bfrt_info.table_get("SwitchIngress.meter")
        self.match_table = self.bfrt_info.table_get("SwitchIngress.meter_color")
        self.match_table.info.key_field_annotation_add("hdr.ethernet.dst_addr", "mac")

    def getMeterData(self, num_entries):
        meter_data = {}
        meter_data['cir'] = [1000 * random.randint(1, 1000) for i in range(num_entries)]
        meter_data['pir'] = [meter_data['cir'][i] * random.randint(1, 5) for i in range(num_entries)]
        meter_data['cbs'] = [1000 * random.randint(1, 100) for i in range(num_entries)]
        meter_data['pbs'] = [meter_data['cbs'][i] * random.randint(1, 5) for i in range(num_entries)]
        return meter_data

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.target = gc.Target(device_id=0, pipe_id=0xFFFF)
        self.num_entries =  random.randint(1,100)
        self.meter_key_list = []
        self.meter_data_list = []
        self.match_key_list = []
        self.match_data_list = []
        key_set = set()
        meter_indices = [x + 1 for x in range(self.num_entries)]
        logger.info("Number of entries %d", self.num_entries)
        self.match_dict = {}

        for i in range(self.num_entries):
            mac_addr = "%02x:%02x:%02x:%02x:%02x:%02x" % (
                random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255),
                random.randint(0, 255), random.randint(0, 255))
            while mac_addr in key_set:
                mac_addr = "%02x:%02x:%02x:%02x:%02x:%02x" % (
                    random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255),
                    random.randint(0, 255), random.randint(0, 255))
            self.match_key_list += [self.match_table.make_key([gc.KeyTuple('hdr.ethernet.dst_addr', mac_addr)])]
            self.match_data_list += [self.match_table.make_data(
                    [gc.DataTuple('meter_idx', meter_indices[x])],
                    'SwitchIngress.set_color')]
            key_set.add(mac_addr)
            self.match_dict[self.match_key_list[-1]] = self.match_data_list[-1]


        self.meter_data = self.getMeterData(self.num_entries)
        for x in range(self.num_entries):
            self.meter_key_list += [self.meter_table.make_key(
                    [gc.KeyTuple('$METER_INDEX', x)])]
            self.meter_data_list += [self.meter_table.make_data(
                    [gc.DataTuple('$METER_SPEC_CIR_KBPS',  self.meter_data['cir'][x]),
                     gc.DataTuple('$METER_SPEC_PIR_KBPS',  self.meter_data['pir'][x]),
                     gc.DataTuple('$METER_SPEC_CBS_KBITS', self.meter_data['cbs'][x]),
                     gc.DataTuple('$METER_SPEC_PBS_KBITS', self.meter_data['pbs'][x])])]

    def add_entries(self):
        logger.info("Adding entries")
        self.meter_table.entry_add(self.target, self.meter_key_list, self.meter_data_list)
        self.match_table.entry_add(self.target, self.match_key_list, self.match_data_list)


    def send_traffic(self):
        logger.info("Sending traffic")
        for x in range(self.num_entries):
            pkt = testutils.simple_tcp_packet(eth_dst=self.match_key_list[x].to_dict()["hdr.ethernet.dst_addr"]["value"],
                                                      with_tcp_chksum=False)
            testutils.send_packet(self, swports[0], pkt)

    def get_entries_and_verify(self):
        logger.info("Verifying get entry")
        resp = self.meter_table.entry_get(self.target, None, {"from_hw": False})
        i = 0
        for data, key in resp:
            data_dict = data.to_dict()
            key_dict = key.to_dict()
            recv_cir = data_dict["$METER_SPEC_CIR_KBPS"]
            recv_pir = data_dict["$METER_SPEC_PIR_KBPS"]
            recv_cbs = data_dict["$METER_SPEC_CBS_KBITS"]
            recv_pbs = data_dict["$METER_SPEC_PBS_KBITS"]

            # Read back meter values are not always the same. It should be within a 2% error rate
            assert abs(recv_cir - self.meter_data['cir'][i]) < self.meter_data['cir'][i] * 0.02
            assert abs(recv_pir - self.meter_data['pir'][i]) < self.meter_data['pir'][i] * 0.02
            assert abs(recv_cbs - self.meter_data['cbs'][i]) < self.meter_data['cbs'][i] * 0.02
            assert abs(recv_pbs - self.meter_data['pbs'][i]) < self.meter_data['pbs'][i] * 0.02

            assert key_dict["$METER_INDEX"]['value'] == i
            i += 1
            if i == self.num_entries:
                break

        resp = self.match_table.entry_get(self.target)
        i=0
        for data, key in resp:
            assert self.match_dict[key] == data
            i+=1


    def setUp(self):
        self.p4_name = "tna_meter_lpf_wred"
        HitlessBaseTest.setUp(self)

    def tearDown(self):
        self.interface.clear_all_tables()
        HitlessBaseTest.tearDown(self)
