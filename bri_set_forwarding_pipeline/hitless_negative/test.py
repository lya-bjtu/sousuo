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

import enum
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

# The following method categorizes the ports in ports.json file as belonging to either of the pipes (0, 1, 2, 3)
swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)
    swports.sort()

if swports == []:
    swports = range(9)

def port_to_pipe(port):
    local_port = port & 0x7F
    assert (local_port < 72)
    pipe = (port >> 7) & 0x3
    assert (port == ((pipe << 7) | local_port))
    return pipe

swports_by_pipe = [[] for i in range(4)]
for port in swports:
    pipe = port_to_pipe(port)
    swports_by_pipe[pipe].append(port)

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

class State(enum.Enum):
    BEFORE_HITLESS = 1
    HITLESS_START = 2
    REPLAY_DONE = 3
    HITLESS_END = 4

class HitlessBaseTestNegative(BfRuntimeTest):
    '''
    This acts as the Base test for all HA negative tests and provides the following template
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

    def send_traffic_and_verify_packets(self):
        pass

    def replay_entries(self):
        logger.info("replaying entries")
        self.add_entries()

    def get_entries_and_verify(self, from_hw = True):
        pass

    def init_replay_funcs(self):
        pass

    def set_state(self, state):
        self.state = state

    def post_hitless_validation(self):
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
        self.replay_func_list = []

    def runTest(self):
        self.setup_tables()
        self.init_replay_funcs()

        test_case_idx = 1
        for replay_func, error_expected in self.replay_func_list:
            logger.info("--------------------------------------")
            logger.info("Test case %d", test_case_idx)

            self.setup_test_data()
            self.set_state(State.BEFORE_HITLESS)
            self.add_entries()
            self.send_traffic_and_verify_packets()
            for from_hw in [True, False]:
                self.get_entries_and_verify(from_hw=from_hw)

            start_hitless(self)
            error_found_during_replay = False
            try:
                self.set_state(State.HITLESS_START)
                self.send_traffic_and_verify_packets()

                replay_func()

                self.set_state(State.REPLAY_DONE)
                self.send_traffic_and_verify_packets()

                end_hitless(self)

                self.set_state(State.HITLESS_END)
                self.send_traffic_and_verify_packets()

                '''
                In order to make sure the warm init did not leave the driver
                in some unexpected state, do some testing here.
                1. Get entries from HW and SW. Make sure it's correct.
                2. Add/Delete/Modify entries and make sure it's taking effect
                '''
                self.post_hitless_validation()

            except gc.BfruntimeRpcException as e:
                # If an error was received, then mark error found
                # since we want to perform a fast reconfig rather
                # than a hitless end
                error_found_during_replay = True

            if not error_found_during_replay and error_expected:
                raise RuntimeError("Expected an error but didn't get any")
            elif error_found_during_replay and not error_expected:
                raise RuntimeError("Expected no error but got one")
            else:
                # perform a simple warm_init
                self.interface.get_and_set_pipeline_config()

            test_case_idx += 1

    def tearDown(self):
        self.interface.clear_all_tables()
        BfRuntimeTest.tearDown(self)

class HitlessTnaExactMatchNegative(HitlessBaseTestNegative):
    """@brief This test does negative testing during replay.
    1. Try removing an entry. Need to verify that after hitless end, the entry was actually
    removed. Traffic pattern should test out.
    2. Try modifying an entry.  It may fail
    3. Try adding an entry which wasn't present. It should pass.
    The delta should be pushed.

    When encountered a failure, we issue a warm_init with fast_reconfig
    """

    def setup_tables(self):
        logger.info("Setting tables")
        self.forward_table = self.bfrt_info.table_get("SwitchIngress.forward")
        self.forward_table.info.key_field_annotation_add("hdr.ethernet.dst_addr", "mac")

    def setup_test_data(self):
        logger.info("Setting test data")
        self.dmac = '22:22:22:22:22:22'
        self.ig_port = swports[1]
        self.eg_port = swports[2]
        self.expect_packet = True
        self.target = gc.Target(device_id=0, pipe_id=0xffff)

        logger.info("Adding entries")
        self.key_list = [self.forward_table.make_key([gc.KeyTuple('hdr.ethernet.dst_addr', self.dmac)])]
        self.data_list = [self.forward_table.make_data([gc.DataTuple('port', self.eg_port)],
                                                                     "SwitchIngress.hit")]

        self.replayed_key_list = [self.forward_table.make_key([gc.KeyTuple('hdr.ethernet.dst_addr', self.dmac)])]
        self.replayed_data_list = [self.forward_table.make_data([gc.DataTuple('port', self.eg_port)],
                                                                              "SwitchIngress.hit")]

    def add_entries(self):
        self.forward_table.entry_add(self.target, self.key_list, self.data_list)

    def init_replay_funcs(self):
        self.replay_func_list.append((self.replay_entries_1, False))
        self.replay_func_list.append((self.replay_entries_2, False))
        # Cannot add an entry which was not present before replay yet
        # self.replay_func_list.append((self.replay_entries_3, True))

    def replay_entries_1(self):
        logger.info("Replay 1: Remove entry")
        self.forward_table.entry_add(self.target, self.key_list, self.data_list)
        self.forward_table.entry_del(self.target, self.key_list)

        self.replayed_key_list = []
        self.replayed_data_list = []

    def replay_entries_2(self):
        logger.info("Replay 2: Modify entry")
        self.forward_table.entry_add(self.target, self.key_list, self.data_list)

        new_data = [self.forward_table.make_data([gc.DataTuple('port', self.eg_port + 1)],
                                                               "SwitchIngress.hit")]
        self.forward_table.entry_mod(self.target, self.key_list, new_data)

        self.replayed_data_list = new_data

    def replay_entries_3(self):
        logger.info("Replay 3: Add not present entry")
        dmac = "aa:bb:cc:dd:ee:ff"
        new_key = [self.forward_table.make_key([gc.KeyTuple('hdr.ethernet.dst_addr', dmac)])]
        self.forward_table.entry_add(self.target, new_key, self.data_list)

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")
        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)

        '''
        Reset the original key and data lists based on what was replayed
        during this particular replay, as it will be used during the post
        hitless validation phase to decide what egress ports to expect or
        not expect packets on.
        '''
        self.key_list = []
        for item in self.replayed_key_list:
            self.key_list.append(item)
        self.data_list = []
        for item in self.replayed_data_list:
            self.data_list.append(item)

        # Add a new entry and verify
        logger.info("Adding a new entry")
        dmac = "aa:bb:cc:dd:ee:ff"
        new_key = self.forward_table.make_key([gc.KeyTuple('hdr.ethernet.dst_addr', dmac)])
        new_data = self.forward_table.make_data([gc.DataTuple('port', self.eg_port)],
                                                              "SwitchIngress.hit")
        self.forward_table.entry_add(self.target, [new_key], [new_data])
        self.replayed_key_list.append(new_key)
        self.replayed_data_list.append(new_data)

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        # Delete an entry and verify
        logger.info("Deleting an entry")
        self.forward_table.entry_del(self.target, [self.replayed_key_list[0]])
        self.replayed_key_list.pop(0)
        self.replayed_data_list.pop(0)

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        # Modify an entry
        if len(self.replayed_key_list) > 0:
            logger.info("Modifying an entry")
            new_data = self.forward_table.make_data([gc.DataTuple('port', self.eg_port + 2)],
                                                                   "SwitchIngress.hit")
            self.forward_table.entry_mod(self.target, [self.replayed_key_list[0]], [new_data])
            self.replayed_data_list[0] = new_data

            for from_hw in [True, False]:
                self.get_entries_and_verify(from_hw=from_hw)
            self.send_traffic_and_verify_packets()

        logger.info("--- Post hitless validation ended ---")

    def send_traffic_and_verify_packets(self):
        logger.info("Sending traffic and verifying packets")
        expect_packet_key_list = self.key_list
        expect_packet_data_list = self.data_list
        no_packet_key_list = []
        no_packet_data_list = []
        if self.state == State.HITLESS_END:
            # Expect packets on the egress ports associated with the replayed entries
            expect_packet_key_list = self.replayed_key_list
            expect_packet_data_list = self.replayed_data_list

            '''
            Do not expect packets on the egress ports associted with the
            original entries, which were not replayed
            '''
            no_packet_key_list = list(set(self.key_list) - set(self.replayed_key_list))
            no_packet_data_list = list(set(self.data_list) - set(self.replayed_data_list))

        count = 1
        if expect_packet_key_list and expect_packet_data_list:
            for index in range(0, len(expect_packet_key_list)):
                dmac = expect_packet_key_list[index].to_dict()["hdr.ethernet.dst_addr"]["value"]
                pkt = testutils.simple_tcp_packet(eth_dst=dmac)
                exp_pkt = pkt
                eg_port = expect_packet_data_list[index].to_dict()["port"]
                logger.info("Entry %d: Sending packet on ingress port %d and expecting on egress port %d",
                            count, self.ig_port, eg_port)
                testutils.send_packet(self, self.ig_port, str(pkt))
                testutils.verify_packets(self, exp_pkt, [eg_port])
                count += 1

        count = 1
        if no_packet_key_list and no_packet_data_list:
            for index in range(0, len(no_packet_key_list)):
                dmac = no_packet_key_list[index].to_dict()["hdr.ethernet.dst_addr"]["value"]
                pkt = testutils.simple_tcp_packet(eth_dst=dmac)
                exp_pkt = pkt
                logger.info("Entry %d: Sending packet on ingress port %d and expecting no packets",
                            count, self.ig_port)
                testutils.send_packet(self, self.ig_port, str(pkt))
                testutils.verify_no_other_packets(self)
                count += 1

    def get_entries_and_verify(self, from_hw = True):
        logger.info("Validating entries from %s", "HW" if from_hw else "SW")
        resp = self.forward_table.entry_get(self.target, None, {"from_hw": from_hw})
        i = 0
        key_list = self.key_list
        data_list = self.data_list
        if self.state == State.HITLESS_END:
            key_list = self.replayed_key_list
            data_list = self.replayed_data_list

        for data, key in resp:
            assert key == key_list[i], "received %s expected %s" %(str(key), str(key_list[i]))
            assert data == data_list[i]
            i += 1

    def setUp(self):
        self.p4_name = "tna_exact_match"
        HitlessBaseTestNegative.setUp(self)

class HitlessTnaTernaryMatchNegative(HitlessBaseTestNegative):
    """@brief This test does negative testing during replay.
    1. Only replays some entries back and makes sure packets are received only for those. 
    2. Modifies a few entries and makes sure the packets are received on modified ports.
    3. Don't replay any entries and make sure no packets were received.

    When encountered a failure, we issue a warm_init with fast_reconfig
    """

    def setup_tables(self):
        logger.info("Setting tables")
        self.forward_table = self.bfrt_info.table_get("SwitchIngress.forward")
        self.forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")

    def setup_test_data(self):
        logger.info("Setting test data")
        self.ig_port = swports[1]
        self.eg_port = swports[2]
        self.key_list = []
        self.data_list = []
        self.replayed_key_list = []
        self.replayed_data_list = []
        self.num_entries = 100
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.ip_random_list = self.generate_random_ip_list(self.num_entries, self.seed)
        self.prio = random.randint(1, 5000)
        for i in range(self.num_entries):
            key = self.forward_table.make_key(
                        [gc.KeyTuple('$MATCH_PRIORITY', self.prio),
                         gc.KeyTuple('vrf', 0),
                         gc.KeyTuple('hdr.ipv4.dst_addr',
                                     getattr(self.ip_random_list[i], "ip"),
                                     getattr(self.ip_random_list[i], "mask"))])
            data = self.forward_table.make_data([gc.DataTuple('port', self.eg_port)],
                                                 'SwitchIngress.hit')
            self.key_list.append(key)
            self.data_list.append(data)
            self.replayed_key_list.append(key)
            self.replayed_data_list.append(data)

    def add_entries(self):
        self.forward_table.entry_add(self.target, self.key_list, self.data_list)

    def init_replay_funcs(self):
        self.replay_func_list.append((self.replay_entries_1, False))
        self.replay_func_list.append((self.replay_entries_2, False))
        self.replay_func_list.append((self.replay_entries_3, False))

    def replay_entries_1(self):
        logger.info("Replay 1: Adding only some entries back")
        num_entries = self.num_entries
        for i in range(5):
            entry_idx = random.randint(0, num_entries - 1)
            self.replayed_key_list.pop(entry_idx)
            self.replayed_data_list.pop(entry_idx)
            num_entries -= 1

        self.forward_table.entry_add(self.target,
                                     self.replayed_key_list,
                                     self.replayed_data_list)

    def replay_entries_2(self):
        logger.info("Replay 2: Modify a few random entries")
        self.forward_table.entry_add(self.target, self.key_list, self.data_list)
        for i in range(self.num_entries):
            should_modify = bool(random.getrandbits(1))
            eg_port = self.eg_port
            if should_modify:
                eg_port = self.eg_port + 1

            data = self.forward_table.make_data([gc.DataTuple('port', eg_port)],
                                                 'SwitchIngress.hit')
            self.replayed_data_list[i] = data

        self.forward_table.entry_mod(self.target,
                                     self.key_list,
                                     self.replayed_data_list)

    def replay_entries_3(self):
        logger.info("Replay 3: Don't replay any entries")
        self.replayed_key_list = []
        self.replayed_data_list = []

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")
        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)

        '''
        Reset the original key and data lists based on what was replayed
        during this particular replay, as it will be used during the post
        hitless validation phase to decide what egress ports to expect or
        not expect packets on.
        '''
        self.key_list = []
        for item in self.replayed_key_list:
            self.key_list.append(item)
        self.data_list = []
        for item in self.replayed_data_list:
            self.data_list.append(item)

        # Delete all the entries and verify
        logger.info("Deleting all entries")
        self.forward_table.entry_del(self.target, self.replayed_key_list)
        self.replayed_key_list = []
        self.replayed_data_list = []

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        # Add a new entry and verify
        logger.info("Adding a new entry")
        new_key = self.forward_table.make_key(
                    [gc.KeyTuple('$MATCH_PRIORITY', self.prio),
                     gc.KeyTuple('vrf', 0),
                     gc.KeyTuple('hdr.ipv4.dst_addr',
                                 '255.255.255.255',
                                 '255.255.255.255')])
        new_data = self.forward_table.make_data([gc.DataTuple('port', self.eg_port)],
                                                 'SwitchIngress.hit')
        self.forward_table.entry_add(self.target, [new_key], [new_data])

        self.replayed_key_list.append(new_key)
        self.replayed_data_list.append(new_data)

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        # Modify the entry added above
        logger.info("Modifying the entry added before")
        new_data = self.forward_table.make_data([gc.DataTuple('port', self.eg_port + 1)],
                                                               "SwitchIngress.hit")
        self.forward_table.entry_mod(self.target, [self.replayed_key_list[0]], [new_data])
        self.replayed_data_list[0] = new_data

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("--- Post hitless validation ended ---")

    def send_traffic_and_verify_packets(self):
        logger.info("Sending traffic and verifying packets")
        expect_packet_key_list = self.key_list
        expect_packet_data_list = self.data_list
        no_packet_index_list = []
        if self.state == State.HITLESS_END:
            # Expect packets on the ports associated with the replayed entries
            expect_packet_key_list = self.replayed_key_list
            expect_packet_data_list = self.replayed_data_list

            '''
            Do not expect packets on the egress ports associted with the
            original entries, which were not replayed
            '''
            for key_idx in range(0, len(self.key_list)):
                key = self.key_list[key_idx]
                if key not in self.replayed_key_list:
                    no_packet_index_list.append(key_idx)

        count = 1
        if expect_packet_key_list and expect_packet_data_list:
            for index in range(0, len(expect_packet_key_list)):
                ip_dst = expect_packet_key_list[index].to_dict()["hdr.ipv4.dst_addr"]["value"]
                pkt = testutils.simple_tcp_packet(ip_dst=ip_dst)
                exp_pkt = pkt
                eg_port = expect_packet_data_list[index].to_dict()["port"]
                logger.info("Entry %d: Sending packet on ingress port %d and expecting on egress port %d",
                            count, self.ig_port, eg_port)
                testutils.send_packet(self, self.ig_port, str(pkt))
                testutils.verify_packets(self, exp_pkt, [eg_port])
                count += 1

        count = 1
        for index in no_packet_index_list:
            ip_dst = self.key_list[index].to_dict()["hdr.ipv4.dst_addr"]["value"]
            pkt = testutils.simple_tcp_packet(ip_dst=ip_dst)
            exp_pkt = pkt
            logger.info("Entry %d: Sending packet on ingress port %d and expecting no packets",
                        count, self.ig_port)
            testutils.send_packet(self, self.ig_port, str(pkt))
            testutils.verify_no_other_packets(self)
            count += 1

    def get_entries_and_verify(self, from_hw = True):
        logger.info("Validating entries from %s", "HW" if from_hw else "SW")
        resp = self.forward_table.entry_get(self.target, None, {"from_hw": from_hw})
        i = 0
        key_list = self.key_list
        data_list = self.data_list
        if self.state == State.HITLESS_END:
            key_list = self.replayed_key_list
            data_list = self.replayed_data_list

        for data, key in resp:
            key_list[i].apply_mask()
            assert key == key_list[i], "received %s expected %s" %(str(key), str(key_list[i]))
            assert data == data_list[i]
            i += 1

    def setUp(self):
        self.p4_name = "tna_ternary_match"
        HitlessBaseTestNegative.setUp(self)

class HitlessTnaPortMetadataNegative(HitlessBaseTestNegative):
    """@brief This test does negative testing during replay.
    1. Only replays some entries back and makes sure packets are received only for those. 
    2. Modifies a few entries and makes sure the packets are received on modified ports.
    3. Don't replay any entries and make sure no packets were received.

    When encountered a failure, we issue a warm_init with fast_reconfig
    """

    def setup_tables(self):
        logger.info("Setting tables")
        self.port_metadata_table = self.bfrt_info.table_get("SwitchIngressParser.$PORT_METADATA")
        self.port_md_exm_match_table = self.bfrt_info.table_get("SwitchIngress.port_md_exm_match")

    def make_phase0_data(self, field1, field2, field3, field4):
        """
        Pack all fields into one phase0_data. For tofino 2, it is
        left shifted 64 more because the field is a 128 bit value
        """
        phase0data = (field1 << 48) | (field2 << 24) | (field3 << 8) | field4
        if testutils.test_param_get("arch") == "tofino2":
            phase0data = phase0data << 64
        return phase0data

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.target = gc.Target(device_id=0, pipe_id=0xffff)

        # Generate random ingress and egress ports
        self.igr_to_egr_port_map = {}
        self.replayed_igr_to_egr_port_map = {}
        self.num_entries = 10
        igr_port_list = random.sample(swports, self.num_entries)
        egr_port_list = random.sample(swports, self.num_entries)
        for x in range(self.num_entries):
            self.igr_to_egr_port_map[igr_port_list[x]] = egr_port_list[x]
            self.replayed_igr_to_egr_port_map[igr_port_list[x]] = egr_port_list[x]

        # Initialize the phase0 data map
        self.phase0_data_map = {}
        for igr_port, egr_port in list(self.igr_to_egr_port_map.items()):
            self.phase0_data_map[igr_port] = 0

        self.key_list = []
        self.data_list = []
        self.pm_dict = {}
        self.replayed_pm_dict = {}
        self.exm_key_list = []
        self.exm_data_list = []
        self.exm_dict = {}
        self.replayed_exm_dict = {}
        for igr_port, egr_port in list(self.igr_to_egr_port_map.items()):
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
            self.replayed_pm_dict[self.key_list[-1]] = self.data_list[-1]

            # Entry for the igr port in the exact match table
            self.exm_key_list += [self.port_md_exm_match_table.make_key(
                    [gc.KeyTuple('ig_md.port_md.field1', field1),
                     gc.KeyTuple('ig_md.port_md.field2', field2),
                     gc.KeyTuple('ig_md.port_md.field3', field3),
                     gc.KeyTuple('ig_md.port_md.field4', field4)])]
            self.exm_data_list += [self.port_md_exm_match_table.make_data(
                    [gc.DataTuple('port', egr_port)],
                    'SwitchIngress.hit')]
            self.exm_dict[self.exm_key_list[-1]] = self.exm_data_list[-1]
            self.replayed_exm_dict[self.exm_key_list[-1]] = self.exm_data_list[-1]

    def add_entries(self):
        self.port_metadata_table.entry_add(self.target, self.key_list, self.data_list)
        self.port_md_exm_match_table.entry_add(self.target, self.exm_key_list, self.exm_data_list)

    def init_replay_funcs(self):
        self.replay_func_list.append((self.replay_entries_1, False))
        self.replay_func_list.append((self.replay_entries_2, False))
        self.replay_func_list.append((self.replay_entries_3, False))

    def replay_entries_1(self):
        logger.info("Replay 1: Adding only some entries back")
        num_entries = self.num_entries
        for i in range(5):
            entry_idx = random.randint(0, num_entries - 1)

            igr_port = self.key_list[entry_idx].to_dict()["ig_intr_md.ingress_port"]["value"]
            self.replayed_igr_to_egr_port_map.pop(igr_port)

            self.replayed_pm_dict.pop(self.key_list[entry_idx])
            self.key_list.pop(entry_idx)
            self.data_list.pop(entry_idx)

            self.replayed_exm_dict.pop(self.exm_key_list[entry_idx])
            self.exm_key_list.pop(entry_idx)
            self.exm_data_list.pop(entry_idx)

            num_entries -= 1

        self.port_metadata_table.entry_add(self.target, self.key_list, self.data_list)
        self.port_md_exm_match_table.entry_add(self.target, self.exm_key_list, self.exm_data_list)

    def replay_entries_2(self):
        logger.info("Replay 2: Modify a few random entries")
        self.port_metadata_table.entry_add(self.target, self.key_list, self.data_list)
        self.port_md_exm_match_table.entry_add(self.target, self.exm_key_list, self.exm_data_list)

        for i in range(self.num_entries):
            should_modify = bool(random.getrandbits(1))
            if should_modify:
                igr_port = self.key_list[i].to_dict()["ig_intr_md.ingress_port"]["value"]
                egr_port = self.exm_data_list[(i + 1) % self.num_entries].to_dict()["port"]
                data = self.port_md_exm_match_table.make_data([gc.DataTuple('port', egr_port)],
                                                               'SwitchIngress.hit')
                self.port_md_exm_match_table.entry_mod(self.target,
                                                       [self.exm_key_list[i]],
                                                       [data])

                self.replayed_igr_to_egr_port_map[igr_port] = egr_port
                self.replayed_exm_dict[self.exm_key_list[i]] = data

    def replay_entries_3(self):
        logger.info("Replay 3: Don't replay any entries")
        self.key_list = []
        self.data_list = []
        self.exm_key_list = []
        self.exm_data_list = []
        self.replayed_igr_to_egr_port_map = {}
        self.replayed_pm_dict = {}
        self.replayed_exm_dict = {}

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")
        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)

        '''
        Reset the original data structures based on what was replayed
        during this particular replay, as it will be used during the post
        hitless validation phase to decide what egress ports to expect or
        not expect packets on.
        '''
        self.igr_to_egr_port_map = {}
        for i, j in self.replayed_igr_to_egr_port_map.iteritems():
            self.igr_to_egr_port_map[i] = j

        self.pm_dict = {}
        for i, j in self.replayed_pm_dict.iteritems():
            self.pm_dict[i] = j

        self.exm_dict = {}
        for i, j in self.replayed_exm_dict.iteritems():
            self.exm_dict[i] = j

        # Delete all the entries and verify
        logger.info("Deleting all entries")
        self.port_metadata_table.entry_del(self.target, self.key_list)
        self.port_md_exm_match_table.entry_del(self.target, self.exm_key_list)

        self.replayed_igr_to_egr_port_map = {}
        self.replayed_pm_dict = {}
        self.replayed_exm_dict = {}

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        # Add a new entry and verify
        logger.info("Adding a new entry")
        igr_port = random.sample(swports, 1)[0]
        egr_port = random.sample(swports, 1)[0]
        self.replayed_igr_to_egr_port_map[igr_port] = egr_port
        self.phase0_data_map[igr_port] = 0

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

        new_key = self.port_metadata_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', igr_port)])
        new_data = self.port_metadata_table.make_data([gc.DataTuple('$DEFAULT_FIELD', phase0data)])
        self.replayed_pm_dict[new_key] = new_data

        # Entry for the igr port in the exact match table
        new_exm_key = self.port_md_exm_match_table.make_key(
                [gc.KeyTuple('ig_md.port_md.field1', field1),
                 gc.KeyTuple('ig_md.port_md.field2', field2),
                 gc.KeyTuple('ig_md.port_md.field3', field3),
                 gc.KeyTuple('ig_md.port_md.field4', field4)])
        new_exm_data = self.port_md_exm_match_table.make_data(
                [gc.DataTuple('port', egr_port)],
                'SwitchIngress.hit')
        self.replayed_exm_dict[new_exm_key] = new_exm_data

        self.port_metadata_table.entry_add(self.target, [new_key], [new_data])
        self.port_md_exm_match_table.entry_add(self.target, [new_exm_key], [new_exm_data])

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        # Modify the entry added above (seems to have issues)
        logger.info("Modifying the entry added before")
        egr_port = random.sample(swports, 1)[0]
        data = self.port_md_exm_match_table.make_data([gc.DataTuple('port', egr_port)],
                                                                    'SwitchIngress.hit')
        self.port_md_exm_match_table.entry_mod(self.target, [new_exm_key], [data])

        self.replayed_igr_to_egr_port_map[igr_port] = egr_port
        self.replayed_exm_dict[new_exm_key] = data

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("--- Post hitless validation ended ---")

    def send_traffic_and_verify_packets(self):
        logger.info("Sending traffic and verifying packets")

        # Figure out what ports to expect or not expect packets on
        no_packet_igr_to_egr_port_map = {}
        expect_packet_igr_to_egr_port_map = self.igr_to_egr_port_map
        if self.state == State.HITLESS_END:
            expect_packet_igr_to_egr_port_map = self.replayed_igr_to_egr_port_map
            for igr_port, egr_port in list(self.igr_to_egr_port_map.items()):
                if not igr_port in self.replayed_igr_to_egr_port_map:
                    no_packet_igr_to_egr_port_map[igr_port] = egr_port

        pkt = testutils.simple_tcp_packet()
        exp_pkt = pkt
        count = 1
        for igr_port, egr_port in list(expect_packet_igr_to_egr_port_map.items()):
            logger.info("Entry %d: Sending packet on port %d and expecting one on port %d", count, igr_port, egr_port)
            testutils.send_packet(self, igr_port, pkt)
            testutils.verify_packet(self, exp_pkt, egr_port)
            count += 1

        for igr_port, egr_port in list(no_packet_igr_to_egr_port_map.items()):
            logger.info("Entry %d: Sending packet on port %d and expecting no packets", count, igr_port)
            testutils.send_packet(self, igr_port, pkt)
            testutils.verify_no_other_packets(self)
            count += 1

    def get_entries_and_verify(self, from_hw = True):
        logger.info("Validating entries from %s", "HW" if from_hw else "SW")

        pm_dict = self.pm_dict
        exm_dict = self.exm_dict
        if self.state == State.HITLESS_END:
            pm_dict = self.replayed_pm_dict
            exm_dict = self.replayed_exm_dict

        resp = self.port_metadata_table.entry_get(self.target, None, {"from_hw": from_hw})
        for data, key in resp:
            assert pm_dict[key] == data

        resp = self.port_md_exm_match_table.entry_get(self.target, None, {"from_hw": from_hw})
        for data, key in resp:
            assert exm_dict[key] == data

    def setUp(self):
        self.p4_name = "tna_port_metadata"
        HitlessBaseTestNegative.setUp(self)

class HitlessTnaExactMatchEntrySingleScopeNegative(HitlessBaseTestNegative):
    """@brief This test does negative testing during replay.
    1. Replay entry only on one pipe
    2. Modify the entry on both the pipes
    3. Don't replay the entry on both the pipes
    4. Delete the entry on one pipe

    When encountered a failure, we issue a warm_init with fast_reconfig
    """

    def setup_tables(self):
        logger.info("Setting tables")
        self.forward_table = self.bfrt_info.table_get("SwitchIngress.forward")
        self.forward_table.info.key_field_annotation_add("hdr.ethernet.dst_addr", "mac")

    def setup_test_data(self):
        logger.info("Setting test data")
        self.dmac = '22:22:22:22:22:22'
        self.ig_port = swports[1]
        self.eg_port = swports[2]
        self.replay_eg_port = self.eg_port
        self.target_pipes = [False] * 4
        self.replay_target_pipes = [False] * 4
        self.target = gc.Target(device_id=0, pipe_id=0xffff)

        # Set all pipes to be in different scopes. Also known as Single scope
        self.forward_table.attribute_entry_scope_set(self.target,
                predefined_pipe_scope=True,
                predefined_pipe_scope_val=bfruntime_pb2.Mode.SINGLE)

    def add_entries(self):
        self.key_list = [self.forward_table.make_key([gc.KeyTuple('hdr.ethernet.dst_addr', self.dmac)])]
        self.data_list = [self.forward_table.make_data([gc.DataTuple('port', self.eg_port)],
                                                   "SwitchIngress.hit")]
        # Add entries for pipe 0 and 2
        target = gc.Target(device_id=0, pipe_id=0x00)
        self.forward_table.entry_add(target, self.key_list, self.data_list)
        self.target_pipes[0] = True

        target = gc.Target(device_id=0, pipe_id=0x02)
        self.forward_table.entry_add(target, self.key_list, self.data_list)
        self.target_pipes[2] = True

    def init_replay_funcs(self):
        self.replay_func_list.append((self.replay_entries_1, False))
        self.replay_func_list.append((self.replay_entries_2, False))
        self.replay_func_list.append((self.replay_entries_3, False))
        self.replay_func_list.append((self.replay_entries_4, False))

    def replay_entries_1(self):
        logger.info("Replay 1: Replay the entry only on pipe 2")
        target = gc.Target(device_id=0, pipe_id=0x02)
        self.forward_table.entry_add(target, self.key_list, self.data_list)
        self.replay_target_pipes[2] = True

    def replay_entries_2(self):
        logger.info("Replay 2: Modify the entry on pipe 0 and pipe 2")
        target0 = gc.Target(device_id=0, pipe_id=0x00)
        target2 = gc.Target(device_id=0, pipe_id=0x02)

        self.forward_table.entry_add(target0, self.key_list, self.data_list)
        self.forward_table.entry_add(target2, self.key_list, self.data_list)

        self.replay_eg_port = self.eg_port + 1
        self.data_list = [self.forward_table.make_data([gc.DataTuple('port', self.replay_eg_port)],
                                                                     "SwitchIngress.hit")]

        self.forward_table.entry_mod(target0, self.key_list, self.data_list)
        self.replay_target_pipes[0] = True

        self.forward_table.entry_mod(target2, self.key_list, self.data_list)
        self.replay_target_pipes[2] = True

    def replay_entries_3(self):
        logger.info("Replay 3: Don't replay any entries")

    def replay_entries_4(self):
        logger.info("Replay 4: Delete the entry on pipe 0")
        target = gc.Target(device_id=0, pipe_id=0x00)
        self.forward_table.entry_add(target, self.key_list, self.data_list)
        self.forward_table.entry_del(target, self.key_list)
        self.replay_target_pipes[0] = False

        target = gc.Target(device_id=0, pipe_id=0x02)
        self.forward_table.entry_add(target, self.key_list, self.data_list)
        self.replay_target_pipes[2] = True

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")
        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)

        '''
        Reset the original target_pipes list based on what was replayed
        during this particular replay, as it will be used during the post
        hitless validation phase.
        '''
        self.target_pipes = []
        for pipe in self.replay_target_pipes:
            self.target_pipes.append(pipe)

        # Add a new entry and verify
        logger.info("Adding new entries for pipe 1 and 3")
        target = gc.Target(device_id=0, pipe_id=0x01)
        self.forward_table.entry_add(target, self.key_list, self.data_list)
        self.replay_target_pipes[1] = True

        target = gc.Target(device_id=0, pipe_id=0x03)
        self.forward_table.entry_add(target, self.key_list, self.data_list)
        self.replay_target_pipes[3] = True

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        # Modify the entries added before
        logger.info("Modifying the entries added before")
        for pipe_idx in range(0, len(self.replay_target_pipes)):
            if self.replay_target_pipes[pipe_idx]:
                self.replay_eg_port = self.eg_port + 1
                new_data = self.forward_table.make_data([gc.DataTuple('port', self.replay_eg_port)],
                                                                      "SwitchIngress.hit")
                target = gc.Target(device_id=0, pipe_id=pipe_idx)
                self.forward_table.entry_mod(target, self.key_list, [new_data])

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        # Delete a few entries and verify
        logger.info("Deleting a few entries")
        for pipe_idx in range(0, len(self.replay_target_pipes)):
            if self.replay_target_pipes[pipe_idx]:
                should_delete = bool(random.getrandbits(1))
                if should_delete:
                    target = gc.Target(device_id=0, pipe_id=pipe_idx)
                    self.forward_table.entry_del(target, self.key_list)
                    self.replay_target_pipes[pipe_idx] = False

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("--- Post hitless validation ended ---")

    def send_traffic_and_verify_packets(self):
        logger.info("Sending traffic and verifying packets")
        def send_and_verify_packet(self, ingress_port, egress_port, pkt, exp_pkt):
            logger.info("Sending packet on port %d, expecting packet on port %d", ingress_port, egress_port)
            testutils.send_packet(self, ingress_port, pkt)
            testutils.verify_packet(self, exp_pkt, egress_port)

        def send_and_verify_no_other_packet(self, ingress_port, pkt):
            logger.info("Sending packet on port %d (negative test); expecting no packet", ingress_port)
            testutils.send_packet(self, ingress_port, pkt)
            testutils.verify_no_other_packets(self)

        expect_packet_in_pipe = self.target_pipes
        eg_port = self.eg_port
        if self.state == State.HITLESS_END:
            expect_packet_in_pipe = self.replay_target_pipes
            eg_port = self.replay_eg_port

        pkt = testutils.simple_tcp_packet(eth_dst=self.dmac)
        exp_pkt = pkt
        for pipe_idx in range(0, len(swports_by_pipe)):
            for port in swports_by_pipe[pipe_idx]:
                if expect_packet_in_pipe[pipe_idx]:
                    send_and_verify_packet(self, port, eg_port, pkt, exp_pkt)
                else:
                    send_and_verify_no_other_packet(self, port, pkt)

    def get_entries_and_verify(self, from_hw = True):
        logger.info("Validating entries from %s", "HW" if from_hw else "SW")
        resp = self.forward_table.attribute_get(self.target, "EntryScope")
        for data in resp:
            assert data["gress_scope"]["predef"] == bfruntime_pb2.Mode.ALL
            assert data["pipe_scope"]["predef"] == bfruntime_pb2.Mode.SINGLE
            assert data["prsr_scope"]["predef"] == bfruntime_pb2.Mode.ALL

        target_pipes = self.target_pipes
        eg_port = self.eg_port
        if self.state == State.HITLESS_END:
            target_pipes = self.replay_target_pipes
            eg_port = self.replay_eg_port

        for pipe_idx in range(0, len(target_pipes)):
            if target_pipes[pipe_idx]:
                target = gc.Target(device_id=0, pipe_id=pipe_idx)
                resp = self.forward_table.entry_get(target, None, {"from_hw": from_hw})
                for data, key in resp:
                    data_dict = data.to_dict()
                    key_dict = key.to_dict()
                    assert data_dict["port"] == eg_port
                    assert key_dict["hdr.ethernet.dst_addr"]["value"] == self.dmac

    def setUp(self):
        self.p4_name = "tna_exact_match"
        HitlessBaseTestNegative.setUp(self)

class HitlessTnaLpmAlpmNegative(HitlessBaseTestNegative):
    """@brief This test does negative testing during replay.
    1. Only replay some entries back
    2. Modify a few random entries
    3. Don't replay any entries

    When encountered a failure, we issue a warm_init with fast_reconfig
    """

    def setup_tables(self):
        logger.info("Setting tables")
        self.alpm_forward_table = self.bfrt_info.table_get("SwitchIngress.alpm_forward")
        self.alpm_forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
        self.alpm_forward_table.info.data_field_annotation_add("srcMac", "SwitchIngress.route", "mac")
        self.alpm_forward_table.info.data_field_annotation_add("dstMac", "SwitchIngress.route", "mac")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.key_list = []
        self.data_list = []
        self.alpm_dict = {}
        self.replayed_alpm_dict = {}
        self.num_entries = 10
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
            self.key_list += [self.alpm_forward_table.make_key([gc.KeyTuple('vrf', vrf),
                                              gc.KeyTuple('hdr.ipv4.dst_addr', dst_ip, prefix_len=p_len)])]
            self.data_list += [self.alpm_forward_table.make_data([gc.DataTuple('dst_port', eg_port),
                                                                  gc.DataTuple('srcMac', srcMac),
                                                                  gc.DataTuple('dstMac', dstMac)],
                                                                  'SwitchIngress.route')]
            self.key_list[-1].apply_mask()
            self.alpm_dict[self.key_list[-1]] = self.data_list[-1]
            self.replayed_alpm_dict[self.key_list[-1]] = self.data_list[-1]

    def add_entries(self):
        self.alpm_forward_table.entry_add(self.target, self.key_list, self.data_list)

    def init_replay_funcs(self):
        self.replay_func_list.append((self.replay_entries_1, False))
        self.replay_func_list.append((self.replay_entries_2, False))
        self.replay_func_list.append((self.replay_entries_3, False))

    def replay_entries_1(self):
        logger.info("Replay 1: Adding only some entries back")
        new_key_list = []
        new_data_list = []
        count = 1
        for key, data in list(self.alpm_dict.items()):
            should_add = bool(random.getrandbits(1))
            if should_add:
                new_key_list.append(key)
                new_data_list.append(data)
                logger.info("Entry %d: Added", count)
            else:
                self.replayed_alpm_dict.pop(key)
                logger.info("Entry %d: Skipped", count)
            count += 1

        self.alpm_forward_table.entry_add(self.target, new_key_list, new_data_list)

    def replay_entries_2(self):
        logger.info("Replay 2: Modify a few random entries")
        self.alpm_forward_table.entry_add(self.target, self.key_list, self.data_list)

        count = 1
        for i in range(self.num_entries):
            should_modify = bool(random.getrandbits(1))
            if should_modify:
                data = self.data_list[i]
                eg_port = self.data_list[i].to_dict()["dst_port"]
                srcMac = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple([random.randint(0, 255) for x in range(6)])
                dstMac = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple([random.randint(0, 255) for x in range(6)])
                new_data = self.alpm_forward_table.make_data([gc.DataTuple('dst_port', eg_port),
                                                              gc.DataTuple('srcMac', srcMac),
                                                              gc.DataTuple('dstMac', dstMac)],
                                                              'SwitchIngress.route')
                self.alpm_forward_table.entry_mod(self.target,
                                                  [self.key_list[i]],
                                                  [new_data])
                self.replayed_alpm_dict[self.key_list[i]] = new_data
                logger.info("Entry %d: Modified", count)
            else:
                logger.info("Entry %d: Was not modified", count)
            count += 1

    def replay_entries_3(self):
        logger.info("Replay 3: Don't replay any entries")
        self.replayed_alpm_dict = {}

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")
        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)

        '''
        Reset the original data structures based on what was replayed
        during this particular replay, as it will be used during the post
        hitless validation phase to decide what egress ports to expect or
        not expect packets on.
        '''
        self.alpm_dict = {}
        self.key_list = []
        self.data_list = []
        for i, j in self.replayed_alpm_dict.iteritems():
            self.alpm_dict[i] = j
            self.key_list.append(i)
            self.data_list.append(j)

        # Delete all the entries and verify (fails)
        '''
        logger.info("Deleting all entries")
        self.alpm_forward_table.entry_del(self.target, self.key_list)

        self.replayed_alpm_dict = {}

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()
        '''

        # Add a new entry and verify (fails)
        '''
        logger.info("Adding a new entry")
        vrf = 0
        ip_list = self.generate_random_ip_list(1, self.seed)
        dst_ip = getattr(ip_list[0], "ip")
        p_len = getattr(ip_list[0], "prefix_len")
        srcMac = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple([random.randint(0, 255) for x in range(6)])
        dstMac = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple([random.randint(0, 255) for x in range(6)])
        eg_port = swports[random.randint(1, 4)]
        key = self.alpm_forward_table.make_key([gc.KeyTuple('vrf', vrf),
                                                gc.KeyTuple('hdr.ipv4.dst_addr', dst_ip, prefix_len=p_len)])
        data = self.alpm_forward_table.make_data([gc.DataTuple('dst_port', eg_port),
                                                  gc.DataTuple('srcMac', srcMac),
                                                  gc.DataTuple('dstMac', dstMac)],
                                                  'SwitchIngress.route')
        key.apply_mask()
        self.replayed_alpm_dict[key] = data

        self.alpm_forward_table.entry_add(self.target, [key], [data])

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()
        '''

        logger.info("--- Post hitless validation ended ---")

    def send_traffic_and_verify_packets(self):
        logger.info("Sending traffic and verifying packets")

        '''
        Figure out what ports to expect or not expect packets on
        If hitless was over, the packets should only be expected
        on the ports belonging to the replayed entries and no
        packets should be expected on the ports belonging to the
        entries which were originally added, but were not replayed.
        '''
        no_packet_alpm_dict = {}
        expect_packet_alpm_dict = self.alpm_dict
        if self.state == State.HITLESS_END:
            expect_packet_alpm_dict = self.replayed_alpm_dict
            for key, data in list(self.alpm_dict.items()):
                if not key in self.replayed_alpm_dict:
                    no_packet_alpm_dict[key] = data

        count = 1
        for k, d in list(expect_packet_alpm_dict.items()):
            key = k.to_dict()
            data = d.to_dict()
            pkt = testutils.simple_tcp_packet(ip_dst=key["hdr.ipv4.dst_addr"]["value"])
            exp_pkt = testutils.simple_tcp_packet(eth_dst=data["dstMac"],
                                                  eth_src=data["srcMac"],
                                                  ip_dst=key["hdr.ipv4.dst_addr"]["value"])
            logger.info("Entry %d: (IP: %s, Prefix length: %d) Sending packet on port %d and expecting one on port %d",
                count, key["hdr.ipv4.dst_addr"]["value"], key["hdr.ipv4.dst_addr"]["prefix_len"],
                self.ig_port, data["dst_port"])
            testutils.send_packet(self, self.ig_port, pkt)
            testutils.verify_packet(self, exp_pkt, data["dst_port"])
            count += 1

        count = 1
        for k, d in list(no_packet_alpm_dict.items()):
            key = k.to_dict()
            data = d.to_dict()
            pkt = testutils.simple_tcp_packet(ip_dst=key["hdr.ipv4.dst_addr"]["value"])
            exp_pkt = testutils.simple_tcp_packet(eth_dst=data["dstMac"],
                                                  eth_src=data["srcMac"],
                                                  ip_dst=key["hdr.ipv4.dst_addr"]["value"])
            logger.info("Entry %d: Sending packet on port %d and expecting no packets",
                count, self.ig_port)
            testutils.send_packet(self, self.ig_port, pkt)
            testutils.verify_no_other_packets(self)
            count += 1

    def get_entries_and_verify(self, from_hw = True):
        logger.info("Validating entries from %s", "HW" if from_hw else "SW")

        alpm_dict = self.alpm_dict

        # If hitless was over, verify entries based on what entries were replayed
        if self.state == State.HITLESS_END:
            alpm_dict = self.replayed_alpm_dict

        resp = self.alpm_forward_table.entry_get(self.target)
        for data, key in resp:
            assert alpm_dict[key] == data

    def setUp(self):
        self.p4_name = "tna_lpm_match"
        HitlessBaseTestNegative.setUp(self)

class HitlessTnaTernaryMatchIndirectNegative(HitlessBaseTestNegative):
    """@brief This test does negative testing during replay.
    1. Only replay some entries back
    2. Modify a few random entries
    3. Don't replay any entries

    When encountered a failure, we issue a warm_init with fast_reconfig
    """

    def setup_tables(self):
        logger.info("Setting tables")
        self.action_profile_table = self.bfrt_info.table_get("SwitchIngress.action_profile")
        self.tcam_direct_lpf_table = self.bfrt_info.table_get("SwitchIngress.tcam_direct_lpf")
        self.action_profile_table.info.data_field_annotation_add("srcAddr", "SwitchIngress.change_ipsrc", "ipv4")
        self.action_profile_table.info.data_field_annotation_add("dstAddr", "SwitchIngress.change_ipdst", "ipv4")
        self.tcam_direct_lpf_table.info.key_field_annotation_add("hdr.ethernet.dst_addr", "mac")
        self.tcam_direct_lpf_table.info.key_field_annotation_add("hdr.ethernet.src_addr", "mac")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.num_entries = 10
        self.ig_ports = [random.choice(swports) for x in range(self.num_entries)]
        self.eg_ports = [random.choice(swports) for x in range(self.num_entries)]
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.action = [random.choice(['SwitchIngress.change_ipsrc', 'SwitchIngress.change_ipdst']) for x in range(self.num_entries)]
        self.action_mbr_ids = [x + 1 for x in range(self.num_entries)]

        self.action_id_to_ig_port_dict = {}
        for i in range(0, len(self.action_mbr_ids)):
            self.action_id_to_ig_port_dict[self.action_mbr_ids[i]] = self.ig_ports[i]

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
        self.priorities = [x for x in range(self.num_entries)]
        random.shuffle(self.priorities)

        self.srcMacAddrtuple = self.generate_random_mac_list(self.num_entries, self.seed)
        self.dstMacAddrtuple = self.generate_random_mac_list(self.num_entries, self.seed)

        self.srcMacAddrs = [getattr(each, "mac") for each in self.srcMacAddrtuple]
        self.srcMacAddrsMask = [getattr(each, "mask") for each in self.srcMacAddrtuple]

        self.dstMacAddrs = [getattr(each, "mac") for each in self.dstMacAddrtuple]
        self.dstMacAddrsMask = [getattr(each, "mask") for each in self.dstMacAddrtuple]

        self.action_key_list = []
        self.action_data_list = []
        self.action_table_dict = {}
        self.replayed_action_table_dict = {}

        self.tcam_key_list = []
        self.tcam_data_list = []
        self.tcam_table_dict = {}
        self.replayed_tcam_table_dict = {}

        self.replayed_action_key_list = []
        self.replayed_action_data_list = []
        self.replayed_tcam_key_list = []
        self.replayed_tcam_data_list = []

        for x in range(self.num_entries):
            self.action_key_list += [self.action_profile_table.make_key([gc.KeyTuple('$ACTION_MEMBER_ID', self.action_mbr_ids[x])])]
            if self.action[x] == 'SwitchIngress.change_ipsrc':
                self.action_data_list += [self.action_profile_table.make_data([gc.DataTuple('dst_port', self.eg_ports[x]),
                                                                               gc.DataTuple('srcAddr', self.ipSrcAddrs[x])],
                                                                               'SwitchIngress.change_ipsrc')]
            elif self.action[x] == 'SwitchIngress.change_ipdst':
                self.action_data_list += [self.action_profile_table.make_data([gc.DataTuple('dst_port', self.eg_ports[x]),
                                                                               gc.DataTuple('dstAddr', self.ipDstAddrs[x])],
                                                                               'SwitchIngress.change_ipdst')]

            self.action_table_dict[self.action_key_list[-1]] = self.action_data_list[-1]
            self.replayed_action_table_dict[self.action_key_list[-1]] = self.action_data_list[-1]

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

            self.tcam_table_dict[self.tcam_key_list[-1]] = self.tcam_data_list[-1]
            self.replayed_tcam_table_dict[self.tcam_key_list[-1]] = self.tcam_data_list[-1]

    def add_entries(self):
        self.action_profile_table.entry_add(self.target, self.action_key_list, self.action_data_list)
        self.tcam_direct_lpf_table.entry_add(self.target, self.tcam_key_list, self.tcam_data_list)

    def init_replay_funcs(self):
        self.replay_func_list.append((self.replay_entries_1, False))
        self.replay_func_list.append((self.replay_entries_2, False))
        self.replay_func_list.append((self.replay_entries_3, False))

    def replay_entries_1(self):
        logger.info("Replay 1: Adding only some entries back")
        self.replayed_action_table_dict = {}
        self.replayed_tcam_table_dict = {}
        for i in range(self.num_entries):
            should_add = bool(random.getrandbits(1))
            if not should_add:
                logger.info("Entry %d: Skipped", i)
                continue

            logger.info("Entry %d: Added", i)
            self.replayed_action_key_list.append(self.action_key_list[i])
            self.replayed_action_data_list.append(self.action_data_list[i])
            self.replayed_action_table_dict[self.action_key_list[i]] = self.action_data_list[i]

            self.replayed_tcam_key_list.append(self.tcam_key_list[i])
            self.replayed_tcam_data_list.append(self.tcam_data_list[i])
            self.replayed_tcam_table_dict[self.tcam_key_list[i]] = self.tcam_data_list[i]

        self.action_profile_table.entry_add(self.target, self.replayed_action_key_list, self.replayed_action_data_list)
        self.tcam_direct_lpf_table.entry_add(self.target, self.replayed_tcam_key_list, self.replayed_tcam_data_list)

    def replay_entries_2(self):
        logger.info("Replay 2: Modify a few entries")

        # Add the original entries first
        self.action_profile_table.entry_add(self.target, self.action_key_list, self.action_data_list)
        self.tcam_direct_lpf_table.entry_add(self.target, self.tcam_key_list, self.tcam_data_list)

        # Modify a few of them
        for x in range(self.num_entries):
            should_modify = bool(random.getrandbits(1))
            if should_modify:
                logger.info("Entry %d: Modified", x)
                new_eg_port = self.eg_ports[(x + 1) % self.num_entries]
                if self.action[x] == 'SwitchIngress.change_ipsrc':
                    new_data = self.action_profile_table.make_data([gc.DataTuple('dst_port', new_eg_port),
                                                                                 gc.DataTuple('srcAddr', self.ipSrcAddrs[x])],
                                                                                 'SwitchIngress.change_ipsrc')
                elif self.action[x] == 'SwitchIngress.change_ipdst':
                    new_data = self.action_profile_table.make_data([gc.DataTuple('dst_port', new_eg_port),
                                                                                 gc.DataTuple('dstAddr', self.ipDstAddrs[x])],
                                                                                 'SwitchIngress.change_ipdst')

                self.replayed_action_table_dict[self.action_key_list[x]] = new_data
                self.action_profile_table.entry_mod(self.target, [self.action_key_list[x]], [new_data])

    def replay_entries_3(self):
        logger.info("Replay 3: Don't replay any entries")
        self.replayed_action_table_dict = {}
        self.replayed_tcam_table_dict = {}

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")
        self.get_entries_and_verify(from_hw=True)
        # Broken
        # self.get_entries_and_verify(from_hw=False)

        '''
        Reset the original data structures based on what was replayed
        during this particular replay, as it will be used during the post
        hitless validation phase to decide what egress ports to expect or
        not expect packets on.
        '''
        self.action_table_dict = {}
        for i, j in self.replayed_action_table_dict.iteritems():
            self.action_table_dict[i] = j

        self.tcam_table_dict = {}
        for i, j in self.replayed_tcam_table_dict.iteritems():
            self.tcam_table_dict[i] = j

        # Delete all the entries and verify
        logger.info("Step 1: Deleting all entries")

        '''
        Delete entries from the tcam table followed by the ones in the action table
        as the entries in the action table can't be deleted while they are being
        referenced by the ones inside the tcam table.
        '''
        self.tcam_direct_lpf_table.entry_del(self.target, self.replayed_tcam_key_list)
        self.action_profile_table.entry_del(self.target, self.replayed_action_key_list)
        self.replayed_action_table_dict = {}
        self.replayed_tcam_table_dict = {}

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        # Add a few new entries and verify
        logger.info("Step 2: Adding a few new entries")
        self.action_table_dict = {}
        self.tcam_table_dict = {}
        self.num_entries = 5
        self.ig_ports = [random.choice(swports) for x in range(self.num_entries)]
        self.eg_ports = [random.choice(swports) for x in range(self.num_entries)]
        self.action = [random.choice(['SwitchIngress.change_ipsrc', 'SwitchIngress.change_ipdst']) for x in range(self.num_entries)]
        self.action_mbr_ids = [x + 1 for x in range(self.num_entries)]
        for i in range(0, len(self.action_mbr_ids)):
            self.action_id_to_ig_port_dict[self.action_mbr_ids[i]] = self.ig_ports[i]
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
        self.priorities = [x for x in range(self.num_entries)]
        random.shuffle(self.priorities)

        self.srcMacAddrtuple = self.generate_random_mac_list(self.num_entries, self.seed)
        self.dstMacAddrtuple = self.generate_random_mac_list(self.num_entries, self.seed)

        self.srcMacAddrs = [getattr(each, "mac") for each in self.srcMacAddrtuple]
        self.srcMacAddrsMask = [getattr(each, "mask") for each in self.srcMacAddrtuple]

        self.dstMacAddrs = [getattr(each, "mac") for each in self.dstMacAddrtuple]
        self.dstMacAddrsMask = [getattr(each, "mask") for each in self.dstMacAddrtuple]

        self.replayed_action_key_list = []
        self.replayed_action_data_list = []
        self.replayed_tcam_key_list = []
        self.replayed_tcam_data_list = []
        for x in range(self.num_entries):
            self.replayed_action_key_list += [self.action_profile_table.make_key([gc.KeyTuple('$ACTION_MEMBER_ID', self.action_mbr_ids[x])])]
            if self.action[x] == 'SwitchIngress.change_ipsrc':
                self.replayed_action_data_list += [self.action_profile_table.make_data([gc.DataTuple('dst_port', self.eg_ports[x]),
                                                                               gc.DataTuple('srcAddr', self.ipSrcAddrs[x])],
                                                                               'SwitchIngress.change_ipsrc')]
            elif self.action[x] == 'SwitchIngress.change_ipdst':
                self.replayed_action_data_list += [self.action_profile_table.make_data([gc.DataTuple('dst_port', self.eg_ports[x]),
                                                                               gc.DataTuple('dstAddr', self.ipDstAddrs[x])],
                                                                               'SwitchIngress.change_ipdst')]
            self.replayed_action_table_dict[self.replayed_action_key_list[-1]] = self.replayed_action_data_list[-1]

            self.replayed_tcam_key_list += [self.tcam_direct_lpf_table.make_key([gc.KeyTuple('$MATCH_PRIORITY', self.priorities[x]),
                                             gc.KeyTuple('hdr.ethernet.dst_addr',
                                                         self.dstMacAddrs[x],
                                                         self.dstMacAddrsMask[x]),
                                             gc.KeyTuple('hdr.ethernet.src_addr',
                                                         self.srcMacAddrs[x],
                                                         self.srcMacAddrsMask[x])])]
            self.replayed_tcam_data_list += [self.tcam_direct_lpf_table.make_data([gc.DataTuple('$ACTION_MEMBER_ID', self.action_mbr_ids[x]),
                                              gc.DataTuple('$LPF_SPEC_TYPE', str_val=self.lpf_types[x]),
                                              gc.DataTuple('$LPF_SPEC_GAIN_TIME_CONSTANT_NS',
                                                           float_val=self.gain_time[x]),
                                              gc.DataTuple('$LPF_SPEC_DECAY_TIME_CONSTANT_NS',
                                                           float_val=self.decay_time[x]),
                                              gc.DataTuple('$LPF_SPEC_OUT_SCALE_DOWN_FACTOR', self.out_scale[x])])]
            self.replayed_tcam_table_dict[self.replayed_tcam_key_list[-1]] = self.replayed_tcam_data_list[-1]

        self.action_profile_table.entry_add(self.target, self.replayed_action_key_list, self.replayed_action_data_list)
        self.tcam_direct_lpf_table.entry_add(self.target, self.replayed_tcam_key_list, self.replayed_tcam_data_list)

        self.get_entries_and_verify(from_hw=True)
        # Broken
        # self.get_entries_and_verify(from_hw=False)
        self.send_traffic_and_verify_packets()

        logger.info("--- Post hitless validation ended ---")

    def send_traffic_and_verify_packets(self):
        logger.info("Sending traffic and verifying packets")

        '''
        Figure out what ports to expect or not expect packets on
        If hitless was over, the packets should only be expected
        on the ports belonging to the replayed entries and no
        packets should be expected on the ports belonging to the
        entries which were originally added, but were not replayed.
        '''
        expect_packet_tcam_dict = self.tcam_table_dict
        expect_packet_action_table_dict = self.action_table_dict
        no_packet_tcam_dict = {}
        if self.state == State.HITLESS_END:
            expect_packet_tcam_dict = self.replayed_tcam_table_dict
            expect_packet_action_table_dict = self.replayed_action_table_dict

            for key, data in list(self.tcam_table_dict.items()):
                if not key in self.replayed_tcam_table_dict:
                    no_packet_tcam_dict[key] = data

        count = 1
        for k, d in list(expect_packet_tcam_dict.items()):
            key = k.to_dict()
            data = d.to_dict()

            src_mac_addr = key["hdr.ethernet.src_addr"]["value"]
            dst_mac_addr = key["hdr.ethernet.dst_addr"]["value"]
            pkt = testutils.simple_tcp_packet(eth_src=src_mac_addr,
                                              eth_dst=dst_mac_addr,
                                              with_tcp_chksum=False)

            action_id = data["$ACTION_MEMBER_ID"]
            action_key = self.action_profile_table.make_key([gc.KeyTuple('$ACTION_MEMBER_ID', action_id)])
            action_data_dict = expect_packet_action_table_dict[action_key].to_dict()
            action_name = action_data_dict["action_name"]
            if action_name == 'SwitchIngress.change_ipsrc':
                exp_pkt = testutils.simple_tcp_packet(eth_src=src_mac_addr,
                                                      eth_dst=dst_mac_addr,
                                                      ip_src=action_data_dict["srcAddr"],
                                                      with_tcp_chksum=False)
            elif action_name == 'SwitchIngress.change_ipdst':
                exp_pkt = testutils.simple_tcp_packet(eth_src=src_mac_addr,
                                                      eth_dst=dst_mac_addr,
                                                      ip_dst=action_data_dict["dstAddr"],
                                                      with_tcp_chksum=False)
            logger.info("Entry %d: Sending packet on port %d and expecting one on port %d",
                        count, self.action_id_to_ig_port_dict[action_id], action_data_dict["dst_port"])
            testutils.send_packet(self, self.action_id_to_ig_port_dict[action_id], pkt)
            testutils.verify_packet(self, exp_pkt, action_data_dict["dst_port"])
            count += 1

        count = 1
        for k, d in list(no_packet_tcam_dict.items()):
            key = k.to_dict()
            data = d.to_dict()

            src_mac_addr = key["hdr.ethernet.src_addr"]["value"]
            dst_mac_addr = key["hdr.ethernet.dst_addr"]["value"]
            pkt = testutils.simple_tcp_packet(eth_src=src_mac_addr,
                                              eth_dst=dst_mac_addr,
                                              with_tcp_chksum=False)

            action_id = data["$ACTION_MEMBER_ID"]
            logger.info("Entry %d: Sending packet on port %d and expecting no packets",
                        count, self.action_id_to_ig_port_dict[action_id])
            testutils.send_packet(self, self.action_id_to_ig_port_dict[action_id], pkt)
            testutils.verify_no_other_packets(self, timeout=2)
            count += 1

    def get_entries_and_verify(self, from_hw = True):
        logger.info("Validating entries from %s", "HW" if from_hw else "SW")

        tcam_dict = self.tcam_table_dict
        action_table_dict = self.action_table_dict

        # If hitless was over, verify entries based on what entries were replayed
        if self.state == State.HITLESS_END:
            tcam_dict = self.replayed_tcam_table_dict
            action_table_dict = self.replayed_action_table_dict

        # Broken
        # resp = self.tcam_direct_lpf_table.entry_get(self.target, None, {"from_hw": from_hw})

        resp = self.action_profile_table.entry_get(self.target, None, {"from_hw": from_hw})
        for data, key in resp:
            k = key.to_dict()
            d = data.to_dict()

            assert d["action_name"] == action_table_dict[key].to_dict()["action_name"]
            if d["action_name"] == "SwitchIngress.change_ipsrc":
                assert d["srcAddr"] == action_table_dict[key].to_dict()["srcAddr"]
            elif d["action_name"] == "SwitchIngress.change_ipdst":
                assert d["dstAddr"] == action_table_dict[key].to_dict()["dstAddr"]

    def setUp(self):
        self.p4_name = "tna_ternary_match"
        HitlessBaseTestNegative.setUp(self)

class HitlessKeyLessTableNegative(HitlessBaseTestNegative):
    """@brief This test does negative testing during replay.
    1. Set a different default port
    2. Don't replay anything, should use the original default entry

    When encountered a failure, we issue a warm_init with fast_reconfig
    """

    def setup_tables(self):
        logger.info("Setting tables")
        self.table_output_port = self.bfrt_info.table_get("SwitchIngress.output_port")
        self.table_bridge_md_ctl= self.bfrt_info.table_get("SwitchIngress.bridge_md_ctrl")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.eg_port = swports[1]
        self.ig_ports = [swports[x] for x in range(6)]
        self.bridged_data = self.table_bridge_md_ctl.make_data([], "SwitchIngress.bridge_add_ig_intr_md")
        self.output_data = self.table_output_port.make_data([gc.DataTuple("port_id", self.eg_port)],
                                                            "SwitchIngress.set_output_port")

        # Store original default entries
        resp = self.table_bridge_md_ctl.default_entry_get(self.target)
        for data, key in resp:
            self.ori_bridged_data = data

        resp = self.table_output_port.default_entry_get(self.target)
        for data, key in resp:
            self.ori_output_data = data

    def add_entries(self):
        logger.info("Adding entries")
        self.table_bridge_md_ctl.default_entry_set(self.target, self.bridged_data)
        self.table_output_port.default_entry_set(self.target, self.output_data)

    def init_replay_funcs(self):
        self.replay_func_list.append((self.replay_entries_1, False))
        self.replay_func_list.append((self.replay_entries_2, False))

    def replay_entries_1(self):
        logger.info("Replay 1: Set a different default port")
        self.replayed_eg_port = swports[2]
        self.replayed_bridged_data = self.table_bridge_md_ctl.make_data([], "SwitchIngress.bridge_add_ig_intr_md")
        self.replayed_output_data = self.table_output_port.make_data([gc.DataTuple("port_id", self.replayed_eg_port)],
                                                            "SwitchIngress.set_output_port")
        self.table_bridge_md_ctl.default_entry_set(self.target, self.replayed_bridged_data)
        self.table_output_port.default_entry_set(self.target, self.replayed_output_data)

    def replay_entries_2(self):
        logger.info("Replay 2: Don't replay anything, should use the original default entry")
        self.replayed_eg_port = None
        self.replayed_bridged_data = self.ori_bridged_data
        self.replayed_output_data = self.ori_output_data

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)

        logger.info("Step 1: Change the default entry")
        self.replayed_eg_port = swports[3]
        self.replayed_bridged_data = self.table_bridge_md_ctl.make_data([], "SwitchIngress.bridge_add_ig_intr_md")
        self.replayed_output_data = self.table_output_port.make_data([gc.DataTuple("port_id", self.replayed_eg_port)],
                                                            "SwitchIngress.set_output_port")
        self.table_bridge_md_ctl.default_entry_set(self.target, self.replayed_bridged_data)
        self.table_output_port.default_entry_set(self.target, self.replayed_output_data)

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("Step 2: Reset the default entry")
        self.replayed_eg_port = None
        self.replayed_bridged_data = self.ori_bridged_data
        self.replayed_output_data = self.ori_output_data
        self.table_bridge_md_ctl.default_entry_reset(self.target)
        self.table_output_port.default_entry_reset(self.target)

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("--- Post hitless validation ended ---")

    def send_traffic_and_verify_packets(self):
        logger.info("Sending traffic and verifying packets")

        eg_port = self.eg_port
        if self.state == State.HITLESS_END:
            eg_port = self.replayed_eg_port

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

        for p in self.ig_ports:
            epkt = epkt_tmpl.copy()[scapy.all.Ether]
            epkt.dst = "00:00:00:00:00:{:02x}".format(p)
            testutils.send_packet(self, p, ipkt)
            if eg_port:
                logger.info("Sending packet on port %d and expecting one on port %d", p, eg_port)
                testutils.verify_packet(self, epkt, eg_port)
            else:
                logger.info("Sending packet on port %d and expecting no packets", p)
                testutils.verify_no_other_packets(self)

    def get_entries_and_verify(self, from_hw = True):
        logger.info("Validating entries from %s", "HW" if from_hw else "SW")

        bridged_data = self.bridged_data
        output_data = self.output_data

        # If hitless was over, verify entries based on what entries were replayed
        if self.state == State.HITLESS_END:
            bridged_data = self.replayed_bridged_data
            output_data = self.replayed_output_data

        resp = self.table_bridge_md_ctl.default_entry_get(self.target, {"from_hw": from_hw})
        for data, key in resp:
            assert data == bridged_data

        resp = self.table_output_port.default_entry_get(self.target, {"from_hw": from_hw})
        for data, key in resp:
            assert data == output_data

    def setUp(self):
        self.p4_name = "tna_bridged_md"
        HitlessBaseTestNegative.setUp(self)

class HitlessHashActionTableNegative(HitlessBaseTestNegative):
    """@brief This test does negative testing during replay.
    1. Modify the original entries
    2. Replay different entries
    3. Don't replay any entries

    When encountered a failure, we issue a warm_init with fast_reconfig
    """

    def setup_tables(self):
        logger.info("Setting tables")
        self.mirror_cfg_table = self.bfrt_info.table_get("$mirror.cfg")
        self.mirror_fwd_table = self.bfrt_info.table_get("mirror_fwd")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.exp_len1 = 127
        self.exp_len2 = 63
        self.max_sid = 1015
        self.base_sid = 1
        self.sids = random.sample(range(self.base_sid, self.max_sid), len(swports))
        self.sids.sort()
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
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

            max_len = 128 if port % 2 == 0 else 64
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

    def init_replay_funcs(self):
        # Broken: entry_mod does not seem to go through
        # self.replay_func_list.append((self.replay_entries_1, False))

        # Broken: cannot add a not exiting entry
        # self.replay_func_list.append((self.replay_entries_2, False))

        self.replay_func_list.append((self.replay_entries_3, False))

    def replay_entries_1(self):
        logger.info("Replay 1: Modify the original entries")
        self.mirror_cfg_table.entry_add(self.target, self.mirror_cfg_key, self.mirror_cfg_data)
        self.mirror_fwd_table.entry_add(self.target, self.mirror_fwd_key, self.mirror_fwd_data)
        self.replay_exp_len1 = 63
        self.replay_exp_len2 = 127
        self.replay_mirror_fwd_key = []
        self.replay_mirror_fwd_data = []
        self.replay_mirror_cfg_key = []
        self.replay_mirror_cfg_data = []
        for port, sid in zip(swports, self.sids):
            self.replay_mirror_fwd_key += [self.mirror_fwd_table.make_key([
                                             gc.KeyTuple('ig_intr_md.ingress_port', port)])]
            self.replay_mirror_fwd_data += [self.mirror_fwd_table.make_data([gc.DataTuple('dest_port', 511),
                                              gc.DataTuple('ing_mir', 1),
                                              gc.DataTuple('ing_ses', sid),
                                              gc.DataTuple('egr_mir', 0),
                                              gc.DataTuple('egr_ses', 0)],
                                             'SwitchIngress.set_md')]

            # Flip the max lengths
            max_len = 64 if port % 2 == 0 else 128
            self.replay_mirror_cfg_key += [self.mirror_cfg_table.make_key([gc.KeyTuple('$sid', sid)])]
            self.replay_mirror_cfg_data += [self.mirror_cfg_table.make_data([gc.DataTuple('$direction', str_val="INGRESS"),
                                                 gc.DataTuple('$ucast_egress_port', port),
                                                 gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                                 gc.DataTuple('$session_enable', bool_val=True),
                                                 gc.DataTuple('$max_pkt_len', max_len)],
                                                '$normal')]

            self.mirror_cfg_table.entry_mod(self.target,
                                            [self.replay_mirror_cfg_key[-1]],
                                            [self.replay_mirror_cfg_data[-1]])

    def replay_entries_2(self):
        logger.info("Replay 2: Replay different entries")
        self.replay_exp_len1 = 63
        self.replay_exp_len2 = 127
        self.replay_mirror_fwd_key = []
        self.replay_mirror_fwd_data = []
        self.replay_mirror_cfg_key = []
        self.replay_mirror_cfg_data = []
        for port, sid in zip(swports, self.sids):
            self.replay_mirror_fwd_key += [self.mirror_fwd_table.make_key([
                                             gc.KeyTuple('ig_intr_md.ingress_port', port)])]
            self.replay_mirror_fwd_data += [self.mirror_fwd_table.make_data([gc.DataTuple('dest_port', 511),
                                              gc.DataTuple('ing_mir', 1),
                                              gc.DataTuple('ing_ses', sid),
                                              gc.DataTuple('egr_mir', 0),
                                              gc.DataTuple('egr_ses', 0)],
                                             'SwitchIngress.set_md')]

            # Flip the max lengths
            max_len = 64 if port % 2 == 0 else 128
            self.replay_mirror_cfg_key += [self.mirror_cfg_table.make_key([gc.KeyTuple('$sid', sid)])]
            self.replay_mirror_cfg_data += [self.mirror_cfg_table.make_data([gc.DataTuple('$direction', str_val="INGRESS"),
                                                 gc.DataTuple('$ucast_egress_port', port),
                                                 gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                                 gc.DataTuple('$session_enable', bool_val=True),
                                                 gc.DataTuple('$max_pkt_len', max_len)],
                                                '$normal')]


        self.mirror_cfg_table.entry_add(self.target, self.replay_mirror_cfg_key, self.replay_mirror_cfg_data)
        self.mirror_fwd_table.entry_add(self.target, self.replay_mirror_fwd_key, self.replay_mirror_fwd_data)

    def replay_entries_3(self):
        logger.info("Replay 3: Don't replay any entries")
        self.replay_exp_len1 = None
        self.replay_exp_len2 = None
        self.replay_mirror_fwd_key = []
        self.replay_mirror_fwd_data = []
        self.replay_mirror_cfg_key = []
        self.replay_mirror_cfg_data = []

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)

        logger.info("Step 1: Add some entries")
        self.replay_exp_len1 = 127
        self.replay_exp_len2 = 63
        self.replay_mirror_fwd_key = []
        self.replay_mirror_fwd_data = []
        self.replay_mirror_cfg_key = []
        self.replay_mirror_cfg_data = []
        for port, sid in zip(swports, self.sids):
            self.replay_mirror_fwd_key += [self.mirror_fwd_table.make_key([
                                             gc.KeyTuple('ig_intr_md.ingress_port', port)])]
            self.replay_mirror_fwd_data += [self.mirror_fwd_table.make_data([gc.DataTuple('dest_port', 511),
                                              gc.DataTuple('ing_mir', 1),
                                              gc.DataTuple('ing_ses', sid),
                                              gc.DataTuple('egr_mir', 0),
                                              gc.DataTuple('egr_ses', 0)],
                                             'SwitchIngress.set_md')]

            # Flip the max lengths
            max_len = 128 if port % 2 == 0 else 64
            self.replay_mirror_cfg_key += [self.mirror_cfg_table.make_key([gc.KeyTuple('$sid', sid)])]
            self.replay_mirror_cfg_data += [self.mirror_cfg_table.make_data([gc.DataTuple('$direction', str_val="INGRESS"),
                                                 gc.DataTuple('$ucast_egress_port', port),
                                                 gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                                 gc.DataTuple('$session_enable', bool_val=True),
                                                 gc.DataTuple('$max_pkt_len', max_len)],
                                                '$normal')]

        self.mirror_cfg_table.entry_add(self.target, self.replay_mirror_cfg_key, self.replay_mirror_cfg_data)
        self.mirror_fwd_table.entry_add(self.target, self.replay_mirror_fwd_key, self.replay_mirror_fwd_data)

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("--- Post hitless validation ended ---")

    def send_traffic_and_verify_packets(self):
        logger.info("Sending traffic and verifying packets")

        exp_len1 = self.exp_len1
        exp_len2 = self.exp_len2
        if self.state == State.HITLESS_END:
            exp_len1 = self.replay_exp_len1
            exp_len2 = self.replay_exp_len2

        if exp_len1 or exp_len2:
            pkt = simple_eth_packet(pktlen=200)
            rec_pkt1 = simple_eth_packet(pktlen=exp_len1)
            rec_pkt2 = simple_eth_packet(pktlen=exp_len2)
            count = 1
            for port in swports:
                send_packet(self, port, pkt)
                if port % 2 == 0:
                    logger.info("Sending packet on port %d and making sure the received packet is of length %d",
                                port, exp_len1)
                    verify_packet(self, rec_pkt1, port)
                else:
                    logger.info("Sending packet on port %d and making sure the received packet is of length %d",
                                port, exp_len2)
                    verify_packet(self, rec_pkt2, port)
                count += 1

        logger.info("Verifying no packets")
        verify_no_other_packets(self)

    def get_entries_and_verify(self, from_hw = True):
        logger.info("Validating entries from %s", "HW" if from_hw else "SW")

        mirror_fwd_key = self.mirror_fwd_key
        mirror_fwd_data = self.mirror_fwd_data
        mirror_cfg_key = self.mirror_cfg_key
        mirror_cfg_data = self.mirror_cfg_data

        # If hitless was over, verify entries based on what entries were replayed
        if self.state == State.HITLESS_END:
            mirror_fwd_key = self.replay_mirror_fwd_key
            mirror_fwd_data = self.replay_mirror_fwd_data
            mirror_cfg_key = self.replay_mirror_cfg_key
            mirror_cfg_data = self.replay_mirror_cfg_data

        resp = self.mirror_fwd_table.entry_get(self.target, None, {"from_hw": from_hw})
        i = 0
        for data, key in resp:
            assert key == mirror_fwd_key[i], "received %s expected %s" %(str(key), str(mirror_fwd_key[i]))
            assert data == mirror_fwd_data[i], "received %s expected %s" %(str(data), str(mirror_fwd_data[i]))
            i += 1

        resp = self.mirror_cfg_table.entry_get(self.target, None, {"from_hw": from_hw})
        i = 0
        for data, key in resp:
            assert key == mirror_cfg_key[i], "received %s expected %s" %(str(key), str(mirror_cfg_key[i]))
            # TODO fix below. server sending more fields than being sent by client. Some are garbage.  Make madatory work
            #assert data == mirror_cfg_data[i], "received %s expected %s" %(str(data), str(mirror_cfg_data[i]))
            i += 1

    def setUp(self):
        self.p4_name = "tna_mirror"
        HitlessBaseTestNegative.setUp(self)

'''
    The tests from here will be replaying the same entries as we need
    to prioritize on post hitless validation more. We can revisit
    different replay combinations later.
'''

class HitlessPVSNegative(HitlessBaseTestNegative):
    def setup_tables(self):
        logger.info("Setting tables")
        self.vs_table = self.bfrt_info.table_get("ParserI.vs")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.target = gc.Target(device_id=0, pipe_id=0xffff, direction=0xff, prsr_id=0xff)
        self.vs_table.attribute_entry_scope_set(self.target,
                                                config_gress_scope=True,
                                                predefined_gress_scope_val=bfruntime_pb2.Mode.ALL,
                                                config_pipe_scope=True,
                                                predefined_pipe_scope=True,
                                                predefined_pipe_scope_val=bfruntime_pb2.Mode.ALL,
                                                pipe_scope_args=0xff,
                                                config_prsr_scope=True,
                                                predefined_prsr_scope_val=bfruntime_pb2.Mode.ALL,
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

    def init_replay_funcs(self):
        self.replay_func_list.append((self.replay_entries_1, False))

    def replay_entries_1(self):
        logger.info("Replay 1: Replay the original entries")
        self.add_entries()

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)

        logger.info("Step 1: Add some new entries")
        self.key_list = []
        for i in [5, 6, 7, 8]:
            f16 = i
            f8 = i + 10
            self.key_list += [self.vs_table.make_key([gc.KeyTuple('f16', f16, 0xffff),
                                                      gc.KeyTuple('f8', f8, 0xff)])]

        # TODO: Fix this, ideally it should return the original entries and the new ones
        self.vs_table.entry_add(self.target, self.key_list)

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("Step 2: Delete some entries")
        for i in [0, 3]:
            key = self.key_list[i]
            self.vs_table.entry_del(self.target, [key])

        self.key_list.pop(0)
        self.key_list.pop(2)

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("--- Post hitless validation ended ---")

    def get_entries_and_verify(self, from_hw = True):
        logger.info("Validating entries from %s", "HW" if from_hw else "SW")
        resp = self.vs_table.entry_get(self.target, None, {"from_hw": from_hw})
        i = 0
        for data, key in resp:
            assert key == self.key_list[i], "received %s expected %s" %(str(key), str(self.key_list[i]))
            i += 1

    def setUp(self):
        self.p4_name = "tna_pvs"
        HitlessBaseTestNegative.setUp(self)

class HitlessTnaRangeNegative(HitlessBaseTestNegative):
    def setup_tables(self):
        self.forward_table = self.bfrt_info.table_get("SwitchIngress.forward")
        self.forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.ig_port = swports[1]
        self.eg_ports = [swports[5], swports[3]]
        self.num_entries = 10
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.key_list = []
        self.data_list = []
        for i in range(0, self.num_entries):
            vrf = 0
            range_size = random.randint(1, 511)
            dst_ip = "%d.%d.%d.%d" % (random.randint(1, 255),
                                      random.randint(0, 255),
                                      random.randint(0, 255),
                                      random.randint(0, 255))
            pkt_length_start = random.randint(60, 511)
            self.key_list += [self.forward_table.make_key([gc.KeyTuple('$MATCH_PRIORITY', 1),
                                         gc.KeyTuple('hdr.ipv4.dst_addr', dst_ip),
                                         gc.KeyTuple('hdr.ipv4.total_len',
                                                         low=pkt_length_start,
                                                         high=pkt_length_start + range_size)])]
            self.data_list += [self.forward_table.make_data([gc.DataTuple('port', self.eg_ports[0])], 'SwitchIngress.hit')]

    def add_entries(self):
        logger.info("Adding entries")
        self.forward_table.entry_add(self.target, self.key_list, self.data_list)

    def init_replay_funcs(self):
        self.replay_func_list.append((self.replay_entries_1, False))

    def replay_entries_1(self):
        logger.info("Replay 1: Replay the original entries")
        self.add_entries()
        self.replayed_key_list = self.key_list
        self.replayed_data_list = self.data_list

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)

        logger.info("Step 1: Add some new entries")
        new_key_list = []
        new_data_list = []
        for i in range(0, 5):
            vrf = 0
            range_size = random.randint(1, 511)
            dst_ip = "%d.%d.%d.%d" % (random.randint(1, 255),
                                      random.randint(0, 255),
                                      random.randint(0, 255),
                                      random.randint(0, 255))
            pkt_length_start = random.randint(60, 511)
            key = self.forward_table.make_key([gc.KeyTuple('$MATCH_PRIORITY', 1),
                                               gc.KeyTuple('hdr.ipv4.dst_addr', dst_ip),
                                               gc.KeyTuple('hdr.ipv4.total_len',
                                                           low=pkt_length_start,
                                                           high=pkt_length_start + range_size)])
            data = self.forward_table.make_data([gc.DataTuple('port', self.eg_ports[0])], 'SwitchIngress.hit')
            new_key_list.append(key)
            new_data_list.append(data)
            self.replayed_key_list.append(key)
            self.replayed_data_list.append(data)

        self.forward_table.entry_add(self.target, new_key_list, new_data_list)

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("Step 2: Modify a few entries")
        for i in range(0, len(self.replayed_key_list)):
            key = self.replayed_key_list[i]
            should_modify = bool(random.getrandbits(1))
            if should_modify:
                new_data = self.forward_table.make_data([gc.DataTuple('port', self.eg_ports[1])], 'SwitchIngress.hit')
                self.forward_table.entry_mod(self.target, [key], [new_data])
                self.replayed_data_list[i] = new_data

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("Step 3: Delete some entries")
        for i in range(5):
            key = self.replayed_key_list[i]
            self.forward_table.entry_del(self.target, [key])

        del self.replayed_key_list[0:5]
        del self.replayed_data_list[0:5]

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("--- Post hitless validation ended ---")

    def send_traffic_and_verify_packets(self):
        logger.info("Sending traffic and verifying packets")

        key_list = self.key_list
        data_list = self.data_list

        # If hitless was over, verify entries based on what entries were replayed
        if self.state == State.HITLESS_END:
            key_list = self.replayed_key_list
            data_list = self.replayed_data_list

        count = 1
        for k, d in zip(self.key_list, self.data_list):
            key = k.to_dict()
            data = d.to_dict()

            dst_ip = key["hdr.ipv4.dst_addr"]["value"]
            pkt_length_start = key["hdr.ipv4.total_len"]["low"]
            pkt_length_end = key["hdr.ipv4.total_len"]["high"]
            range_size = key["hdr.ipv4.total_len"]["high"] - key["hdr.ipv4.total_len"]["low"]
            eg_port = data["port"]
            eth_hdr_size = 14

            # Pick a length between the valid range, the packet should be received on the egress port
            pkt_len = random.randint(pkt_length_start, pkt_length_end) + eth_hdr_size
            pkt = testutils.simple_tcp_packet(pktlen=pkt_len, ip_dst=dst_ip)
            exp_pkt = pkt
            logger.info("Entry %d: Sending packet on port %d for with total_len %d and expecting packet on port %d",
                        count, self.ig_port, pkt_len - eth_hdr_size, eg_port)
            testutils.send_packet(self, self.ig_port, pkt)
            testutils.verify_packet(self, exp_pkt, eg_port)

            # Pick a length more than the range, the packet should get dropped
            pkt_len = pkt_length_end + eth_hdr_size + 2
            pkt = testutils.simple_tcp_packet(pktlen=pkt_len, ip_dst=dst_ip)
            exp_pkt = pkt
            logger.info("Entry %d: Sending packet on port %d with total_len %d, it should be dropped",
                        count, self.ig_port, pkt_len - eth_hdr_size)
            testutils.send_packet(self, self.ig_port, pkt)
            testutils.verify_no_other_packets(self)

            count += 1

    def get_entries_and_verify(self, from_hw = True):
        logger.info("Validating entries from %s", "HW" if from_hw else "SW")

        key_list = self.key_list
        data_list = self.data_list

        # If hitless was over, verify entries based on what entries were replayed
        if self.state == State.HITLESS_END:
            key_list = self.replayed_key_list
            data_list = self.replayed_data_list

        resp = self.forward_table.entry_get(self.target, None, {"from_hw": from_hw})
        i = 0
        for data, key in resp:
            assert key == key_list[i], "received %s expected %s" %(str(key), str(key_list[i]))
            assert data == data_list[i]
            i += 1

    def setUp(self):
        self.p4_name = "tna_range_match"
        HitlessBaseTestNegative.setUp(self)

class HitlessDynHashingNegative(HitlessBaseTestNegative):
    def setup_tables(self):
        logger.info("Setting tables")
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
        self.hash_config_table.attribute_dyn_hashing_set(self.target,
                                                         alg_hdl=self.alg_hdl,
                                                         seed=self.hash_seed)

    def init_replay_funcs(self):
        self.replay_func_list.append((self.replay_entries_1, False))

    def replay_entries_1(self):
        logger.info("Replay 1: Replay the original entries")
        self.add_entries()

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)

        # Adding a new entry will override the original values
        logger.info("Step 1: Add a new entry")
        self.data_list = [self.hash_config_table.make_data([gc.DataTuple('hdr.ipv4.proto.$PRIORITY', 4),
                                                            gc.DataTuple('hdr.ipv4.sip.$PRIORITY', 3),
                                                            gc.DataTuple('hdr.ipv4.dip.$PRIORITY', 2),
                                                            gc.DataTuple('hdr.tcp.sPort.$PRIORITY', 1),
                                                            gc.DataTuple('hdr.tcp.dPort.$PRIORITY', 0)])]
        self.hash_config_table.entry_add(self.target, None, self.data_list)
        self.hash_config_table.attribute_dyn_hashing_set(self.target,
                                                         alg_hdl=self.alg_hdl,
                                                         seed=self.hash_seed)

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("--- Post hitless validation ended ---")

    def get_entries_and_verify(self, from_hw = True):
        logger.info("Verifying get entry")
        resp = self.hash_config_table.entry_get(self.target, None, {"from_hw": False})
        i = 0
        for data, key in resp:
            assert data == self.data_list[i], "received %s expected %s" %(str(data), str(self.data_list[i]))
            i += 1

        resp = self.hash_config_table.attribute_get(self.target, "DynamicHashing")
        for data in resp:
            assert data["alg"] == self.alg_hdl
            assert data["seed"] == self.hash_seed

    def setUp(self):
        self.p4_name = "tna_dyn_hashing"
        HitlessBaseTestNegative.setUp(self)

class HitlessIndirectMeterTestNegative(HitlessBaseTestNegative):
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
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.num_entries =  random.randint(1, 100)
        self.meter_key_list = []
        self.meter_data_list = []
        self.match_key_list = []
        self.match_data_list = []
        key_set = set()
        meter_indices = [x + 1 for x in range(self.num_entries)]
        logger.info("Number of entries %d", self.num_entries)
        self.match_dict = {}
        for i in range(self.num_entries):
            mac_addr = "%02x:%02x:%02x:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))

            # Make sure the mac address is unique
            while mac_addr in key_set:
                mac_addr = "%02x:%02x:%02x:%02x:%02x:%02x" % (random.randint(0, 255),
                                                              random.randint(0, 255),
                                                              random.randint(0, 255),
                                                              random.randint(0, 255),
                                                              random.randint(0, 255),
                                                              random.randint(0, 255))

            self.match_key_list += [self.match_table.make_key([gc.KeyTuple('hdr.ethernet.dst_addr', mac_addr)])]
            self.match_data_list += [self.match_table.make_data(
                                            [gc.DataTuple('meter_idx', meter_indices[i])],
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

    def init_replay_funcs(self):
        self.replay_func_list.append((self.replay_entries_1, False))

    def replay_entries_1(self):
        logger.info("Replay 1: Replay the original entries")
        self.add_entries()

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)

        # Adding a few new entries
        logger.info("Step 1: Add a few new entries")
        meter_indices = [x + 1 for x in range(self.num_entries, self.num_entries + 5)]
        key_set = set()
        for i in range(5):
            mac_addr = "%02x:%02x:%02x:%02x:%02x:%02x" % (random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255),
                                                          random.randint(0, 255))

            # Make sure the mac address is unique
            while mac_addr in key_set:
                mac_addr = "%02x:%02x:%02x:%02x:%02x:%02x" % (random.randint(0, 255),
                                                              random.randint(0, 255),
                                                              random.randint(0, 255),
                                                              random.randint(0, 255),
                                                              random.randint(0, 255),
                                                              random.randint(0, 255))

            self.match_key_list += [self.match_table.make_key([gc.KeyTuple('hdr.ethernet.dst_addr', mac_addr)])]
            self.match_data_list += [self.match_table.make_data(
                                            [gc.DataTuple('meter_idx', meter_indices[i])],
                                                          'SwitchIngress.set_color')]
            key_set.add(mac_addr)
            self.match_dict[self.match_key_list[-1]] = self.match_data_list[-1]

        new_meter_data = self.getMeterData(5)
        for key, data in self.meter_data.iteritems():
            self.meter_data[key] += new_meter_data[key]

        for x in range(self.num_entries, self.num_entries + 5):
            self.meter_key_list += [self.meter_table.make_key(
                    [gc.KeyTuple('$METER_INDEX', x)])]
            self.meter_data_list += [self.meter_table.make_data(
                    [gc.DataTuple('$METER_SPEC_CIR_KBPS',  self.meter_data['cir'][x]),
                     gc.DataTuple('$METER_SPEC_PIR_KBPS',  self.meter_data['pir'][x]),
                     gc.DataTuple('$METER_SPEC_CBS_KBITS', self.meter_data['cbs'][x]),
                     gc.DataTuple('$METER_SPEC_PBS_KBITS', self.meter_data['pbs'][x])])]

        self.meter_table.entry_add(self.target,
                                   self.meter_key_list[self.num_entries:self.num_entries + 5],
                                   self.meter_data_list[self.num_entries:self.num_entries + 5])
        self.match_table.entry_add(self.target,
                                   self.match_key_list[self.num_entries:self.num_entries + 5],
                                   self.match_data_list[self.num_entries:self.num_entries + 5])

        self.num_entries += 5

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        # Modify a few entries
        logger.info("Step 2: Modify a few entries")
        new_meter_data = self.getMeterData(5)
        for x in range(5):
            for key, data in self.meter_data.iteritems():
                self.meter_data[key][x] = new_meter_data[key][x]

            self.meter_data_list[x] = self.meter_table.make_data(
                    [gc.DataTuple('$METER_SPEC_CIR_KBPS',  new_meter_data['cir'][x]),
                     gc.DataTuple('$METER_SPEC_PIR_KBPS',  new_meter_data['pir'][x]),
                     gc.DataTuple('$METER_SPEC_CBS_KBITS', new_meter_data['cbs'][x]),
                     gc.DataTuple('$METER_SPEC_PBS_KBITS', new_meter_data['pbs'][x])])

            self.meter_table.entry_mod(self.target,
                                       [self.meter_key_list[x]],
                                       [self.meter_data_list[x]])

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        # Delete a few entries
        '''
        logger.info("Step 3: Delete a few entries")
        for x in range(5):
            self.meter_table.entry_del(self.target, [self.meter_key_list[x]])

        self.num_entries -= 5
        del self.meter_key_list[0:5]
        del self.meter_data_list[0:5]

        for key, data in self.meter_data.iteritems():
            del self.meter_data[key][0:5]

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()
        '''

        logger.info("--- Post hitless validation ended ---")

    def get_entries_and_verify(self, from_hw = True):
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

        resp = self.match_table.entry_get(self.target, None, {"from_hw": from_hw})
        i = 0
        for data, key in resp:
            assert self.match_dict[key] == data
            i += 1

    def setUp(self):
        self.p4_name = "tna_meter_lpf_wred"
        HitlessBaseTestNegative.setUp(self)

class HitlessTnaTernaryMatchAtcamNegative(HitlessBaseTestNegative):
    def setup_tables(self):
        logger.info("Setting tables")
        self.forward_atcam_table = self.bfrt_info.table_get("SwitchIngress.forward_atcam")
        self.set_partition_table = self.bfrt_info.table_get("SwitchIngress.set_partition")
        self.forward_atcam_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.ig_port = swports[1]
        self.eg_port = swports[2]
        self.key_list_1 = []
        self.key_list_2 = []
        self.data_list = []
        self.num_entries = 20
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.ip_random_list = self.generate_random_ip_list(self.num_entries + 5, self.seed)
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
        logger.info("Adding entries")
        self.set_partition_table.entry_add(self.target, [self.partition_key_1], [self.partition_data_1])
        self.set_partition_table.entry_add(self.target, [self.partition_key_2], [self.partition_data_2])

        self.forward_atcam_table.entry_add(self.target, self.key_list_1, self.data_list)
        self.forward_atcam_table.entry_add(self.target, self.key_list_2, self.data_list)

    def init_replay_funcs(self):
        self.replay_func_list.append((self.replay_entries_1, False))

    def replay_entries_1(self):
        logger.info("Replay 1: Replay the original entries")
        self.add_entries()

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)

        # Adding a few new entries
        logger.info("Step 1: Add a few new entries")
        for i in range(5):
            self.key_list_1.append(
                    self.forward_atcam_table.make_key(
                        [gc.KeyTuple('$MATCH_PRIORITY', 0),
                         gc.KeyTuple('ig_md.partition.partition_index', 3),
                         gc.KeyTuple('hdr.ipv4.dst_addr',
                                     getattr(self.ip_random_list[self.num_entries + i], "ip"),
                                     getattr(self.ip_random_list[self.num_entries + i], "mask"))]))
            self.key_list_2.append(
                    self.forward_atcam_table.make_key(
                        [gc.KeyTuple('$MATCH_PRIORITY', 0),
                         gc.KeyTuple('ig_md.partition.partition_index', 1),
                         gc.KeyTuple('hdr.ipv4.dst_addr',
                                     getattr(self.ip_random_list[self.num_entries + i], "ip"),
                                     getattr(self.ip_random_list[self.num_entries + i], "mask"))]))
            self.data_list.append(self.forward_atcam_table.make_data([gc.DataTuple('port', self.eg_port)], 'SwitchIngress.hit'))

            self.key_list_1[-1].apply_mask()
            self.key_list_2[-1].apply_mask()
            self.atcam_dict[self.key_list_1[-1]] = self.data_list[-1]
            self.atcam_dict[self.key_list_2[-1]] = self.data_list[-1]

        self.forward_atcam_table.entry_add(self.target,
                                           self.key_list_1[self.num_entries:self.num_entries + 5],
                                           self.data_list[self.num_entries:self.num_entries + 5])
        self.forward_atcam_table.entry_add(self.target,
                                           self.key_list_2[self.num_entries:self.num_entries + 5],
                                           self.data_list[self.num_entries:self.num_entries + 5])

        self.num_entries += 5

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        # Modify a few entries
        logger.info("Step 2: Modify a few entries")
        for i in range(self.num_entries):
            should_modify = bool(random.getrandbits(1))
            if should_modify:
                self.data_list[i] = self.forward_atcam_table.make_data([gc.DataTuple('port', swports[3])], 'SwitchIngress.hit')
                self.atcam_dict[self.key_list_1[i]] = self.data_list[i]
                self.atcam_dict[self.key_list_2[i]] = self.data_list[i]

                self.forward_atcam_table.entry_mod(self.target,
                                                   [self.key_list_1[i]],
                                                   [self.data_list[i]])
                self.forward_atcam_table.entry_mod(self.target,
                                                   [self.key_list_2[i]],
                                                   [self.data_list[i]])

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        # Delete a few entries
        logger.info("Step 3: Delete a few entries")
        self.forward_atcam_table.entry_del(self.target,
                                           self.key_list_1[0:5])
        self.forward_atcam_table.entry_del(self.target,
                                           self.key_list_2[0:5])

        for i in range(5):
            self.atcam_dict.pop(self.key_list_1[i])
            self.atcam_dict.pop(self.key_list_2[i])
        del self.key_list_1[0:5]
        del self.key_list_2[0:5]
        del self.data_list[0:5]
        self.num_entries -= 5

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("--- Post hitless validation ended ---")

    def send_traffic_and_verify_packets(self):
        def send_and_verify_packet(self, ingress_port, egress_port, pkt, exp_pkt):
            testutils.send_packet(self, ingress_port, pkt)
            testutils.verify_packet(self, exp_pkt, egress_port)

        logger.info("Sending traffic")
        for i in range(self.num_entries):
            eg_port = self.data_list[i].to_dict()["port"]
            dst_ip = self.key_list_1[i].to_dict()["hdr.ipv4.dst_addr"]["value"]
            logger.info("Entry %d: (IP: %s) Sending a packet on port %d and expecting one on port %d",
                        i + 1, dst_ip, self.ig_port, eg_port)
            pkt = testutils.simple_tcp_packet(ip_dst=dst_ip)
            exp_pkt = pkt
            send_and_verify_packet(self, self.ig_port, eg_port, pkt, exp_pkt)

            dst_ip = self.key_list_2[i].to_dict()["hdr.ipv4.dst_addr"]["value"]
            logger.info("Entry %d: (IP: %s) Sending a packet on port %d and expecting one on port %d",
                        i + 1, dst_ip, self.ig_port, eg_port)
            pkt = testutils.simple_tcp_packet(ip_dst=dst_ip)
            exp_pkt = pkt
            send_and_verify_packet(self, self.ig_port, eg_port, pkt, exp_pkt)

    def get_entries_and_verify(self, from_hw = True):
        logger.info("Verifying get entry")
        resp = self.forward_atcam_table.entry_get(self.target, None, {"from_hw": False})
        atcam_dict = self.atcam_dict.copy()
        for data, key in resp:
            assert atcam_dict[key] == data
            atcam_dict.pop(key)
        assert len(atcam_dict) == 0

    def setUp(self):
        self.p4_name = "tna_ternary_match"
        HitlessBaseTestNegative.setUp(self)

class HitlessDefaultEntryNegative(HitlessBaseTestNegative):
    def setup_tables(self):
        logger.info("Setting tables")
        self.iproute_table = self.bfrt_info.table_get("SwitchIngress.ipRoute")

    def setup_test_data(self):
        logger.info("Setting up test data")
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        self.ig_port = swports[1]
        self.route_action_data = {}
        self.route_action_data['srcMac'] = "%02x:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255))
        self.route_action_data['dstMac'] = "%02x:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255))
        self.route_action_data['dst_port'] = swports[2]

        self.iproute_table.info.data_field_annotation_add("srcMac", "SwitchIngress.route", "mac")
        self.iproute_table.info.data_field_annotation_add("dstMac", "SwitchIngress.route", "mac")

    def add_entries(self):
        logger.info("Adding default entry")
        self.iproute_table.default_entry_set(self.target,
            self.iproute_table.make_data(
                [gc.DataTuple('srcMac', self.route_action_data['srcMac']),
                 gc.DataTuple('dstMac', self.route_action_data['dstMac']),
                 gc.DataTuple('dst_port', self.route_action_data['dst_port'])],
                "SwitchIngress.route"))

    def init_replay_funcs(self):
        self.replay_func_list.append((self.replay_entries_1, False))

    def replay_entries_1(self):
        logger.info("Replay 1: Replay the original entries")
        self.add_entries()

    def post_hitless_validation(self):
        logger.info("--- Post hitless validation started ---")

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)

        logger.info("Step 1: Change the default entry")
        self.route_action_data['dst_port'] = swports[3]
        self.iproute_table.default_entry_set(self.target,
            self.iproute_table.make_data(
                [gc.DataTuple('srcMac', self.route_action_data['srcMac']),
                 gc.DataTuple('dstMac', self.route_action_data['dstMac']),
                 gc.DataTuple('dst_port', self.route_action_data['dst_port'])],
                "SwitchIngress.route"))

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("Step 2: Reset the default entry")
        self.route_action_data['srcMac'] = None
        self.route_action_data['dstMac'] = None
        self.route_action_data['dst_port'] = None
        self.iproute_table.default_entry_reset(self.target)

        for from_hw in [True, False]:
            self.get_entries_and_verify(from_hw=from_hw)
        self.send_traffic_and_verify_packets()

        logger.info("--- Post hitless validation ended ---")

    def send_traffic_and_verify_packets(self):
        logger.info("Sending traffic and verifying packets")
        pkt = testutils.simple_tcp_packet()
        exp_pkt = testutils.simple_tcp_packet(eth_dst=self.route_action_data['dstMac'],
                                              eth_src=self.route_action_data['srcMac'])

        testutils.send_packet(self, self.ig_port, pkt)
        if self.route_action_data['dst_port']:
            logger.info("For default entry, sending packet on port %d and expecting one on port %d",
                        self.ig_port, self.route_action_data['dst_port'])
            testutils.verify_packet(self, exp_pkt, self.route_action_data['dst_port'])
        else:
            logger.info("For default entry, sending packet on port %d and expecting no packets",
                        self.ig_port)
            testutils.verify_no_other_packets(self)

    def get_entries_and_verify(self, from_hw = True):
        logger.info("Validating entries from %s", "HW" if from_hw else "SW")
        resp = self.iproute_table.default_entry_get(self.target, {"from_hw": from_hw})
        for data, key in resp:
            data = data.to_dict()
            if self.route_action_data.get('srcMac'):
                assert data['srcMac'] == self.route_action_data['srcMac']

            if self.route_action_data.get('dstMac'):
                assert data['dstMac'] == self.route_action_data['dstMac']

            if self.route_action_data.get('dst_port'):
                assert data['dst_port'] == self.route_action_data['dst_port']

            # TODO: Fix entry get for counters and meters

    def setUp(self):
        self.p4_name = "tna_exact_match"
        HitlessBaseTestNegative.setUp(self)
