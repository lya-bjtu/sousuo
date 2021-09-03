################################################################################
# BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
#
# Copyright (c) 2018-2020 Barefoot Networks, Inc.

# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to Barefoot Networks,
# Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in
# process, and are protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this material is
# strictly forbidden unless prior written permission is obtained from
# Barefoot Networks, Inc.
#
# No warranty, explicit or implicit is provided, unless granted under a
# written agreement with Barefoot Networks, Inc.
#
###############################################################################

import logging
import copy

from ptf import config
from ptf.thriftutils import *
from ptf.testutils import *

from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

logger = logging.getLogger('Test')
logger.addHandler(logging.StreamHandler())

p4_name = "bri_handle"
dev_id = 0
num_pipes = int(test_param_get('num_pipes'))
pipes = list(range(num_pipes))
is_tofino2 = test_param_get("arch") == "tofino2"
is_hw = test_param_get("target") == "hw"


def make_port(pipe, local_port):
    return (pipe << 7) | local_port


def port_to_pipe(port):
    return port >> 7


def port_to_pipe_local_port(port):
    return port & 0x7F


swports = []
for device, port, ifname in config["interfaces"]:
    if port_to_pipe(port) < num_pipes:
        swports.append(port)
swports.sort()


def setup_random(seed_val=None):
    if seed_val is None:
        if test_param_get('test_seed') is not 'None':
            seed_val = int(test_param_get('test_seed'))
    if seed_val is None:
        seed_val = int(time.time())
    logger.info("Seed is: %d", seed_val)
    random.seed(seed_val)


class HandleTest(BfRuntimeTest):
    """
    For each supported table type:
     1. Add entry with specific key.
     2. Get entry handle.
     3. Get entry by handle using data field filtering (request only
        specific fields) where applicable
     4. Get entry key and verify with key used to create.
     Tables not supported : SNAPSHOT_LIVENESS, DYN_HASH.
    """
    def setUp(self):
        client_id = 0
        BfRuntimeTest.setUp(self, client_id, p4_name)
        self.bfrt_info = self.interface.bfrt_info_get(p4_name)
        self.target = gc.Target(device_id=dev_id)

    def tearDown(self):
        BfRuntimeTest.tearDown(self)

    def testTable(self, table, key_list, data_list, data_filter=None, target=None):
        handle_list = []
        if target is None:
            target = self.target
        # Add entries
        if len(data_list) > 0:
            table.entry_add(
                    self.target,
                    key_list,
                    data_list)
        else:
            table.entry_add(
                    self.target,
                    key_list)
            
        # Fetch handles
        for key in key_list:
            resp = table.handle_get(target, [key])
            handle_list.append(resp)

        # Now use handle to get entry data and key.
        # First entry_get is for data and key (tableEntryGet),
        # second one will fetch only key (tableEntryKeyGet).
        for handle in handle_list:
            if len(data_list) > 0:
                # Apply data filter if applicable
                resp = table.entry_get(target, required_data=data_filter,
                                       handle=handle, flags={"from_hw":False})
                for data, _ in resp:
                    data_dict = data.to_dict()
                    try:
                        data_list.remove(data)
                    except ValueError:
                        assert False, 'Invalid data returned'
            resp = table.entry_get(target, handle=handle,
                                   flags={"key_only": True})
            for data, key, tgt in resp:
                key_dict = key.to_dict()
                try:
                    key_list.remove(key)
                except ValueError:
                    assert False, 'Invalid key returned'
                try:
                    data.to_dict()
                except Exception:
                    logger.info("No data received - as expected")
                else:
                    assert False, 'Unexpected data received'
                assert tgt==target, 'Received entry target do not match expected'

        # Clear table
        table.entry_del(self.target, [])
        assert len(data_list) == 0, 'data_list should be empty after receiving all test entries'
        assert len(key_list) == 0, 'key_list should be empty after receiving all test entries'

    def runTest(self):
        # Get table handle for every type
        cntr_tbl = self.bfrt_info.table_get('Ing.c1.cntr')
        mtr_tbl = self.bfrt_info.table_get('Ing.c1.mtr')
        reg_tbl = self.bfrt_info.table_get('Ing.c1.reg')
        wred_tbl = self.bfrt_info.table_get('Ing.c1.wred')
        selector_tbl = self.bfrt_info.table_get('Ing.c1.action_selector')
        action_tbl = self.bfrt_info.table_get('Ing.c1.action_profile')
        mat_tbl = self.bfrt_info.table_get('Ing.c1.match_tbl')
        indir_mat_tbl = self.bfrt_info.table_get('Ing.c1.selec_tbl')
        phase0_tbl = self.bfrt_info.table_get('IngPrsr.$PORT_METADATA')
        pvs_tbl = self.bfrt_info.table_get('IngPrsr.data_value')
        snapshot_tbl = self.bfrt_info.table_get('$SNAPSHOT_INGRESS')
        key_list = []
        data_list = []
 
        # PHASE0 TBL
        # Create data set to operate on
        logger.info("Testing PHASE0 table...")
        table = phase0_tbl
        for x in range(1,8):
            key_list.append(table.make_key(
                    [gc.KeyTuple('intr_md.ingress_port', x)]))
            data_list.append(table.make_data(
                    [gc.DataTuple('dummy_field', 1)]))
        self.testTable(table, key_list, data_list)

        # PVS TBL
        # Create data set to operate on
        logger.info("Testing PVS table...")
        table = pvs_tbl
        for x in range(1,5):
            key_list.append(table.make_key(
                    [gc.KeyTuple('f16', x, 0xffff),
                     gc.KeyTuple('f8', x+100, 0xff)]))
        self.testTable(table, key_list, data_list)

        # MAT TBL
        # Create data set to operate on
        logger.info("Testing MAT table...")
        table = mat_tbl
        for x in range(1,5):
            key_list.append(table.make_key(
                    [gc.KeyTuple('hdr.ipv4.dst', x+0xffff),
                     # Use prefix len of 32, otherwise returned key will not match
                     # because of automatically filtered bits.
                     gc.KeyTuple('hdr.ipv4.src', x+0xffff, prefix_len=32),
                     gc.KeyTuple('hdr.ipv4.$valid', 1)]))
            data_list.append(table.make_data(
                    [gc.DataTuple('da', 0xff00ff-x)],
                     "Ing.c1.ipda_modify"))
        self.testTable(table, key_list, data_list, data_filter=data_list[0])

        # Action TBL
        # Create data set to operate on
        logger.info("Testing Action table...")
        table = action_tbl
        for x in range(1,5):
            key_list.append(table.make_key(
                    [gc.KeyTuple('$ACTION_MEMBER_ID', x)]))
            data_list.append(table.make_data(
                    [gc.DataTuple('da', 0xff00ff-x),
                     gc.DataTuple('port', x)],
                     "Ing.c1.ipda_modify"))
        self.testTable(table, key_list, data_list)

        # Selector and indirect match need selector and action table entries
        for x in range(1,5):
            action_tbl.entry_add(self.target,
                [action_tbl.make_key(
                    [gc.KeyTuple('$ACTION_MEMBER_ID', 32-x)])],
                [action_tbl.make_data(
                    [gc.DataTuple('ttl', 10+x),
                     gc.DataTuple('port', 5+x)],
                     "Ing.c1.ipttl_modify")])

        # INDIRECT MATCH ACTION TBL
        # Create data set to operate on
        logger.info("Testing INDIRECT MAT table...")
        table = indir_mat_tbl
        for x in range(1,5):
            key_list.append(table.make_key(
                    [gc.KeyTuple('hdr.ipv4.dst', x+0xAFFFF00),
                     gc.KeyTuple('hdr.ipv4.src', x+1001, prefix_len=32),
                     gc.KeyTuple('hdr.ipv4.$valid', 1)]))
            data_list.append(table.make_data(
                    [gc.DataTuple('$ACTION_MEMBER_ID', 32-x)]))
        self.testTable(table, key_list, data_list)

        # SELECTOR TBL
        # Create data set to operate on
        logger.info("Testing SELECTOR table...")
        table = selector_tbl
        for x in range(1,5):
            key_list.append(table.make_key(
                    [gc.KeyTuple('$SELECTOR_GROUP_ID', x)]))
            data_list.append(table.make_data(
                    [gc.DataTuple('$ACTION_MEMBER_ID', int_arr_val=[32-x]),
                     gc.DataTuple('$ACTION_MEMBER_STATUS', bool_arr_val=[True]),
                     gc.DataTuple('$MAX_GROUP_SIZE', 10)]))
        self.testTable(table, key_list, data_list)

        # Clear action tbl after tests
        action_tbl.entry_del(self.target, [])

        # Counter TBL
        # Create data set to operate on
        logger.info("Testing COUNTER table...")
        table = cntr_tbl
        for x in range(1,8):
            key_list.append(table.make_key(
                    [gc.KeyTuple('$COUNTER_INDEX', x)]))
            data_list.append(table.make_data(
                    [gc.DataTuple('$COUNTER_SPEC_BYTES', 64*x),
                     gc.DataTuple('$COUNTER_SPEC_PKTS', x)]))
        self.testTable(table, key_list, data_list)

        # Register TBL
        # Create data set to operate on
        logger.info("Testing REGISTER table...")
        table = reg_tbl
        for x in range(1,8):
            key_list.append(table.make_key(
                    [gc.KeyTuple('$REGISTER_INDEX', 128-x)]))
            data_list.append(table.make_data(
                    [gc.DataTuple('Ing.c1.reg.first', x+10),
                     gc.DataTuple('Ing.c1.reg.second', 100*x)]))
        self.testTable(table, key_list, data_list, target=gc.Target(device_id=dev_id, pipe_id=0))

        # Meter TBL
        # Create data set to operate on
        # No support for filters
        logger.info("Testing METER table...")
        table = mtr_tbl
        for x in range(1,8):
            key_list.append(table.make_key(
                    [gc.KeyTuple('$METER_INDEX', x)]))
            data_list.append(table.make_data(
                    [gc.DataTuple('$METER_SPEC_CIR_KBPS', 2*x),
                     gc.DataTuple('$METER_SPEC_CBS_KBITS', 4*x),
                     gc.DataTuple('$METER_SPEC_PBS_KBITS', 6*x),
                     gc.DataTuple('$METER_SPEC_PIR_KBPS', 8*x)]))
        self.testTable(table, key_list, data_list)

        # WRED TBL
        # Create data set to operate on
        # Float values passed to the API are rounded to closest supported by HW,
        # hence hardcoded to avoid missmatch during validation.
        logger.info("Testing WRED table...")
        table = wred_tbl
        const_ns = 0
        if is_tofino2:
            # Same for SW and HW
            const_ns = 7.9765625
        else:
            # Tofino 1
            if is_hw:
                const_ns = 7.966188430786133
            else:
                const_ns = 7.990755081176758
        for x in range(1,8):
            key_list.append(table.make_key(
                    [gc.KeyTuple('$WRED_INDEX', x)]))
            data_list.append(table.make_data(
                    [
                     gc.DataTuple('$WRED_SPEC_MAX_PROBABILITY', float_val=0.11999999731779099),
                     gc.DataTuple('$WRED_SPEC_MIN_THRESH_CELLS', 4*x),
                     gc.DataTuple('$WRED_SPEC_MAX_THRESH_CELLS', 6*x),
                     gc.DataTuple('$WRED_SPEC_TIME_CONSTANT_NS', float_val=const_ns)
                    ]))
        self.testTable(table, key_list, data_list)

        # Snapshot TBL
        # Create data set to operate on
        # Custom handled table, no data validation
        logger.info("Testing SNAPSHOT table...")
        table = snapshot_tbl
        # Custom target as snapshot need gress and pipe for get.
        trgt = gc.Target(device_id=dev_id, pipe_id=0, direction=0)
        for x in range(0,4):
            key_list.append(table.make_key(
                    [gc.KeyTuple('$SNAPSHOT_TRIGGER_STAGE', 2*x),
                     gc.KeyTuple('$SNAPSHOT_END_STAGE', (2*x)+1)]))

        table.entry_del(trgt, [])
        table.entry_add(trgt, key_list)
        handle_list = []     
        # Fetch handles
        for key in key_list:
            resp = table.handle_get(trgt, [key])
            handle_list.append(resp)
        # Fetch data and keys
        for handle in handle_list:
            resp = table.entry_get(trgt, handle=handle, flags={"from_hw":False})
            # Check if no error by dereferencing (impossible to validate data).
            # Keys will be validated in next step.
            for data, key in resp:
                data_dict = data.to_dict()
                key_dict = key.to_dict()
            # Get key and validate start and end stage
            resp = table.entry_get(trgt, handle=handle, flags={"key_only": True})
            for _, key, tgt in resp:
                assert tgt == trgt, 'Unexpected entry target returned'
                key_dict = key.to_dict()
                for add_key in key_list:
                    add_key_dict = add_key.to_dict()
                    if add_key_dict['$SNAPSHOT_TRIGGER_STAGE'] == key_dict['$SNAPSHOT_TRIGGER_STAGE'] and add_key_dict['$SNAPSHOT_END_STAGE'] == key_dict['$SNAPSHOT_END_STAGE']:
                        key_list.remove(add_key)
        # Clear table
        table.entry_del(trgt, [])
        assert len(data_list) == 0, 'data_list should be empty after receiving all test entries'
        assert len(key_list) == 0, 'key_list should be empty after receiving all test entries'


