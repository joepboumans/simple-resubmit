#!/usr/bin/python3
import logging
from collections import namedtuple
from time import perf_counter
import random

from ptf import config
import ptf.testutils as testutils
from p4testutils.misc_utils import *
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

swports = get_sw_ports()
logger = logging.getLogger('waterfall')

if not len(logger.handlers):
    sh = logging.StreamHandler()
    formatter = logging.Formatter('[%(levelname)s - %(name)s - %(funcName)s]: %(message)s')
    sh.setFormatter(formatter)
    sh.setLevel(logging.INFO)
    logger.addHandler(sh)

class TestTest(BfRuntimeTest):
    def setUp(self):
        logger.info("Starting setup")
        client_id = 0
        BfRuntimeTest.setUp(self, client_id)
        logger.info("\tfinished BfRuntimeSetup")

        self.bfrt_info = self.interface.bfrt_info_get("waterfall")
        self.forward_table = self.bfrt_info.table_get("SwitchIngress.forward")
        self.forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
        self.tables = []
        for i in range(1,2):
            for j in range(1,2):
                logger.info(f"Adding table_{i}_{j}")
                self.tables.append(self.bfrt_info.table_get(f"SwitchIngress.table_{i}_{j}"))
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        logger.info("Finished setup")

    def runTest(self):
        logger.info("Start testing")
        ig_port = swports[0]
        seed=1001
        bfrt_info = self.bfrt_info
        target = self.target
        forward_table = self.forward_table

        key_tuple = namedtuple('key', 'dst_ip')
        data_tuple = namedtuple('data', 'eg_port')
        key_list = []
        data_list = []
        forward_dict = {}

        ''' TC:1 Setting and validating forwarding plane via get'''
        logger.info("Populating foward table...")
        num_entries =  1
        logger.info(f"Generating {num_entries} random ips with seed {seed}")
        ip_list = self.generate_random_ip_list(num_entries, seed)
        logger.info("Adding entries to forward table")
        for ip_entry in ip_list:
            dst_addr = getattr(ip_entry, "ip")
            eg_port = swports[random.randint(0, len(swports) - 1)]

            key_list.append(key_tuple(dst_addr))
            data_list.append(data_tuple(eg_port))

            logger.debug(f"\tinserting table entry with IP {dst_addr} and egress port {eg_port}")
            key = forward_table.make_key([gc.KeyTuple('hdr.ipv4.dst_addr', dst_addr)])
            data = forward_table.make_data([gc.DataTuple('dst_port', eg_port)], 'SwitchIngress.route')

            forward_table.entry_add(target, [key], [data])
            
            key.apply_mask()
            forward_dict[key] = data


        logger.info("Validate forwarding table via get")
        resp = forward_table.entry_get(target)
        for data, key in resp:
            logger.debug(f"\tresp = {data} : {key}")
            assert forward_dict[key] == data
            forward_dict.pop(key)
        assert len(forward_dict) == 0
        logger.info("Forward plane validated")

        ''' TC:2 Validate forward plane via packets'''
        test_list = list(zip(key_list, data_list))
        logger.info(f"Sending packets over port {ig_port}")
        for key, data in test_list:
            pkt = testutils.simple_tcp_packet(ip_dst=key.dst_ip)
            exp_pkt = testutils.simple_tcp_packet(ip_dst=key.dst_ip)
            logger.debug(f"\tsending: {key.dst_ip}")
            testutils.send_packet(self, ig_port, pkt)
            # logger.debug(f"\texpecting pkt with port {data.eg_port}")
            testutils.verify_packets(self, exp_pkt, [data.eg_port])
            # break
        for key, data in test_list:
            pkt = testutils.simple_tcp_packet(ip_dst=key.dst_ip)
            exp_pkt = testutils.simple_tcp_packet(ip_dst=key.dst_ip)
            logger.debug(f"\tsending: {key.dst_ip}")
            testutils.send_packet(self, ig_port, pkt)
            # logger.debug(f"\texpecting pkt with port {data.eg_port}")
            testutils.verify_packets(self, exp_pkt, [data.eg_port])

        logger.info(f"All expected packets recieved")

        ''' TC:3 Get the table values'''
        for i in range(1):
            for j in range(1):
                logger.info(f"Getting table_{i + 1}_{j + 1}")
                try:
                    dump = self.tables[0].entry_get(target, [], {"from_hw" : True})
                except:
                    break;
                logger.info(f"Got table_{i + 1}_{j + 1}")
                for data, key in dump:
                    data_dict = data.to_dict()
                    e = data_dict[f"SwitchIngress.table_{i + 1}_{j + 1}.f1"]
                    # logger.info(e)
                    for entry_val in e:
                        if entry_val != 0:
                            logger.info(data[f"SwitchIngress.table_{i + 1}_{j + 1}.f1"].int_arr_val)
                    #         logger.info(f"got value {entry_val}")
                            # logger.info(data)
                            break
                    #         logger.info(key)


    def tearDown(self):
        logger.info("Tearing down test")
        self.forward_table.entry_del(self.target)
        usage = next(self.forward_table.usage_get(self.target, []))
        for table in self.tables:
            # logger.info(f"Removing table {table.info.id}")
            try:
                table.entry_del(self.target)
            except:
                pass
        assert usage == 0
        BfRuntimeTest.tearDown(self)
