#!/usr/bin/python3
import logging
from collections import namedtuple
from math import radians
import random

from ptf import config
import ptf.testutils as testutils
from p4testutils.misc_utils import *
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

swports = get_sw_ports()
logger = logging.getLogger('simple_resubmit')

if not len(logger.handlers):
    sh = logging.StreamHandler()
    formatter = logging.Formatter('[%(levelname)s - %(name)s - %(funcName)s]: %(message)s')
    sh.setFormatter(formatter)
    sh.setLevel(logging.INFO)
    logger.addHandler(sh)

# class NoResubmitTest(BfRuntimeTest):
#     def setUp(self):
#         logger.info("Starting setup")
#         client_id = 0
#         BfRuntimeTest.setUp(self, client_id)
#         logger.info("\tfinished BfRuntimeSetup")
#
#         self.bfrt_info = self.interface.bfrt_info_get("simple_resubmit")
#         self.port_meta = self.bfrt_info.table_get("$PORT_METADATA")
#         self.resub = self.bfrt_info.table_get("resub")
#         self.target = gc.Target(device_id=0, pipe_id=0xffff)
#         logger.info("Finished setup")
#
#     def runTest(self):
#         logger.info("Start testing")
#         ig_port = swports[0]
#         target = self.target
#         port_meta = self.port_meta
#         resub = self.resub
#
#         ''' TC:1 Setting up port_metadata and resub'''
#         logger.info("Populating port_meta and resub tables...")
#         ig_port = random.choice(swports)
#         port_meta_values = [random.getrandbits(32), random.getrandbits(32)]
#
#         logger.debug(f"\tport metadata - inserting table entry with port {ig_port} and f1,f2 {port_meta_values}")
#         key = port_meta.make_key([gc.KeyTuple('ig_intr_md.ingress_port', ig_port)])
#         data = port_meta.make_data([gc.DataTuple('f1', port_meta_values[0]), gc.DataTuple('f2', port_meta_values[1])])
#         port_meta.entry_add(target, [key], [data])
#
#         logger.debug(f"\tresub - inserting table entry with port {ig_port} and f1,f2 {port_meta_values}")
#         key = resub.make_key([gc.KeyTuple('port', ig_port),
#                               gc.KeyTuple('f1', port_meta_values[0]),
#                               gc.KeyTuple('f2', port_meta_values[1])])
#         data = resub.make_data([], "SwitchIngress.no_resub")
#         resub.entry_add(target, [key], [data])
#
#         logger.info("Adding entries to port_meta and resub tables")
#         ''' TC:2 Send, receive and verify packets'''
#         pkt_in = testutils.simple_ip_packet()
#         logger.info("Sending simple packet to switch")
#         testutils.send_packet(self, ig_port, pkt_in)
#         logger.info("Verifying simple packet has been correct...")
#         testutils.verify_packet(self, pkt_in, ig_port)
#         logger.info("..packet received correctly")
#
#     def tearDown(self):
#         logger.info("Tearing down test")
#         self.resub.entry_del(self.target)
#         self.port_meta.entry_del(self.target)
#         BfRuntimeTest.tearDown(self)

class ResubmitTest(BfRuntimeTest):
    def setUp(self):
        logger.info("Starting setup")
        client_id = 0
        BfRuntimeTest.setUp(self, client_id)
        logger.info("\tfinished BfRuntimeSetup")

        self.bfrt_info = self.interface.bfrt_info_get("simple_resubmit")
        self.port_meta = self.bfrt_info.table_get("$PORT_METADATA")
        self.resub = self.bfrt_info.table_get("resub")
        self.resub.info.key_field_annotation_add("dst_addr", "ipv4")
        self.pass_two = self.bfrt_info.table_get("pass_two")
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        logger.info("Finished setup")

    def getCntr(self, index):
        t = self.bfrt_info.table_get('cntr')
        resp = t.entry_get(self.target,
                           [t.make_key([gc.KeyTuple('$COUNTER_INDEX', index)])],
                           {"from_hw":True},
                           None)
        data_dict = next(resp)[0].to_dict()
        return data_dict['$COUNTER_SPEC_PKTS']

    def clrCntrs(self):
        t = self.bfrt_info.table_get('cntr')
        for i in range(4):
            t.entry_add(self.target,
                        [t.make_key([gc.KeyTuple('$COUNTER_INDEX', i)])],
                        [t.make_data([gc.DataTuple('$COUNTER_SPEC_PKTS', 0)])])

    def runTest(self):
        logger.info("Start testing")
        ig_port = swports[0]
        target = self.target
        port_meta = self.port_meta
        resub = self.resub
        pass_two = self.pass_two

        ip_list = self.generate_random_ip_list(5, 1)
        ''' TC:1 Setting up port_metadata and resub'''
        for ip_entry in ip_list:
            value = random.getrandbits(56)
            logger.info("Populating port_meta table...")
            ig_port = random.choice(swports)
            port_meta_values = [random.getrandbits(32), random.getrandbits(32)]

            logger.debug(f"\tport metadata - inserting table entry with port {ig_port} and f1,f2 {port_meta_values}")
            key = port_meta.make_key([gc.KeyTuple('ig_intr_md.ingress_port', ig_port)])
            data = port_meta.make_data([gc.DataTuple('f1', port_meta_values[0]), gc.DataTuple('f2', port_meta_values[1])])
            port_meta.entry_add(target, [key], [data])

            logger.info("Populating resub table...")
            logger.debug(f"\tresub - inserting table entry with port {ig_port} and f1,f2 {port_meta_values}")

            dst_addr = getattr(ip_entry, "ip")
            key = resub.make_key([gc.KeyTuple('dst_addr', dst_addr),
                                  gc.KeyTuple('port', ig_port),
                                  gc.KeyTuple('f1', port_meta_values[0]),
                                  gc.KeyTuple('f2', port_meta_values[1])])
            data = resub.make_data([gc.DataTuple('val', value)], "SwitchIngress.resubmit_hdr")
            resub.entry_add(target, [key], [data])

            logger.info("Populating pass_two table...")
            # Add pass two entry
            key = pass_two.make_key([ gc.KeyTuple('value', value)])
            data = pass_two.make_data([], "SwitchIngress.okay")
            pass_two.entry_add(target, [key], [data])

            logger.info("Adding entries to port_meta and resub tables")
            ''' TC:2 Send, receive and verify packets'''
            pkt_in = testutils.simple_ip_packet(ip_dst=dst_addr)
            logger.info("Sending simple packet to switch")
            testutils.send_packet(self, ig_port, pkt_in)
            logger.info("Verifying simple packet has been correct...")
            testutils.verify_packet(self, pkt_in, ig_port)
            logger.info("..packet received correctly")

            logger.info(f"Counter[0]={self.getCntr(0)} == Counter[1]={self.getCntr(1)}")
            assert(self.getCntr(0) == self.getCntr(1))



    def tearDown(self):
        logger.info("Tearing down test")
        self.resub.entry_del(self.target)
        self.port_meta.entry_del(self.target)
        self.pass_two.entry_del(self.target)
        self.clrCntrs()
        BfRuntimeTest.tearDown(self)
