/*******************************************************************************
 *  INTEL CONFIDENTIAL
 *
 *  Copyright (c) 2021 Intel Corporation
 *  All Rights Reserved.
 *
 *  This software and the related documents are Intel copyrighted materials,
 *  and your use of them is governed by the express license under which they
 *  were provided to you ("License"). Unless the License provides otherwise,
 *  you may not use, modify, copy, publish, distribute, disclose or transmit
 *  this software or the related documents without Intel's prior written
 *  permission.
 *
 *  This software and the related documents are provided as is, with no express
 *  or implied warranties, other than those that are expressly stated in the
 *  License.
 ******************************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

#define WATERFALL_WIDTH 16
#define WATERFALL_BIT_WIDTH 4 // 2^WATERFALL_BIT_WIDTH = WATERFALL_WIDTH

const bit<8> RESUB_TYPE_A = 255;
const bit<3> DPRSR_DIGEST_TYPE_A = 5;

header resubmit_type_a {
  bit<8> type;
  bit<8> f1;
  bit<16> f2;
  bit<32> f3;
}

header port_metadata {
  bit<32> f1;
  bit<32> f2;
}

struct metadata_t {
  port_metadata port_md;
  bit<8> resub_type;
  resubmit_type_a a;
  bit<WATERFALL_BIT_WIDTH> idx1;
  bit<WATERFALL_BIT_WIDTH> idx2;
  bit<32> in_src_addr;
  bool found;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(packet_in pkt, out header_t hdr, out metadata_t ig_md,
                    out ingress_intrinsic_metadata_t ig_intr_md) {

  TofinoIngressParser() tofino_parser;

  state start {
    pkt.extract(ig_intr_md);
    /*tofino_parser.apply(pkt, ig_intr_md);*/
    /*transition parse_ethernet;*/
    transition select(ig_intr_md.resubmit_flag) {
      0 : parse_init;
      1 : parse_resubmit;
    }
  }

  state parse_init {
    ig_md.port_md = port_metadata_unpack<port_metadata>(pkt);
    transition parse_ethernet;
  }

  state parse_resubmit {
    ig_md.resub_type = pkt.lookahead<bit<8>>()[7:0];
    transition select(ig_md.resub_type) {
      RESUB_TYPE_A : parse_resub_a;
    }
  }

  state parse_resub_a {
    pkt.extract(ig_md.a);
    transition parse_ethernet;
  }

  state parse_ethernet {
    pkt.extract(hdr.ethernet);
    transition select(hdr.ethernet.ether_type) {
    ETHERTYPE_IPV4:
      parse_ipv4;
    default:
      reject;
    }
  }

  state parse_ipv4 {
    pkt.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) {
    IP_PROTOCOLS_UDP:
      parse_udp;
    IP_PROTOCOLS_TCP:
      parse_tcp;
    default:
      accept;
    }
  }

  state parse_tcp {
    pkt.extract(hdr.tcp);
    transition accept;
  }

  state parse_udp {
    pkt.extract(hdr.udp);
    transition accept;
  }
}
// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser( packet_out pkt, inout header_t hdr, in metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

  Resubmit() resubmit;

  apply {
    if (ig_intr_dprsr_md.resubmit_type == DPRSR_DIGEST_TYPE_A) {
      resubmit.emit(ig_md);
    }
    pkt.emit(hdr);
  }
}

control SwitchIngress(inout header_t hdr, inout metadata_t ig_md,
              in ingress_intrinsic_metadata_t ig_intr_md,
              in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
              inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
              inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

  
  Hash<bit<WATERFALL_BIT_WIDTH>>(HashAlgorithm_t.CRC16) hash1;

  action get_hash1() {
    ig_md.idx1 = hash1.get({hdr.ipv4.src_addr, 
                            hdr.ipv4.dst_addr, 
                            hdr.udp.src_port, 
                            hdr.udp.dst_port,
                            hdr.ipv4.protocol});
  }

  action hit(PortId_t port) {
    ig_intr_tm_md.ucast_egress_port = port;
    ig_intr_dprsr_md.drop_ctl = 0x0;
  }

  action route(PortId_t dst_port) {
    ig_intr_tm_md.ucast_egress_port = dst_port;
    ig_intr_dprsr_md.drop_ctl = 0x0;
  }

  action miss() {
    ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet
  }
  table forward {
    key = { 
      hdr.ipv4.dst_addr : exact;
  }
  actions = { 
    route;
  }

  size = 1024;
 }


  apply { 
    if (ig_intr_md.resubmit_flag == 0) {
      get_hash1();
      // Resubmit packet
      hdr.ethernet.dst_addr = 1;
      hdr.ethernet.src_addr = 0;
    } else {
    }

    ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    ig_intr_tm_md.bypass_egress = 1w1;
    forward.apply();
  }
}

Pipeline(SwitchIngressParser(), SwitchIngress(), SwitchIngressDeparser(),
         EmptyEgressParser(), EmptyEgress(), EmptyEgressDeparser()) pipe;

Switch(pipe) main;
