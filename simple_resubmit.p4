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

const bit<8> RESUB_TYPE = 1;
const bit<3> DPSRS_RESUBMIT_TYPE = 1;

header resubmit_md_t {
  bit<8> type;
  bit<56> value;
}

struct port_metadata_t {
  bit<32> f1;
  bit<32> f2;
}

struct metadata_t {
  port_metadata_t port_metadata;
  resubmit_md_t resubmit_md;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(packet_in pkt, out header_t hdr, out metadata_t ig_md,
                    out ingress_intrinsic_metadata_t ig_intr_md) {

  /*TofinoIngressParser() tofino_parser;*/

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
    ig_md.port_metadata = port_metadata_unpack<port_metadata_t>(pkt);
    transition parse_ethernet;
  }

  state parse_resubmit {
    pkt.extract(ig_md.resubmit_md);
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
    if (ig_intr_dprsr_md.resubmit_type == DPSRS_RESUBMIT_TYPE) {
      resubmit.emit(ig_md.resubmit_md);
    }
    pkt.emit(hdr);
  }
}

control SwitchIngress(inout header_t hdr, inout metadata_t ig_md,
              in ingress_intrinsic_metadata_t ig_intr_md,
              in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
              inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
              inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

  Counter<bit<1>, bit<2>>(4, CounterType_t.PACKETS) cntr;

  action resubmit_hdr(bit<56> val) {
    ig_md.resubmit_md.type = RESUB_TYPE;
    ig_md.resubmit_md.value = val;
    ig_intr_dprsr_md.resubmit_type = DPSRS_RESUBMIT_TYPE;

    cntr.count(0);
  }

  action no_resub() { }
  action drop() { ig_intr_dprsr_md.drop_ctl = 1; }

  table resub {
    key = {
      ig_intr_md.ingress_port : exact @name("port");
      ig_md.port_metadata.f1  : exact @name("f1");
      ig_md.port_metadata.f2  : exact @name("f2");
    }
    actions = {
      resubmit_hdr;
      no_resub;
      drop;
    }
    default_action = drop;
    size = 256;
  }

  action okay() { cntr.count(1); }

  table pass_two {
    key = {
      ig_md.resubmit_md.value : exact;
    }
    actions = {
      okay;
    }
    size = 256;
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
      // Resubmit packet
      /*hdr.ethernet.dst_addr = 1;*/
      /*hdr.ethernet.src_addr = 0;*/
      resub.apply();
    } else {
      pass_two.apply();
    }

    ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    ig_intr_tm_md.bypass_egress = 1w1;
    /*forward.apply();*/
  }
}

Pipeline(SwitchIngressParser(), SwitchIngress(), SwitchIngressDeparser(),
         EmptyEgressParser(), EmptyEgress(), EmptyEgressDeparser()) pipe;

Switch(pipe) main;
