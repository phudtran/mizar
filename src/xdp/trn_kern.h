// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * @file transit_kern.h
 * @author Sherif Abdelwahab (@zasherif)
 *
 * @brief Helper functions, macros and data structures.
 *
 * @copyright Copyright (c) 2019 The Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#pragma once

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stddef.h>

#include "extern/bpf_helpers.h"
#include "extern/jhash.h"

#include "trn_datamodel.h"

#define PRIu8 "hu"
#define PRId8 "hd"
#define PRIx8 "hx"
#define PRIu16 "hu"
#define PRId16 "hd"
#define PRIx16 "hx"
#define PRIu32 "u"
#define PRId32 "d"
#define PRIx32 "x"
#define PRIu64 "llu" // or possibly "lu"
#define PRId64 "lld" // or possibly "ld"
#define PRIx64 "llx" // or possibly "lx"

#define TRN_DEFAULT_TTL 64
#define GEN_DSTPORT 0xc117
#define INIT_JHASH_SEED 0xdeadbeef

#define TRN_GNV_OPT_CLASS 0x0111
#define TRN_GNV_RTS_OPT_TYPE 0x48
#define TRN_GNV_SCALED_EP_OPT_TYPE 0x49
#define TRN_GNV_POD_LABEL_VALUE_OPT_TYPE 0x50
#define TRN_GNV_NAMESPACE_LABEL_VALUE_OPT_TYPE 0x51

/* Scaled endpoint messages type */
#define TRN_SCALED_EP_MODIFY 0x4d // (M: Modify)

#ifndef __inline
#define __inline inline __attribute__((always_inline))
#endif

struct trn_gnv_scaled_ep_data {
	__u8 msg_type;
	struct scaled_endpoint_remote_t target;
} __attribute__((packed, aligned(4)));

struct trn_gnv_scaled_ep_opt {
	__be16 opt_class;
	__u8 type;
	__u8 length : 5;
	__u8 r3 : 1;
	__u8 r2 : 1;
	__u8 r1 : 1;
	/* opt data */
	struct trn_gnv_scaled_ep_data scaled_ep_data;
} __attribute__((packed, aligned(4)));

struct trn_gnv_label_value_data {
	__u32 value;
} __attribute__((packed, aligned(4)));

struct trn_gnv_label_value_opt {
	__be16 opt_class;
	__u8 type;
	__u8 length : 5;
	__u8 r3 : 1;
	__u8 r2 : 1;
	__u8 r1 : 1;
	/* opt data */
	struct trn_gnv_label_value_data label_value_data;
} __attribute__((packed, aligned(4)));

struct trn_gnv_rts_data {
	__u8 match_flow : 1;
	struct remote_endpoint_t host;
} __attribute__((packed, aligned(4)));

struct trn_gnv_rts_opt {
	__be16 opt_class;
	__u8 type;
	__u8 length : 5;
	__u8 r3 : 1;
	__u8 r2 : 1;
	__u8 r1 : 1;
	/* opt data */
	struct trn_gnv_rts_data rts_data;
} __attribute__((packed, aligned(4)));

struct geneve_opt {
	__be16 opt_class;
	__u8 type;
	__u8 length : 5;
	__u8 r3 : 1;
	__u8 r2 : 1;
	__u8 r1 : 1;
	__u8 opt_data[];
};

struct genevehdr {
	/* Big endian! */
	__u8 opt_len : 6;
	__u8 ver : 2;
	__u8 rsvd1 : 6;
	__u8 critical : 1;
	__u8 oam : 1;
	__be16 proto_type;
	__u8 vni[3];
	__u8 rsvd2;
	struct geneve_opt options[];
};

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct transit_packet {
	void *data;
	void *data_end;

	/* interface index */
	int itf_idx;
	__u32 itf_ipv4;

	/* xdp*/
	struct xdp_md *xdp;

	/* Ether */
	struct ethhdr *eth;
	__u64 eth_off;

	/* IP */
	struct iphdr *ip;

	/* UDP */
	struct udphdr *udp;

	/* Geneve */
	struct genevehdr *geneve;
	struct trn_gnv_rts_opt *rts_opt;
	struct trn_gnv_scaled_ep_opt *scaled_ep_opt;
	struct trn_gnv_label_value_opt *pod_label_value_opt;
	struct trn_gnv_label_value_opt *namespace_label_value_opt;
	int gnv_hdr_len;
	int gnv_opt_len;

	/* Inner ethernet */
	struct ethhdr *inner_eth;
	__u64 inner_eth_off;

	/* Inner arp */
	// struct _arp_hdr *inner_arp;
	struct arphdr *inner_arp;

	/* Inner IP */
	struct iphdr *inner_ip;
	__u8 inner_ttl;
	__u8 inner_tos;

	/* Inner udp */
	struct udphdr *inner_udp;

	/* Inner tcp */
	struct tcphdr *inner_tcp;

	/* inner ipv4 tuple */
	struct ipv4_tuple_t inner_ipv4_tuple;

	/* Agent metadata */
	struct agent_metadata_t *agent_md;
	__be64 agent_ep_tunid;
	__u32 agent_ep_ipv4;

	// TODO: Inner UDP or TCP
} __attribute__((packed));
