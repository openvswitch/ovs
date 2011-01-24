/*
 * Copyright (c) 2009, 2010 Nicira Networks.
 *
 * This file is offered under your choice of two licenses: Apache 2.0 or GNU
 * GPL 2.0 or later.  The permission statements for each of these licenses is
 * given below.  You may license your modifications to this file under either
 * of these licenses or both.  If you wish to license your modifications under
 * only one of these licenses, delete the permission text for the other
 * license.
 *
 * ----------------------------------------------------------------------
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ----------------------------------------------------------------------
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * ----------------------------------------------------------------------
 */

/* Protocol between userspace and kernel datapath.
 *
 * Be sure to update datapath/odp-compat.h if you change any of the structures
 * in here. */

#ifndef OPENVSWITCH_DATAPATH_PROTOCOL_H
#define OPENVSWITCH_DATAPATH_PROTOCOL_H 1

/* The ovs_be<N> types indicate that an object is in big-endian, not
 * native-endian, byte order.  They are otherwise equivalent to uint<N>_t.
 * The Linux kernel already has __be<N> types for this, which take on
 * additional semantics when the "sparse" static checker is used, so we use
 * those types when compiling the kernel. */
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/socket.h>
#define ovs_be16 __be16
#define ovs_be32 __be32
#define ovs_be64 __be64
#else
#include "openvswitch/types.h"
#include <sys/socket.h>
#endif

#ifndef __aligned_u64
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#define __aligned_be64 __be64 __attribute__((aligned(8)))
#define __aligned_le64 __le64 __attribute__((aligned(8)))
#endif

#include <linux/if_link.h>
#include <linux/netlink.h>

#define ODP_MAX 256             /* Maximum number of datapaths. */

#define ODP_DP_CREATE           _IO('O', 0)
#define ODP_DP_DESTROY          _IO('O', 1)
#define ODP_DP_STATS            _IOW('O', 2, struct odp_stats)

#define ODP_GET_DROP_FRAGS      _IOW('O', 3, int)
#define ODP_SET_DROP_FRAGS      _IOR('O', 4, int)

#define ODP_GET_LISTEN_MASK     _IOW('O', 5, int)
#define ODP_SET_LISTEN_MASK     _IOR('O', 6, int)

#define ODP_VPORT_ATTACH        _IOR('O', 7, struct odp_port)
#define ODP_VPORT_DETACH        _IOR('O', 8, int)
#define ODP_VPORT_QUERY         _IOWR('O', 9, struct odp_port)
#define ODP_VPORT_LIST          _IOWR('O', 10, struct odp_portvec)

#define ODP_FLOW_GET            _IOWR('O', 13, struct odp_flowvec)
#define ODP_FLOW_PUT            _IOWR('O', 14, struct odp_flow)
#define ODP_FLOW_DUMP           _IOWR('O', 15, struct odp_flow_dump)
#define ODP_FLOW_FLUSH          _IO('O', 16)
#define ODP_FLOW_DEL            _IOWR('O', 17, struct odp_flow)

#define ODP_EXECUTE             _IOR('O', 18, struct odp_execute)

#define ODP_SET_SFLOW_PROBABILITY _IOR('O', 19, int)
#define ODP_GET_SFLOW_PROBABILITY _IOW('O', 20, int)

#define ODP_VPORT_MOD           _IOR('O', 22, struct odp_port)
#define ODP_VPORT_STATS_GET     _IOWR('O', 24, struct odp_vport_stats_req)
#define ODP_VPORT_ETHER_GET     _IOWR('O', 25, struct odp_vport_ether)
#define ODP_VPORT_ETHER_SET     _IOW('O', 26, struct odp_vport_ether)
#define ODP_VPORT_MTU_GET       _IOWR('O', 27, struct odp_vport_mtu)
#define ODP_VPORT_MTU_SET       _IOW('O', 28, struct odp_vport_mtu)
#define ODP_VPORT_STATS_SET     _IOWR('O', 29, struct odp_vport_stats_req)

struct odp_stats {
    /* Flows. */
    uint32_t n_flows;           /* Number of flows in flow table. */
    uint32_t cur_capacity;      /* Current flow table capacity. */
    uint32_t max_capacity;      /* Maximum expansion of flow table capacity. */

    /* Ports. */
    uint32_t n_ports;           /* Current number of ports. */
    uint32_t max_ports;         /* Maximum supported number of ports. */

    /* Lookups. */
    uint64_t n_frags;           /* Number of dropped IP fragments. */
    uint64_t n_hit;             /* Number of flow table matches. */
    uint64_t n_missed;          /* Number of flow table misses. */
    uint64_t n_lost;            /* Number of misses not sent to userspace. */

    /* Queues. */
    uint16_t max_miss_queue;    /* Max length of ODPL_MISS queue. */
    uint16_t max_action_queue;  /* Max length of ODPL_ACTION queue. */
    uint16_t max_sflow_queue;   /* Max length of ODPL_SFLOW queue. */
};

/* Logical ports. */
#define ODPP_LOCAL      ((uint16_t)0)
#define ODPP_NONE       ((uint16_t)-1)

/* Listening channels. */
#define _ODPL_MISS_NR   0       /* Packet missed in flow table. */
#define ODPL_MISS       (1 << _ODPL_MISS_NR)
#define _ODPL_ACTION_NR 1       /* Packet output to ODPP_CONTROLLER. */
#define ODPL_ACTION     (1 << _ODPL_ACTION_NR)
#define _ODPL_SFLOW_NR  2       /* sFlow samples. */
#define ODPL_SFLOW      (1 << _ODPL_SFLOW_NR)
#define ODPL_ALL        (ODPL_MISS | ODPL_ACTION | ODPL_SFLOW)

/**
 * struct odp_msg - format of messages read from datapath fd.
 * @length: Total length of message, including this header.
 * @type: One of the %_ODPL_* constants.
 * @port: Port that received the packet embedded in this message.
 * @arg: Argument value whose meaning depends on @type.
 *
 * For @type == %_ODPL_MISS_NR, the header is followed by packet data.  The
 * @arg member is the ID (in network byte order) of the tunnel that
 * encapsulated this packet. It is 0 if the packet was not received on a tunnel.
 *
 * For @type == %_ODPL_ACTION_NR, the header is followed by packet data.  The
 * @arg member is copied from the %ODPAT_CONTROLLER action that caused the
 * &struct odp_msg to be composed.
 *
 * For @type == %_ODPL_SFLOW_NR, the header is followed by &struct
 * odp_sflow_sample_header, then by a series of Netlink attributes (whose
 * length is specified in &struct odp_sflow_sample_header), then by packet
 * data.
 */
struct odp_msg {
    uint32_t length;
    uint16_t type;
    uint16_t port;
    __aligned_u64 arg;
};

/**
 * struct odp_sflow_sample_header - header added to sFlow sampled packet.
 * @sample_pool: Number of packets that were candidates for sFlow sampling,
 * regardless of whether they were actually chosen and sent down to userspace.
 * @actions_len: Number of bytes of actions immediately following this header.
 *
 * This header follows &struct odp_msg when that structure's @type is
 * %_ODPL_SFLOW_NR, and it is itself followed by a series of Netlink attributes
 * (the number of bytes of which is specified in @actions_len) and then by
 * packet data.
 */
struct odp_sflow_sample_header {
    uint32_t sample_pool;
    uint32_t actions_len;
};

#define VPORT_TYPE_SIZE     16
#define VPORT_CONFIG_SIZE     32
struct odp_port {
    char devname[16];           /* IFNAMSIZ */
    char type[VPORT_TYPE_SIZE];
    uint16_t port;
    uint16_t reserved1;
    uint32_t reserved2;
    __aligned_u64 config[VPORT_CONFIG_SIZE / 8]; /* type-specific */
};

struct odp_portvec {
    struct odp_port *ports;
    uint32_t n_ports;
};

struct odp_flow_stats {
    uint64_t n_packets;         /* Number of matched packets. */
    uint64_t n_bytes;           /* Number of matched bytes. */
    uint64_t used_sec;          /* Time last used, in system monotonic time. */
    uint32_t used_nsec;
    uint8_t  tcp_flags;
    uint8_t  reserved;
    uint16_t error;             /* Used by ODP_FLOW_GET. */
};

enum odp_key_type {
	ODP_KEY_ATTR_UNSPEC,
	ODP_KEY_ATTR_TUN_ID,    /* 64-bit tunnel ID */
	ODP_KEY_ATTR_IN_PORT,   /* 32-bit ODP port number */
	ODP_KEY_ATTR_ETHERNET,  /* struct odp_key_ethernet */
	ODP_KEY_ATTR_8021Q,     /* struct odp_key_8021q */
	ODP_KEY_ATTR_ETHERTYPE,	/* 16-bit Ethernet type */
	ODP_KEY_ATTR_IPV4,      /* struct odp_key_ipv4 */
	ODP_KEY_ATTR_TCP,       /* struct odp_key_tcp */
	ODP_KEY_ATTR_UDP,       /* struct odp_key_udp */
	ODP_KEY_ATTR_ICMP,      /* struct odp_key_icmp */
	ODP_KEY_ATTR_ARP,       /* struct odp_key_arp */
	__ODP_KEY_ATTR_MAX
};

#define ODP_KEY_ATTR_MAX (__ODP_KEY_ATTR_MAX - 1)

struct odp_key_ethernet {
	uint8_t	 eth_src[6];
	uint8_t	 eth_dst[6];
};

struct odp_key_8021q {
	ovs_be16 q_tpid;
	ovs_be16 q_tci;
};

struct odp_key_ipv4 {
	ovs_be32 ipv4_src;
	ovs_be32 ipv4_dst;
	uint8_t  ipv4_proto;
	uint8_t  ipv4_tos;
};

struct odp_key_tcp {
	ovs_be16 tcp_src;
	ovs_be16 tcp_dst;
};

struct odp_key_udp {
	ovs_be16 udp_src;
	ovs_be16 udp_dst;
};

struct odp_key_icmp {
	uint8_t icmp_type;
	uint8_t icmp_code;
};

struct odp_key_arp {
	ovs_be32 arp_sip;
	ovs_be32 arp_tip;
	ovs_be16 arp_op;
};

/* Flags for ODP_FLOW. */
#define ODPFF_ZERO_TCP_FLAGS (1 << 0) /* Zero the TCP flags. */
#define ODPFF_EOF            (1 << 1) /* ODP_FLOW_DUMP: end of flow table. */

struct odp_flow {
    struct odp_flow_stats stats;
    struct nlattr *key;
    uint32_t key_len;
    struct nlattr *actions;
    uint32_t actions_len;
    uint32_t flags;
};

/* Flags for ODP_FLOW_PUT. */
#define ODPPF_CREATE        (1 << 0) /* Allow creating a new flow. */
#define ODPPF_MODIFY        (1 << 1) /* Allow modifying an existing flow. */
#define ODPPF_ZERO_STATS    (1 << 2) /* Zero the stats of an existing flow. */

/* ODP_FLOW_PUT argument. */
struct odp_flow_put {
    struct odp_flow flow;
    uint32_t flags;
};

struct odp_flowvec {
    struct odp_flow *flows;
    uint32_t n_flows;
};

/* ODP_FLOW_DUMP argument.
 *
 * This is used to iterate through the flow table flow-by-flow.  Each
 * ODP_FLOW_DUMP call either stores a new odp_flow into 'flow' or stores
 * ODPFF_EOF into flow->flags to indicate that the end of the table has been
 * reaches, and updates 'state' in-place.
 *
 * Before the first call, zero 'state'.  The format of 'state' is otherwise
 * unspecified.
 */
struct odp_flow_dump {
	struct odp_flow *flow;
	uint32_t state[2];
};

/* Action types. */
enum odp_action_type {
    ODPAT_UNSPEC,
    ODPAT_OUTPUT,		/* Output to switch port. */
    ODPAT_CONTROLLER,		/* Send copy to controller. */
    ODPAT_SET_DL_TCI,		/* Set the 802.1q TCI value. */
    ODPAT_STRIP_VLAN,		/* Strip the 802.1q header. */
    ODPAT_SET_DL_SRC,		/* Ethernet source address. */
    ODPAT_SET_DL_DST,		/* Ethernet destination address. */
    ODPAT_SET_NW_SRC,		/* IPv4 source address. */
    ODPAT_SET_NW_DST,		/* IPv4 destination address. */
    ODPAT_SET_NW_TOS,		/* IP ToS/DSCP field (6 bits). */
    ODPAT_SET_TP_SRC,		/* TCP/UDP source port. */
    ODPAT_SET_TP_DST,		/* TCP/UDP destination port. */
    ODPAT_SET_TUNNEL,		/* Set the encapsulating tunnel ID. */
    ODPAT_SET_PRIORITY,		/* Set skb->priority. */
    ODPAT_POP_PRIORITY,		/* Restore original skb->priority. */
    ODPAT_DROP_SPOOFED_ARP,	/* Drop ARPs with spoofed source MAC. */
    __ODPAT_MAX
};

#define ODPAT_MAX (__ODPAT_MAX - 1)

struct odp_execute {
    struct nlattr *actions;
    uint32_t actions_len;

    const void *data;
    uint32_t length;
};

#define VPORT_TYPE_SIZE     16
struct odp_vport_add {
    char port_type[VPORT_TYPE_SIZE];
    char devname[16];           /* IFNAMSIZ */
    void *config;
};

struct odp_vport_mod {
    char devname[16];           /* IFNAMSIZ */
    void *config;
};

struct odp_vport_stats_req {
    char devname[16];           /* IFNAMSIZ */
    struct rtnl_link_stats64 stats;
};

struct odp_vport_ether {
    char devname[16];           /* IFNAMSIZ */
    unsigned char ether_addr[6];
};

struct odp_vport_mtu {
    char devname[16];           /* IFNAMSIZ */
    uint16_t mtu;
};

#endif  /* openvswitch/datapath-protocol.h */
