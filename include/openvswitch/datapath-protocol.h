/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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

#define ODP_VPORT_NEW           _IOR('O', 7, struct odp_vport)
#define ODP_VPORT_DEL           _IOR('O', 8, struct odp_vport)
#define ODP_VPORT_GET           _IOWR('O', 9, struct odp_vport)
#define ODP_VPORT_SET           _IOR('O', 22, struct odp_vport)
#define ODP_VPORT_DUMP          _IOWR('O', 10, struct odp_vport)

#define ODP_FLOW_NEW            _IOWR('O', 13, struct odp_flow)
#define ODP_FLOW_DEL            _IOWR('O', 14, struct odp_flow)
#define ODP_FLOW_GET            _IOWR('O', 15, struct odp_flow)
#define ODP_FLOW_SET            _IOWR('O', 16, struct odp_flow)
#define ODP_FLOW_DUMP           _IOWR('O', 17, struct odp_flow)
#define ODP_FLOW_FLUSH          _IO('O', 19)

/* Datapaths. */

#define ODP_DATAPATH_FAMILY  "odp_datapath"
#define ODP_DATAPATH_MCGROUP "odp_datapath"

enum odp_datapath_cmd {
	ODP_DP_CMD_UNSPEC,
	ODP_DP_CMD_NEW,
	ODP_DP_CMD_DEL,
	ODP_DP_CMD_GET,
	ODP_DP_CMD_SET
};

/**
 * struct odp_header - header for ODP Generic Netlink messages.
 * @dp_idx: Number of datapath to which the packet belongs.
 *
 * Attributes following the header are specific to a particular ODP Generic
 * Netlink family, but all of the ODP families use this header.
 */
struct odp_header {
	uint32_t dp_idx;
};

/**
 * enum odp_datapath_attr - attributes for %ODP_DP_* commands.
 * @ODP_DP_ATTR_NAME: Name of the network device that serves as the "local
 * port".  This is the name of the network device whose dp_idx is given in the
 * &struct odp_header.  Always present in notifications.  Required in
 * %ODP_DP_NEW requests.  May be used as an alternative to specifying dp_idx on
 * other requests (with a dp_idx of %UINT32_MAX).
 * @ODP_DP_ATTR_STATS: Statistics about packets that have passed through the
 * datapath.  Always present in notifications.
 * @ODP_DP_ATTR_IPV4_FRAGS: One of %ODP_DP_FRAG_*.  Always present in
 * notifications.  May be included in %ODP_DP_NEW or %ODP_DP_SET requests to
 * change the fragment handling policy.
 * @ODP_DP_ATTR_SAMPLING: 32-bit fraction of packets to sample with
 * @ODP_PACKET_CMD_SAMPLE.  A value of 0 samples no packets, a value of
 * %UINT32_MAX samples all packets, and intermediate values sample intermediate
 * fractions of packets.
 * @ODP_DP_ATTR_MCGROUPS: Nested attributes with multicast groups.  Each nested
 * attribute has a %ODP_PACKET_CMD_* type with a 32-bit value giving the
 * Generic Netlink multicast group number used for sending this datapath's
 * messages with that command type up to userspace.
 *
 * These attributes follow the &struct odp_header within the Generic Netlink
 * payload for %ODP_DP_* commands.
 */
enum odp_datapath_attr {
	ODP_DP_ATTR_UNSPEC,
	ODP_DP_ATTR_NAME,       /* name of dp_ifidx netdev */
	ODP_DP_ATTR_STATS,      /* struct odp_stats */
	ODP_DP_ATTR_IPV4_FRAGS,	/* 32-bit enum odp_frag_handling */
	ODP_DP_ATTR_SAMPLING,   /* 32-bit fraction of packets to sample. */
	ODP_DP_ATTR_MCGROUPS,   /* Nested attributes with multicast groups. */
	__ODP_DP_ATTR_MAX
};

#define ODP_DP_ATTR_MAX (__ODP_DP_ATTR_MAX - 1)

/**
 * enum odp_frag_handling - policy for handling received IPv4 fragments.
 * @ODP_DP_FRAG_ZERO: Treat IP fragments as IP protocol 0 and transport ports
 * zero.
 * @ODP_DP_FRAG_DROP: Drop IP fragments.  Do not pass them through the flow
 * table or up to userspace.
 */
enum odp_frag_handling {
	ODP_DP_FRAG_UNSPEC,
	ODP_DP_FRAG_ZERO,	/* Treat IP fragments as transport port 0. */
	ODP_DP_FRAG_DROP	/* Drop IP fragments. */
};

struct odp_stats {
    uint64_t n_frags;           /* Number of dropped IP fragments. */
    uint64_t n_hit;             /* Number of flow table matches. */
    uint64_t n_missed;          /* Number of flow table misses. */
    uint64_t n_lost;            /* Number of misses not sent to userspace. */
};

/* Logical ports. */
#define ODPP_LOCAL      ((uint16_t)0)

#define ODP_PACKET_FAMILY "odp_packet"

enum odp_packet_cmd {
        ODP_PACKET_CMD_UNSPEC,

        /* Kernel-to-user notifications. */
        ODP_PACKET_CMD_MISS,    /* Flow table miss. */
        ODP_PACKET_CMD_ACTION,  /* ODPAT_CONTROLLER action. */
        ODP_PACKET_CMD_SAMPLE,  /* Sampled packet. */

        /* User commands. */
        ODP_PACKET_CMD_EXECUTE  /* Apply actions to a packet. */
};

/**
 * enum odp_packet_attr - attributes for %ODP_PACKET_* commands.
 * @ODP_PACKET_ATTR_PACKET: Present for all notifications.  Contains the entire
 * packet as received, from the start of the Ethernet header onward.  For
 * %ODP_PACKET_CMD_ACTION, %ODP_PACKET_ATTR_PACKET reflects changes made by
 * actions preceding %ODPAT_CONTROLLER, but %ODP_PACKET_ATTR_KEY is the flow
 * key extracted from the packet as originally received.
 * @ODP_PACKET_ATTR_KEY: Present for all notifications.  Contains the flow key
 * extracted from the packet as nested %ODP_KEY_ATTR_* attributes.  This allows
 * userspace to adapt its flow setup strategy by comparing its notion of the
 * flow key against the kernel's.
 * @ODP_PACKET_ATTR_USERDATA: Present for an %ODP_PACKET_CMD_ACTION
 * notification if the %ODPAT_CONTROLLER action's argument was nonzero.
 * @ODP_PACKET_ATTR_SAMPLE_POOL: Present for %ODP_PACKET_CMD_SAMPLE.  Contains
 * the number of packets processed so far that were candidates for sampling.
 * @ODP_PACKET_ATTR_ACTIONS: Present for %ODP_PACKET_CMD_SAMPLE.  Contains a
 * copy of the actions applied to the packet, as nested %ODPAT_* attributes.
 *
 * These attributes follow the &struct odp_header within the Generic Netlink
 * payload for %ODP_PACKET_* commands.
 */
enum odp_packet_attr {
	ODP_PACKET_ATTR_UNSPEC,
	ODP_PACKET_ATTR_PACKET,      /* Packet data. */
	ODP_PACKET_ATTR_KEY,         /* Nested ODP_KEY_ATTR_* attributes. */
	ODP_PACKET_ATTR_USERDATA,    /* 64-bit data from ODPAT_CONTROLLER. */
	ODP_PACKET_ATTR_SAMPLE_POOL, /* # sampling candidate packets so far. */
	ODP_PACKET_ATTR_ACTIONS,     /* Nested ODPAT_* attributes. */
	__ODP_PACKET_ATTR_MAX
};

#define ODP_PACKET_ATTR_MAX (__ODP_PACKET_ATTR_MAX - 1)

enum odp_vport_type {
	ODP_VPORT_TYPE_UNSPEC,
	ODP_VPORT_TYPE_NETDEV,   /* network device */
	ODP_VPORT_TYPE_INTERNAL, /* network device implemented by datapath */
	ODP_VPORT_TYPE_PATCH,    /* virtual tunnel connecting two vports */
	ODP_VPORT_TYPE_GRE,      /* GRE tunnel */
	ODP_VPORT_TYPE_CAPWAP,   /* CAPWAP tunnel */
	__ODP_VPORT_TYPE_MAX
};

#define ODP_VPORT_TYPE_MAX (__ODP_VPORT_TYPE_MAX - 1)

/**
 * struct odp_vport - header with basic information about a virtual port.
 * @dp_idx: Number of datapath to which the vport belongs.
 * @len: Length of this structure plus the Netlink attributes following it.
 * @total_len: Total space available for kernel reply to request.
 *
 * Followed by &struct nlattr attributes, whose types are drawn from
 * %ODP_VPORT_ATTR_*, up to a length of @len bytes including the &struct
 * odp_vport header.
 */
struct odp_vport {
	uint32_t dp_idx;
	uint32_t len;
	uint32_t total_len;
};

enum {
	ODP_VPORT_ATTR_UNSPEC,
	ODP_VPORT_ATTR_PORT_NO,	/* port number within datapath */
	ODP_VPORT_ATTR_TYPE,	/* 32-bit ODP_VPORT_TYPE_* constant. */
	ODP_VPORT_ATTR_NAME,	/* string name, up to IFNAMSIZ bytes long */
	ODP_VPORT_ATTR_STATS,	/* struct rtnl_link_stats64 */
	ODP_VPORT_ATTR_ADDRESS, /* hardware address */
	ODP_VPORT_ATTR_MTU,	/* 32-bit maximum transmission unit */
	ODP_VPORT_ATTR_OPTIONS, /* nested attributes, varies by vport type */
	ODP_VPORT_ATTR_IFINDEX, /* 32-bit ifindex of backing netdev */
	ODP_VPORT_ATTR_IFLINK,	/* 32-bit ifindex on which packets are sent */
	__ODP_VPORT_ATTR_MAX
};

#define ODP_VPORT_ATTR_MAX (__ODP_VPORT_ATTR_MAX - 1)

/* ODP_VPORT_ATTR_OPTIONS attributes for patch vports. */
enum {
	ODP_PATCH_ATTR_UNSPEC,
	ODP_PATCH_ATTR_PEER,	/* name of peer vport, as a string */
	__ODP_PATCH_ATTR_MAX
};

#define ODP_PATCH_ATTR_MAX (__ODP_PATCH_ATTR_MAX - 1)

struct odp_flow_stats {
    uint64_t n_packets;         /* Number of matched packets. */
    uint64_t n_bytes;           /* Number of matched bytes. */
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

/**
 * struct odp_flow - header with basic information about a flow.
 * @dp_idx: Datapath index.
 * @len: Length of this structure plus the Netlink attributes following it.
 * @total_len: Total space available for kernel reply to request.
 *
 * Followed by &struct nlattr attributes, whose types are drawn from
 * %ODP_FLOW_ATTR_*, up to a length of @len bytes including the &struct
 * odp_flow header.
 */
struct odp_flow {
	uint32_t nlmsg_flags;
	uint32_t dp_idx;
	uint32_t len;
	uint32_t total_len;
};

enum odp_flow_type {
	ODP_FLOW_ATTR_UNSPEC,
	ODP_FLOW_ATTR_KEY,       /* Sequence of ODP_KEY_ATTR_* attributes. */
	ODP_FLOW_ATTR_ACTIONS,   /* Sequence of nested ODPAT_* attributes. */
	ODP_FLOW_ATTR_STATS,     /* struct odp_flow_stats. */
	ODP_FLOW_ATTR_TCP_FLAGS, /* 8-bit OR'd TCP flags. */
	ODP_FLOW_ATTR_USED,      /* u64 msecs last used in monotonic time. */
	ODP_FLOW_ATTR_CLEAR,     /* Flag to clear stats, tcp_flags, used. */
	ODP_FLOW_ATTR_STATE,     /* u64 state for ODP_FLOW_DUMP. */
	__ODP_FLOW_ATTR_MAX
};

#define ODP_FLOW_ATTR_MAX (__ODP_FLOW_ATTR_MAX - 1)

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

#endif  /* openvswitch/datapath-protocol.h */
