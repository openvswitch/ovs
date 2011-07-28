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

#ifndef OPENVSWITCH_DATAPATH_PROTOCOL_H
#define OPENVSWITCH_DATAPATH_PROTOCOL_H 1

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

#include <linux/if_link.h>
#include <linux/netlink.h>

/* datapaths. */

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
 * @dp_ifindex: ifindex of local port for datapath (0 to make a request not
 * specific to a datapath).
 *
 * Attributes following the header are specific to a particular ODP Generic
 * Netlink family, but all of the ODP families use this header.
 */
struct odp_header {
	int dp_ifindex;
};

/**
 * enum odp_datapath_attr - attributes for %ODP_DP_* commands.
 * @ODP_DP_ATTR_NAME: Name of the network device that serves as the "local
 * port".  This is the name of the network device whose dp_ifindex is given in
 * the &struct odp_header.  Always present in notifications.  Required in
 * %ODP_DP_NEW requests.  May be used as an alternative to specifying
 * dp_ifindex in other requests (with a dp_ifindex of 0).
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
	ODP_DP_ATTR_NAME,       /* name of dp_ifindex netdev */
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
        ODP_PACKET_CMD_ACTION,  /* ODP_ACTION_ATTR_USERSPACE action. */
        ODP_PACKET_CMD_SAMPLE,  /* Sampled packet. */

        /* User commands. */
        ODP_PACKET_CMD_EXECUTE  /* Apply actions to a packet. */
};

/**
 * enum odp_packet_attr - attributes for %ODP_PACKET_* commands.
 * @ODP_PACKET_ATTR_PACKET: Present for all notifications.  Contains the entire
 * packet as received, from the start of the Ethernet header onward.  For
 * %ODP_PACKET_CMD_ACTION, %ODP_PACKET_ATTR_PACKET reflects changes made by
 * actions preceding %ODP_ACTION_ATTR_USERSPACE, but %ODP_PACKET_ATTR_KEY is
 * the flow key extracted from the packet as originally received.
 * @ODP_PACKET_ATTR_KEY: Present for all notifications.  Contains the flow key
 * extracted from the packet as nested %ODP_KEY_ATTR_* attributes.  This allows
 * userspace to adapt its flow setup strategy by comparing its notion of the
 * flow key against the kernel's.
 * @ODP_PACKET_ATTR_USERDATA: Present for an %ODP_PACKET_CMD_ACTION
 * notification if the %ODP_ACTION_ATTR_USERSPACE, action's argument was
 * nonzero.
 * @ODP_PACKET_ATTR_SAMPLE_POOL: Present for %ODP_PACKET_CMD_SAMPLE.  Contains
 * the number of packets processed so far that were candidates for sampling.
 * @ODP_PACKET_ATTR_ACTIONS: Present for %ODP_PACKET_CMD_SAMPLE.  Contains a
 * copy of the actions applied to the packet, as nested %ODP_ACTION_ATTR_*
 * attributes.
 *
 * These attributes follow the &struct odp_header within the Generic Netlink
 * payload for %ODP_PACKET_* commands.
 */
enum odp_packet_attr {
	ODP_PACKET_ATTR_UNSPEC,
	ODP_PACKET_ATTR_PACKET,      /* Packet data. */
	ODP_PACKET_ATTR_KEY,         /* Nested ODP_KEY_ATTR_* attributes. */
	ODP_PACKET_ATTR_USERDATA,    /* u64 ODP_ACTION_ATTR_USERSPACE arg. */
	ODP_PACKET_ATTR_SAMPLE_POOL, /* # sampling candidate packets so far. */
	ODP_PACKET_ATTR_ACTIONS,     /* Nested ODP_ACTION_ATTR_* attributes. */
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

#define ODP_VPORT_FAMILY  "odp_vport"
#define ODP_VPORT_MCGROUP "odp_vport"

enum odp_vport_cmd {
	ODP_VPORT_CMD_UNSPEC,
	ODP_VPORT_CMD_NEW,
	ODP_VPORT_CMD_DEL,
	ODP_VPORT_CMD_GET,
	ODP_VPORT_CMD_SET
};

/**
 * enum odp_vport_attr - attributes for %ODP_VPORT_* commands.
 * @ODP_VPORT_ATTR_PORT_NO: 32-bit port number within datapath.
 * @ODP_VPORT_ATTR_TYPE: 32-bit %ODP_VPORT_TYPE_* constant describing the type
 * of vport.
 * @ODP_VPORT_ATTR_NAME: Name of vport.  For a vport based on a network device
 * this is the name of the network device.  Maximum length %IFNAMSIZ-1 bytes
 * plus a null terminator.
 * @ODP_VPORT_ATTR_STATS: A &struct rtnl_link_stats64 giving statistics for
 * packets sent or received through the vport.
 * @ODP_VPORT_ATTR_ADDRESS: A 6-byte Ethernet address for the vport.
 * @ODP_VPORT_ATTR_MTU: MTU for the vport.  Omitted if the vport does not have
 * an MTU as, e.g., some tunnels do not.
 * @ODP_VPORT_ATTR_IFINDEX: ifindex of the underlying network device, if any.
 * @ODP_VPORT_ATTR_IFLINK: ifindex of the device on which packets are sent (for
 * tunnels), if any.
 *
 * These attributes follow the &struct odp_header within the Generic Netlink
 * payload for %ODP_VPORT_* commands.
 *
 * All attributes applicable to a given port are present in notifications.
 * This means that, for example, a vport that has no corresponding network
 * device would omit %ODP_VPORT_ATTR_IFINDEX.
 *
 * For %ODP_VPORT_CMD_NEW requests, the %ODP_VPORT_ATTR_TYPE and
 * %ODP_VPORT_ATTR_NAME attributes are required.  %ODP_VPORT_ATTR_PORT_NO is
 * optional; if not specified a free port number is automatically selected.
 * Whether %ODP_VPORT_ATTR_OPTIONS is required or optional depends on the type
 * of vport.  %ODP_VPORT_ATTR_STATS, %ODP_VPORT_ATTR_ADDRESS, and
 * %ODP_VPORT_ATTR_MTU are optional, and other attributes are ignored.
 *
 * For other requests, if %ODP_VPORT_ATTR_NAME is specified then it is used to
 * look up the vport to operate on; otherwise dp_idx from the &struct
 * odp_header plus %ODP_VPORT_ATTR_PORT_NO determine the vport.
 */
enum odp_vport_attr {
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

/* Flows. */

#define ODP_FLOW_FAMILY  "odp_flow"
#define ODP_FLOW_MCGROUP "odp_flow"

enum odp_flow_cmd {
	ODP_FLOW_CMD_UNSPEC,
	ODP_FLOW_CMD_NEW,
	ODP_FLOW_CMD_DEL,
	ODP_FLOW_CMD_GET,
	ODP_FLOW_CMD_SET
};

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
	ODP_KEY_ATTR_IPV6,      /* struct odp_key_ipv6 */
	ODP_KEY_ATTR_TCP,       /* struct odp_key_tcp */
	ODP_KEY_ATTR_UDP,       /* struct odp_key_udp */
	ODP_KEY_ATTR_ICMP,      /* struct odp_key_icmp */
	ODP_KEY_ATTR_ICMPV6,    /* struct odp_key_icmpv6 */
	ODP_KEY_ATTR_ARP,       /* struct odp_key_arp */
	ODP_KEY_ATTR_ND,        /* struct odp_key_nd */
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

struct odp_key_ipv6 {
	ovs_be32 ipv6_src[4];
	ovs_be32 ipv6_dst[4];
	uint8_t  ipv6_proto;
	uint8_t  ipv6_tos;
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

struct odp_key_icmpv6 {
	uint8_t icmpv6_type;
	uint8_t icmpv6_code;
};

struct odp_key_arp {
	ovs_be32 arp_sip;
	ovs_be32 arp_tip;
	ovs_be16 arp_op;
	uint8_t  arp_sha[6];
	uint8_t  arp_tha[6];
};

struct odp_key_nd {
	uint32_t nd_target[4];
	uint8_t  nd_sll[6];
	uint8_t  nd_tll[6];
};

/**
 * enum odp_flow_attr - attributes for %ODP_FLOW_* commands.
 * @ODP_FLOW_ATTR_KEY: Nested %ODP_KEY_ATTR_* attributes specifying the flow
 * key.  Always present in notifications.  Required for all requests (except
 * dumps).
 * @ODP_FLOW_ATTR_ACTIONS: Nested %ODPAT_* attributes specifying the actions to
 * take for packets that match the key.  Always present in notifications.
 * Required for %ODP_FLOW_CMD_NEW requests, optional on %ODP_FLOW_CMD_SET
 * request to change the existing actions, ignored for other requests.
 * @ODP_FLOW_ATTR_STATS: &struct odp_flow_stats giving statistics for this
 * flow.  Present in notifications if the stats would be nonzero.  Ignored in
 * requests.
 * @ODP_FLOW_ATTR_TCP_FLAGS: An 8-bit value giving the OR'd value of all of the
 * TCP flags seen on packets in this flow.  Only present in notifications for
 * TCP flows, and only if it would be nonzero.  Ignored in requests.
 * @ODP_FLOW_ATTR_USED: A 64-bit integer giving the time, in milliseconds on
 * the system monotonic clock, at which a packet was last processed for this
 * flow.  Only present in notifications if a packet has been processed for this
 * flow.  Ignored in requests.
 * @ODP_FLOW_ATTR_CLEAR: If present in a %ODP_FLOW_CMD_SET request, clears the
 * last-used time, accumulated TCP flags, and statistics for this flow.
 * Otherwise ignored in requests.  Never present in notifications.
 *
 * These attributes follow the &struct odp_header within the Generic Netlink
 * payload for %ODP_FLOW_* commands.
 */
enum odp_flow_attr {
	ODP_FLOW_ATTR_UNSPEC,
	ODP_FLOW_ATTR_KEY,       /* Sequence of ODP_KEY_ATTR_* attributes. */
	ODP_FLOW_ATTR_ACTIONS,   /* Nested ODP_ACTION_ATTR_* attributes. */
	ODP_FLOW_ATTR_STATS,     /* struct odp_flow_stats. */
	ODP_FLOW_ATTR_TCP_FLAGS, /* 8-bit OR'd TCP flags. */
	ODP_FLOW_ATTR_USED,      /* u64 msecs last used in monotonic time. */
	ODP_FLOW_ATTR_CLEAR,     /* Flag to clear stats, tcp_flags, used. */
	__ODP_FLOW_ATTR_MAX
};

#define ODP_FLOW_ATTR_MAX (__ODP_FLOW_ATTR_MAX - 1)

/* Action types. */
enum odp_action_type {
	ODP_ACTION_ATTR_UNSPEC,
	ODP_ACTION_ATTR_OUTPUT,	      /* Output to switch port. */
	ODP_ACTION_ATTR_USERSPACE,    /* Send copy to userspace. */
	ODP_ACTION_ATTR_SET_DL_TCI,   /* Set the 802.1q TCI value. */
	ODP_ACTION_ATTR_STRIP_VLAN,   /* Strip the 802.1q header. */
	ODP_ACTION_ATTR_SET_DL_SRC,   /* Ethernet source address. */
	ODP_ACTION_ATTR_SET_DL_DST,   /* Ethernet destination address. */
	ODP_ACTION_ATTR_SET_NW_SRC,   /* IPv4 source address. */
	ODP_ACTION_ATTR_SET_NW_DST,   /* IPv4 destination address. */
	ODP_ACTION_ATTR_SET_NW_TOS,   /* IP ToS/DSCP field (6 bits). */
	ODP_ACTION_ATTR_SET_TP_SRC,   /* TCP/UDP source port. */
	ODP_ACTION_ATTR_SET_TP_DST,   /* TCP/UDP destination port. */
	ODP_ACTION_ATTR_SET_TUNNEL,   /* Set the encapsulating tunnel ID. */
	ODP_ACTION_ATTR_SET_PRIORITY, /* Set skb->priority. */
	ODP_ACTION_ATTR_POP_PRIORITY, /* Restore original skb->priority. */
	__ODP_ACTION_ATTR_MAX
};

#define ODP_ACTION_ATTR_MAX (__ODP_ACTION_ATTR_MAX - 1)

#endif  /* openvswitch/datapath-protocol.h */
