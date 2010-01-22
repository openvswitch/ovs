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

/* Protocol between userspace and kernel datapath. */

#ifndef OPENVSWITCH_DATAPATH_PROTOCOL_H
#define OPENVSWITCH_DATAPATH_PROTOCOL_H 1

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#endif
#include <linux/if_ether.h>

#define ODP_MAX 256             /* Maximum number of datapaths. */

#define ODP_DP_CREATE           _IO('O', 0)
#define ODP_DP_DESTROY          _IO('O', 1)
#define ODP_DP_STATS            _IOW('O', 2, struct odp_stats)

#define ODP_GET_DROP_FRAGS      _IOW('O', 3, int)
#define ODP_SET_DROP_FRAGS      _IOR('O', 4, int)

#define ODP_GET_LISTEN_MASK     _IOW('O', 5, int)
#define ODP_SET_LISTEN_MASK     _IOR('O', 6, int)

#define ODP_PORT_ADD            _IOR('O', 7, struct odp_port)
#define ODP_PORT_DEL            _IOR('O', 8, int)
#define ODP_PORT_QUERY          _IOWR('O', 9, struct odp_port)
#define ODP_PORT_LIST           _IOWR('O', 10, struct odp_portvec)

#define ODP_PORT_GROUP_SET      _IOR('O', 11, struct odp_port_group)
#define ODP_PORT_GROUP_GET      _IOWR('O', 12, struct odp_port_group)

#define ODP_FLOW_GET            _IOWR('O', 13, struct odp_flow)
#define ODP_FLOW_PUT            _IOWR('O', 14, struct odp_flow)
#define ODP_FLOW_LIST           _IOWR('O', 15, struct odp_flowvec)
#define ODP_FLOW_FLUSH          _IO('O', 16)
#define ODP_FLOW_DEL            _IOWR('O', 17, struct odp_flow)

#define ODP_EXECUTE             _IOR('O', 18, struct odp_execute)

struct odp_stats {
    /* Flows. */
    __u32 n_flows;              /* Number of flows in flow table. */
    __u32 cur_capacity;         /* Current flow table capacity. */
    __u32 max_capacity;         /* Maximum expansion of flow table capacity. */

    /* Ports. */
    __u32 n_ports;              /* Current number of ports. */
    __u32 max_ports;            /* Maximum supported number of ports. */
    __u16 max_groups;           /* Maximum number of port groups. */
    __u16 reserved;

    /* Lookups. */
    __u64 n_frags;               /* Number of dropped IP fragments. */
    __u64 n_hit;                 /* Number of flow table matches. */
    __u64 n_missed;              /* Number of flow table misses. */
    __u64 n_lost;                /* Number of misses not sent to userspace. */

    /* Queues. */
    __u16 max_miss_queue;       /* Max length of ODPL_MISS queue. */
    __u16 max_action_queue;     /* Max length of ODPL_ACTION queue. */
};

/* Logical ports. */
#define ODPP_LOCAL      ((__u16)0)
#define ODPP_NONE       ((__u16)-1)

/* Listening channels. */
#define _ODPL_MISS_NR   0       /* Packet missed in flow table. */
#define ODPL_MISS       (1 << _ODPL_MISS_NR)
#define _ODPL_ACTION_NR 1       /* Packet output to ODPP_CONTROLLER. */
#define ODPL_ACTION     (1 << _ODPL_ACTION_NR)
#define ODPL_ALL        (ODPL_MISS | ODPL_ACTION)

/* Format of messages read from datapath fd. */
struct odp_msg {
    __u32 type;                 /* _ODPL_MISS_NR or _ODPL_ACTION_NR. */
    __u32 length;               /* Message length, including header. */
    __u16 port;                 /* Port on which frame was received. */
    __u16 reserved;
    __u32 arg;                  /* Argument value specified in action. */
    /* Followed by packet data. */
};

#define ODP_PORT_INTERNAL (1 << 0) /* This port is simulated. */
struct odp_port {
    char devname[16];           /* IFNAMSIZ */
    __u16 port;
    __u16 flags;
    __u32 reserved2;
};

struct odp_portvec {
    struct odp_port *ports;
    int n_ports;
};

struct odp_port_group {
    __u16 *ports;
    __u16 n_ports;                /* Number of ports. */
    __u16 group;                  /* Group number. */
};

struct odp_flow_stats {
    __u64 n_packets;            /* Number of matched packets. */
    __u64 n_bytes;              /* Number of matched bytes. */
    __u64 used_sec;             /* Time last used. */
    __u32 used_nsec;
    __u8 tcp_flags;
    __u8 ip_tos;
    __u16 error;                /* Used by ODP_FLOW_GET. */
};

struct odp_flow_key {
    __be32 nw_src;               /* IP source address. */
    __be32 nw_dst;               /* IP destination address. */
    __u16  in_port;              /* Input switch port. */
    __be16 dl_vlan;              /* Input VLAN. */
    __be16 dl_type;              /* Ethernet frame type. */
    __be16 tp_src;               /* TCP/UDP source port. */
    __be16 tp_dst;               /* TCP/UDP destination port. */
    __u8   dl_src[ETH_ALEN];     /* Ethernet source address. */
    __u8   dl_dst[ETH_ALEN];     /* Ethernet destination address. */
    __u8   nw_proto;             /* IP protocol or lower 8 bits of 
                                    ARP opcode. */
    __u8   dl_vlan_pcp;          /* Input VLAN priority. */
    __u8   nw_tos;               /* IP ToS (DSCP field, 6 bits). */
    __u8   reserved[3];          /* Align to 32-bits...must be zeroed. */
};

/* Flags for ODP_FLOW. */
#define ODPFF_ZERO_TCP_FLAGS (1 << 0) /* Zero the TCP flags. */

struct odp_flow {
    struct odp_flow_stats stats;
    struct odp_flow_key key;
    union odp_action *actions;
    __u32 n_actions;
    __u32 flags;
};

/* Flags for ODP_FLOW_PUT. */
#define ODPPF_CREATE        (1 << 0) /* Allow creating a new flow. */
#define ODPPF_MODIFY        (1 << 1) /* Allow modifying an existing flow. */
#define ODPPF_ZERO_STATS    (1 << 2) /* Zero the stats of an existing flow. */

/* ODP_FLOW_PUT argument. */
struct odp_flow_put {
    struct odp_flow flow;
    __u32 flags;
};

struct odp_flowvec {
    struct odp_flow *flows;
    int n_flows;
};

/* The VLAN id is 12 bits, so we can use the entire 16 bits to indicate
 * special conditions.  All ones is used to match that no VLAN id was
 * set. */
#define ODP_VLAN_NONE      0xffff

/* Action types. */
#define ODPAT_OUTPUT            0    /* Output to switch port. */
#define ODPAT_OUTPUT_GROUP      1    /* Output to all ports in group. */
#define ODPAT_CONTROLLER        2    /* Send copy to controller. */
#define ODPAT_SET_VLAN_VID      3    /* Set the 802.1q VLAN id. */
#define ODPAT_SET_VLAN_PCP      4    /* Set the 802.1q priority. */
#define ODPAT_STRIP_VLAN        5    /* Strip the 802.1q header. */
#define ODPAT_SET_DL_SRC        6    /* Ethernet source address. */
#define ODPAT_SET_DL_DST        7    /* Ethernet destination address. */
#define ODPAT_SET_NW_SRC        8    /* IP source address. */
#define ODPAT_SET_NW_DST        9    /* IP destination address. */
#define ODPAT_SET_NW_TOS        10   /* IP ToS/DSCP field (6 bits). */
#define ODPAT_SET_TP_SRC        11   /* TCP/UDP source port. */
#define ODPAT_SET_TP_DST        12   /* TCP/UDP destination port. */
#define ODPAT_N_ACTIONS         13

struct odp_action_output {
    __u16 type;                  /* ODPAT_OUTPUT. */
    __u16 port;                  /* Output port. */
    __u16 reserved1;
    __u16 reserved2;
};

struct odp_action_output_group {
    __u16 type;                 /* ODPAT_OUTPUT_GROUP. */
    __u16 group;                /* Group number. */
    __u16 reserved1;
    __u16 reserved2;
};

struct odp_action_controller {
    __u16 type;                 /* ODPAT_OUTPUT_CONTROLLER. */
    __u16 reserved;
    __u32 arg;                  /* Copied to struct odp_msg 'arg' member. */
};

/* Action structure for ODPAT_SET_VLAN_VID. */
struct odp_action_vlan_vid {
    __u16 type;                  /* ODPAT_SET_VLAN_VID. */
    __be16 vlan_vid;             /* VLAN id. */
    __u16 reserved1;
    __u16 reserved2;
};

/* Action structure for ODPAT_SET_VLAN_PCP. */
struct odp_action_vlan_pcp {
    __u16 type;                  /* ODPAT_SET_VLAN_PCP. */
    __u8 vlan_pcp;               /* VLAN priority. */
    __u8 reserved1;
    __u16 reserved2;
    __u16 reserved3;
};

/* Action structure for ODPAT_SET_DL_SRC/DST. */
struct odp_action_dl_addr {
    __u16 type;                  /* ODPAT_SET_DL_SRC/DST. */
    __u8 dl_addr[ETH_ALEN];      /* Ethernet address. */
};

/* Action structure for ODPAT_SET_NW_SRC/DST. */
struct odp_action_nw_addr {
    __u16 type;                 /* ODPAT_SET_TW_SRC/DST. */
    __u16 reserved;
    __be32 nw_addr;             /* IP address. */
};

struct odp_action_nw_tos {
    __u16 type;                  /* ODPAT_SET_NW_TOS. */
    __u8 nw_tos;                 /* IP ToS/DSCP field (6 bits). */
    __u8 reserved1;
    __u16 reserved2;
    __u16 reserved3;
};

/* Action structure for ODPAT_SET_TP_SRC/DST. */
struct odp_action_tp_port {
    __u16 type;                  /* ODPAT_SET_TP_SRC/DST. */
    __be16 tp_port;              /* TCP/UDP port. */
    __u16 reserved1;
    __u16 reserved2;
};

union odp_action {
    __u16 type;
    struct odp_action_output output;
    struct odp_action_output_group output_group;
    struct odp_action_controller controller;
    struct odp_action_vlan_vid vlan_vid;
    struct odp_action_vlan_pcp vlan_pcp;
    struct odp_action_dl_addr dl_addr;
    struct odp_action_nw_addr nw_addr;
    struct odp_action_nw_tos nw_tos;
    struct odp_action_tp_port tp_port;
};

struct odp_execute {
    __u16 in_port;
    __u16 reserved1;
    __u32 reserved2;

    union odp_action *actions;
    __u32 n_actions;

    const void *data;
    __u32 length;
};

/* Values below this cutoff are 802.3 packets and the two bytes
 * following MAC addresses are used as a frame length.  Otherwise, the
 * two bytes are used as the Ethernet type.
 */
#define ODP_DL_TYPE_ETH2_CUTOFF   0x0600

/* Value of dl_type to indicate that the frame does not include an
 * Ethernet type.
 */
#define ODP_DL_TYPE_NOT_ETH_TYPE  0x05ff

/* The VLAN id is 12-bits, so we can use the entire 16 bits to indicate
 * special conditions.  All ones indicates that no VLAN id was set.
 */
#define ODP_VLAN_NONE      0xffff

#endif /* openvswitch/datapath-protocol.h */
