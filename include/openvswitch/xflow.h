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
 * Be sure to update datapath/xflow-compat.h if you change any of the
 * structures in here. */

#ifndef XFLOW_H
#define XFLOW_H 1

/* The ovs_be<N> types indicate that an object is in big-endian, not
 * native-endian, byte order.  They are otherwise equivalent to uint<N>_t.
 * The Linux kernel already has __be<N> types for this, which take on
 * additional semantics when the "sparse" static checker is used, so we use
 * those types when compiling the kernel. */
#ifdef __KERNEL__
#include <linux/types.h>
#define ovs_be16 __be16
#define ovs_be32 __be32
#define ovs_be64 __be64
#else
#include <stdint.h>
#define ovs_be16 uint16_t
#define ovs_be32 uint32_t
#define ovs_be64 uint64_t
#endif

#define XFLOW_MAX 256             /* Maximum number of datapaths. */

#define XFLOW_DP_CREATE           _IO('O', 0)
#define XFLOW_DP_DESTROY          _IO('O', 1)
#define XFLOW_DP_STATS            _IOW('O', 2, struct xflow_stats)

#define XFLOW_GET_DROP_FRAGS      _IOW('O', 3, int)
#define XFLOW_SET_DROP_FRAGS      _IOR('O', 4, int)

#define XFLOW_GET_LISTEN_MASK     _IOW('O', 5, int)
#define XFLOW_SET_LISTEN_MASK     _IOR('O', 6, int)

#define XFLOW_PORT_ATTACH         _IOR('O', 7, struct xflow_port)
#define XFLOW_PORT_DETACH         _IOR('O', 8, int)
#define XFLOW_PORT_QUERY          _IOWR('O', 9, struct xflow_port)
#define XFLOW_PORT_LIST           _IOWR('O', 10, struct xflow_portvec)

#define XFLOW_PORT_GROUP_SET      _IOR('O', 11, struct xflow_port_group)
#define XFLOW_PORT_GROUP_GET      _IOWR('O', 12, struct xflow_port_group)

#define XFLOW_FLOW_GET            _IOWR('O', 13, struct xflow_flow)
#define XFLOW_FLOW_PUT            _IOWR('O', 14, struct xflow_flow)
#define XFLOW_FLOW_LIST           _IOWR('O', 15, struct xflow_flowvec)
#define XFLOW_FLOW_FLUSH          _IO('O', 16)
#define XFLOW_FLOW_DEL            _IOWR('O', 17, struct xflow_flow)

#define XFLOW_EXECUTE             _IOR('O', 18, struct xflow_execute)

#define XFLOW_SET_SFLOW_PROBABILITY _IOR('O', 19, int)
#define XFLOW_GET_SFLOW_PROBABILITY _IOW('O', 20, int)

#define XFLOW_VPORT_ADD           _IOR('O', 21, struct xflow_vport_add)
#define XFLOW_VPORT_MOD           _IOR('O', 22, struct xflow_vport_mod)
#define XFLOW_VPORT_DEL           _IO('O', 23)
#define XFLOW_VPORT_STATS_GET     _IOWR('O', 24, struct xflow_vport_stats_req)
#define XFLOW_VPORT_ETHER_GET     _IOWR('O', 25, struct xflow_vport_ether)
#define XFLOW_VPORT_ETHER_SET     _IOW('O', 26, struct xflow_vport_ether)
#define XFLOW_VPORT_MTU_GET       _IOWR('O', 27, struct xflow_vport_mtu)
#define XFLOW_VPORT_MTU_SET       _IOW('O', 28, struct xflow_vport_mtu)
#define XFLOW_VPORT_STATS_SET     _IOWR('O', 29, struct xflow_vport_stats_req)

struct xflow_stats {
    /* Flows. */
    uint32_t n_flows;           /* Number of flows in flow table. */
    uint32_t cur_capacity;      /* Current flow table capacity. */
    uint32_t max_capacity;      /* Maximum expansion of flow table capacity. */

    /* Ports. */
    uint32_t n_ports;           /* Current number of ports. */
    uint32_t max_ports;         /* Maximum supported number of ports. */
    uint16_t max_groups;        /* Maximum number of port groups. */
    uint16_t reserved;

    /* Lookups. */
    uint64_t n_frags;           /* Number of dropped IP fragments. */
    uint64_t n_hit;             /* Number of flow table matches. */
    uint64_t n_missed;          /* Number of flow table misses. */
    uint64_t n_lost;            /* Number of misses not sent to userspace. */

    /* Queues. */
    uint16_t max_miss_queue;    /* Max length of XFLOWL_MISS queue. */
    uint16_t max_action_queue;  /* Max length of XFLOWL_ACTION queue. */
    uint16_t max_sflow_queue;   /* Max length of XFLOWL_SFLOW queue. */
};

/* Logical ports. */
#define XFLOWP_LOCAL      ((uint16_t)0)
#define XFLOWP_NONE       ((uint16_t)-1)
#define XFLOWP_NORMAL     ((uint16_t)-2)

/* Listening channels. */
#define _XFLOWL_MISS_NR   0       /* Packet missed in flow table. */
#define XFLOWL_MISS       (1 << _XFLOWL_MISS_NR)
#define _XFLOWL_ACTION_NR 1       /* Packet output to XFLOWP_CONTROLLER. */
#define XFLOWL_ACTION     (1 << _XFLOWL_ACTION_NR)
#define _XFLOWL_SFLOW_NR  2       /* sFlow samples. */
#define XFLOWL_SFLOW      (1 << _XFLOWL_SFLOW_NR)
#define XFLOWL_ALL        (XFLOWL_MISS | XFLOWL_ACTION | XFLOWL_SFLOW)

/**
 * struct xflow_msg - format of messages read from datapath fd.
 * @type: One of the %_XFLOWL_* constants.
 * @length: Total length of message, including this header.
 * @port: Port that received the packet embedded in this message.
 * @reserved: Not currently used.  Should be set to 0.
 * @arg: Argument value whose meaning depends on @type.
 *
 * For @type == %_XFLOWL_MISS_NR, the header is followed by packet data.  The
 * @arg member is the ID (in network byte order) of the tunnel that
 * encapsulated this packet. It is 0 if the packet was not received on a tunnel. *
 * For @type == %_XFLOWL_ACTION_NR, the header is followed by packet data.  The
 * @arg member is copied from the &struct xflow_action_controller that caused
 * the &struct xflow_msg to be composed.
 *
 * For @type == %_XFLOWL_SFLOW_NR, the header is followed by &struct
 * xflow_sflow_sample_header, then by an array of &union xflow_action (the
 * number of which is specified in &struct xflow_sflow_sample_header), then by
 * packet data.
 */
struct xflow_msg {
    uint32_t type;
    uint32_t length;
    uint16_t port;
    uint16_t reserved;
    uint32_t arg;
};

/**
 * struct xflow_sflow_sample_header - header added to sFlow sampled packet.
 * @sample_pool: Number of packets that were candidates for sFlow sampling,
 * regardless of whether they were actually chosen and sent down to userspace.
 * @n_actions: Number of "union xflow_action"s immediately following this
 * header.
 *
 * This header follows &struct xflow_msg when that structure's @type is
 * %_XFLOWL_SFLOW_NR, and it is itself followed by an array of &union
 * xflow_action (the number of which is specified in @n_actions) and then by
 * packet data.
 */
struct xflow_sflow_sample_header {
    uint32_t sample_pool;
    uint32_t n_actions;
};

#define XFLOW_PORT_INTERNAL (1 << 0) /* This port is simulated. */
struct xflow_port {
    char devname[16];           /* IFNAMSIZ */
    uint16_t port;
    uint16_t flags;
    uint32_t reserved2;
};

struct xflow_portvec {
    struct xflow_port *ports;
    uint32_t n_ports;
};

struct xflow_port_group {
    uint16_t *ports;
    uint16_t n_ports;           /* Number of ports. */
    uint16_t group;             /* Group number. */
};

struct xflow_flow_stats {
    uint64_t n_packets;         /* Number of matched packets. */
    uint64_t n_bytes;           /* Number of matched bytes. */
    uint64_t used_sec;          /* Time last used, in system monotonic time. */
    uint32_t used_nsec;
    uint8_t tcp_flags;
    uint8_t ip_tos;
    uint16_t error;             /* Used by XFLOW_FLOW_GET. */
};

/*
 * The datapath protocol adopts the Linux convention for TCI fields: if an
 * 802.1Q header is present then its TCI value is used verbatim except that the
 * CFI bit (0x1000) is always set to 1, and all-bits-zero indicates no 802.1Q
 * header.
 */
#define XFLOW_TCI_PRESENT 0x1000  /* CFI bit */

struct xflow_key {
    ovs_be32 tun_id;            /* Encapsulating tunnel ID. */
    ovs_be32 nw_src;            /* IP source address. */
    ovs_be32 nw_dst;            /* IP destination address. */
    uint16_t in_port;           /* Input switch port. */
    ovs_be16 dl_tci;            /* All zeros if 802.1Q header absent,
                                 * XFLOW_TCI_PRESENT set if present. */
    ovs_be16 dl_type;           /* Ethernet frame type. */
    ovs_be16 tp_src;            /* TCP/UDP source port. */
    ovs_be16 tp_dst;            /* TCP/UDP destination port. */
    uint8_t  dl_src[6];         /* Ethernet source address. */
    uint8_t  dl_dst[6];         /* Ethernet destination address. */
    uint8_t  nw_proto;          /* IP protocol or low 8 bits of ARP opcode. */
    uint8_t  nw_tos;            /* IP ToS (DSCP field, 6 bits). */
};

/* Flags for XFLOW_FLOW. */
#define XFLOWFF_ZERO_TCP_FLAGS (1 << 0) /* Zero the TCP flags. */

struct xflow_flow {
    struct xflow_flow_stats stats;
    struct xflow_key key;
    union xflow_action *actions;
    uint32_t n_actions;
    uint32_t flags;
};

/* Flags for XFLOW_FLOW_PUT. */
#define XFLOWPF_CREATE        (1 << 0) /* Allow creating a new flow. */
#define XFLOWPF_MODIFY        (1 << 1) /* Allow modifying an existing flow. */
#define XFLOWPF_ZERO_STATS    (1 << 2) /* Zero the stats of existing flow. */

/* XFLOW_FLOW_PUT argument. */
struct xflow_flow_put {
    struct xflow_flow flow;
    uint32_t flags;
};

struct xflow_flowvec {
    struct xflow_flow *flows;
    uint32_t n_flows;
};

/* Action types. */
#define XFLOWAT_OUTPUT            0  /* Output to switch port. */
#define XFLOWAT_OUTPUT_GROUP      1  /* Output to all ports in group. */
#define XFLOWAT_CONTROLLER        2  /* Send copy to controller. */
#define XFLOWAT_SET_DL_TCI        3  /* Set the 802.1q VLAN VID and/or PCP. */
#define XFLOWAT_STRIP_VLAN        4  /* Strip the 802.1q header. */
#define XFLOWAT_SET_DL_SRC        5  /* Ethernet source address. */
#define XFLOWAT_SET_DL_DST        6  /* Ethernet destination address. */
#define XFLOWAT_SET_NW_SRC        7  /* IP source address. */
#define XFLOWAT_SET_NW_DST        8  /* IP destination address. */
#define XFLOWAT_SET_NW_TOS        9  /* IP ToS/DSCP field (6 bits). */
#define XFLOWAT_SET_TP_SRC        10 /* TCP/UDP source port. */
#define XFLOWAT_SET_TP_DST        11 /* TCP/UDP destination port. */
#define XFLOWAT_SET_TUNNEL        12 /* Set the encapsulating tunnel ID. */
#define XFLOWAT_SET_PRIORITY      14 /* Set skb->priority. */
#define XFLOWAT_POP_PRIORITY      15 /* Restore original skb->priority. */
#define XFLOWAT_N_ACTIONS         16

struct xflow_action_output {
    uint16_t type;              /* XFLOWAT_OUTPUT. */
    uint16_t port;              /* Output port. */
    uint16_t reserved1;
    uint16_t reserved2;
};

struct xflow_action_output_group {
    uint16_t type;              /* XFLOWAT_OUTPUT_GROUP. */
    uint16_t group;             /* Group number. */
    uint16_t reserved1;
    uint16_t reserved2;
};

struct xflow_action_controller {
    uint16_t type;              /* XFLOWAT_OUTPUT_CONTROLLER. */
    uint16_t reserved;
    uint32_t arg;               /* Copied to struct xflow_msg 'arg' member. */
};

struct xflow_action_tunnel {
    uint16_t type;              /* XFLOWAT_SET_TUNNEL. */
    uint16_t reserved;
    ovs_be32 tun_id;            /* Tunnel ID. */
};

/* Action structure for XFLOWAT_SET_DL_TCI. */
struct xflow_action_dl_tci {
    uint16_t type;              /* XFLOWAT_SET_DL_TCI. */
    ovs_be16 tci;               /* New TCI.  Bits not in mask must be zero. */
    ovs_be16 mask;              /* 0x0fff to set VID, 0xe000 to set PCP,
                                 * or 0xefff to set both. */
    uint16_t reserved;
};

/* Action structure for XFLOWAT_SET_DL_SRC/DST. */
struct xflow_action_dl_addr {
    uint16_t type;              /* XFLOWAT_SET_DL_SRC/DST. */
    uint8_t dl_addr[6];         /* Ethernet address. */
};

/* Action structure for XFLOWAT_SET_NW_SRC/DST. */
struct xflow_action_nw_addr {
    uint16_t type;              /* XFLOWAT_SET_TW_SRC/DST. */
    uint16_t reserved;
    ovs_be32 nw_addr;           /* IP address. */
};

struct xflow_action_nw_tos {
    uint16_t type;              /* XFLOWAT_SET_NW_TOS. */
    uint8_t nw_tos;             /* IP ToS/DSCP field (6 bits). */
    uint8_t reserved1;
    uint16_t reserved2;
    uint16_t reserved3;
};

/* Action structure for XFLOWAT_SET_PRIORITY. */
struct xflow_action_priority {
    uint16_t type;              /* XFLOWAT_SET_PRIORITY. */
    uint16_t reserved;
    uint32_t priority;          /* skb->priority value. */
};

/* Action structure for XFLOWAT_SET_TP_SRC/DST. */
struct xflow_action_tp_port {
    uint16_t type;              /* XFLOWAT_SET_TP_SRC/DST. */
    ovs_be16 tp_port;           /* TCP/UDP port. */
    uint16_t reserved1;
    uint16_t reserved2;
};

union xflow_action {
    uint16_t type;
    struct xflow_action_output output;
    struct xflow_action_output_group output_group;
    struct xflow_action_controller controller;
    struct xflow_action_tunnel tunnel;
    struct xflow_action_dl_tci dl_tci;
    struct xflow_action_dl_addr dl_addr;
    struct xflow_action_nw_addr nw_addr;
    struct xflow_action_nw_tos nw_tos;
    struct xflow_action_tp_port tp_port;
    struct xflow_action_priority priority;
};

struct xflow_execute {
    uint16_t in_port;
    uint16_t reserved1;
    uint32_t reserved2;

    union xflow_action *actions;
    uint32_t n_actions;

    const void *data;
    uint32_t length;
};

#define VPORT_TYPE_SIZE     16
struct xflow_vport_add {
    char port_type[VPORT_TYPE_SIZE];
    char devname[16];           /* IFNAMSIZ */
    void *config;
};

struct xflow_vport_mod {
    char devname[16];           /* IFNAMSIZ */
    void *config;
};

struct xflow_vport_stats {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
    uint64_t rx_errors;
    uint64_t tx_errors;
    uint64_t rx_frame_err;
    uint64_t rx_over_err;
    uint64_t rx_crc_err;
    uint64_t collisions;
};

struct xflow_vport_stats_req {
    char devname[16];           /* IFNAMSIZ */
    struct xflow_vport_stats stats;
};

struct xflow_vport_ether {
    char devname[16];           /* IFNAMSIZ */
    unsigned char ether_addr[6];
};

struct xflow_vport_mtu {
    char devname[16];           /* IFNAMSIZ */
    uint16_t mtu;
};

/* Values below this cutoff are 802.3 packets and the two bytes
 * following MAC addresses are used as a frame length.  Otherwise, the
 * two bytes are used as the Ethernet type.
 */
#define XFLOW_DL_TYPE_ETH2_CUTOFF   0x0600

/* Value of dl_type to indicate that the frame does not include an
 * Ethernet type.
 */
#define XFLOW_DL_TYPE_NOT_ETH_TYPE  0x05ff

#endif /* openvswitch/xflow.h */
