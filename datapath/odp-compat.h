/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef ODP_COMPAT_H
#define ODP_COMPAT_H 1

/* 32-bit ioctl compatibility definitions for datapath protocol. */

#ifdef CONFIG_COMPAT
#include "openvswitch/datapath-protocol.h"
#include <linux/compat.h>

#define ODP_PORT_LIST32		_IOWR('O', 10, struct compat_odp_portvec)
#define ODP_PORT_GROUP_SET32	_IOR('O', 11, struct compat_odp_port_group)
#define ODP_PORT_GROUP_GET32	_IOWR('O', 12, struct compat_odp_port_group)
#define ODP_FLOW_GET32		_IOWR('O', 13, struct compat_odp_flow)
#define ODP_FLOW_PUT32		_IOWR('O', 14, struct compat_odp_flow)
#define ODP_FLOW_LIST32		_IOWR('O', 15, struct compat_odp_flowvec)
#define ODP_FLOW_DEL32		_IOWR('O', 17, struct compat_odp_flow)
#define ODP_EXECUTE32		_IOR('O', 18, struct compat_odp_execute)
#define ODP_FLOW_DEL32		_IOWR('O', 17, struct compat_odp_flow)
#define ODP_VPORT_ADD32		_IOR('O', 21, struct compat_odp_vport_add)
#define ODP_VPORT_MOD32		_IOR('O', 22, struct compat_odp_vport_mod)

struct compat_odp_portvec {
	compat_uptr_t ports;
	u32 n_ports;
};

struct compat_odp_port_group {
	compat_uptr_t ports;
	u16 n_ports;		/* Number of ports. */
	u16 group;		/* Group number. */
};

struct compat_odp_flow {
	struct odp_flow_stats stats;
	struct odp_flow_key key;
	compat_uptr_t actions;
	u32 n_actions;
	u32 flags;
};

struct compat_odp_flow_put {
	struct compat_odp_flow flow;
	u32 flags;
};

struct compat_odp_flowvec {
	compat_uptr_t flows;
	u32 n_flows;
};

struct compat_odp_execute {
	u16 in_port;
	u16 reserved1;
	u32 reserved2;

	compat_uptr_t actions;
	u32 n_actions;

	compat_uptr_t data;
	u32 length;
};

struct compat_odp_vport_add {
	char port_type[VPORT_TYPE_SIZE];
	char devname[16];	     /* IFNAMSIZ */
	compat_uptr_t config;
};

struct compat_odp_vport_mod {
	char devname[16];	     /* IFNAMSIZ */
	compat_uptr_t config;
};
#endif	/* CONFIG_COMPAT */

#endif	/* odp-compat.h */
