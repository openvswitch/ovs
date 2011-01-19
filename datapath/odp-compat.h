/*
 * Copyright (c) 2010, 2011 Nicira Networks.
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

#define ODP_FLOW_GET32		_IOWR('O', 13, struct compat_odp_flow)
#define ODP_FLOW_PUT32		_IOWR('O', 14, struct compat_odp_flow)
#define ODP_FLOW_DUMP32		_IOWR('O', 15, struct compat_odp_flow_dump)
#define ODP_FLOW_DEL32		_IOWR('O', 17, struct compat_odp_flow)
#define ODP_EXECUTE32		_IOR('O', 18, struct compat_odp_execute)
#define ODP_FLOW_DEL32		_IOWR('O', 17, struct compat_odp_flow)

struct compat_odp_flow {
	uint32_t dp_idx;
	struct odp_flow_stats stats;
	compat_uptr_t key;
	u32 key_len;
	compat_uptr_t actions;
	u32 actions_len;
};

struct compat_odp_flow_put {
	struct compat_odp_flow flow;
	u32 flags;
};

struct compat_odp_flow_dump {
	uint32_t dp_idx;
	compat_uptr_t flow;
	uint32_t state[2];
};

struct compat_odp_execute {
	uint32_t dp_idx;

	compat_uptr_t actions;
	u32 actions_len;

	compat_uptr_t data;
	u32 length;
};
#endif	/* CONFIG_COMPAT */

#endif	/* odp-compat.h */
