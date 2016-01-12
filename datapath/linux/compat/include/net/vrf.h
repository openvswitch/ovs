/*
 * include/net/net_vrf.h - adds vrf dev structure definitions
 * Copyright (c) 2015 Cumulus Networks
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __LINUX_NET_VRF_WRAPPER_H
#define __LINUX_NET_VRF_WRAPPER_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
#include_next <net/vrf.h>
#else

static inline int vrf_master_ifindex_rcu(const struct net_device *dev)
{
	return 0;
}
#endif

#endif /* __LINUX_NET_VRF_WRAPPER_H */
