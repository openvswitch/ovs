/*
 * Copyright (c) 2009 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef DP_SYSFS_H
#define DP_SYSFS_H 1

struct datapath;
struct net_bridge_port;

/* dp_sysfs_dp.c */
int dp_sysfs_add_dp(struct datapath *dp);
int dp_sysfs_del_dp(struct datapath *dp);

/* dp_sysfs_if.c */
int dp_sysfs_add_if(struct net_bridge_port *p);
int dp_sysfs_del_if(struct net_bridge_port *p);

#include <linux/version.h>
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,18)
#define SUPPORT_SYSFS 1
#else
/* We only support sysfs on Linux 2.6.18 because that's the only place we
 * really need it (on Xen, for brcompat) and it's a big pain to try to support
 * multiple versions. */
#endif

#ifdef SUPPORT_SYSFS
extern struct sysfs_ops brport_sysfs_ops;
#endif

#endif /* dp_sysfs.h */

