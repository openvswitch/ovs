/*
 * Copyright (c) 2009, 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef DP_SYSFS_H
#define DP_SYSFS_H 1

struct datapath;
struct vport;

/* dp_sysfs_dp.c */
int dp_sysfs_add_dp(struct datapath *dp);
int dp_sysfs_del_dp(struct datapath *dp);

/* dp_sysfs_if.c */
int dp_sysfs_add_if(struct vport *p);
int dp_sysfs_del_if(struct vport *p);

#ifdef CONFIG_SYSFS
extern struct sysfs_ops brport_sysfs_ops;
#endif

#endif /* dp_sysfs.h */

