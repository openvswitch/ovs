/*
 * Copyright (c) 2007-2011 Nicira Networks.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
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

