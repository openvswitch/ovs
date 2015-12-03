/*
 * Copyright (c) 2007-2015 Nicira, Inc.
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

#ifndef COMPAT_H
#define COMPAT_H 1

#include <linux/in.h>
#include <linux/in_route.h>
#include <linux/netlink.h>
#include <net/route.h>
#include <net/xfrm.h>

#ifdef HAVE_GENL_MULTICAST_GROUP_WITH_ID
#define GROUP_ID(grp)	((grp)->id)
#else
#define GROUP_ID(grp)	0
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
#define rt_dst(rt) (rt->dst)
#else
#define rt_dst(rt) (rt->u.dst)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
#define inet_sport(sk)	(inet_sk(sk)->sport)
#else
#define inet_sport(sk)	(inet_sk(sk)->inet_sport)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
static inline bool skb_encapsulation(struct sk_buff *skb)
{
	return skb->encapsulation;
}
#else
#define skb_encapsulation(skb) false
#endif

#endif /* compat.h */
