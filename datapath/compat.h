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
#include <net/ip.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>

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

#ifdef OVS_FRAGMENT_BACKPORT
#ifdef HAVE_NF_IPV6_OPS_FRAGMENT
static inline int __init ip6_output_init(void) { return 0; }
static inline void ip6_output_exit(void) { }
#else
int __init ip6_output_init(void);
void ip6_output_exit(void);
#endif

static inline int __init compat_init(void)
{
	int err;

	err = ipfrag_init();
	if (err)
		return err;

	err = nf_ct_frag6_init();
	if (err)
		goto error_ipfrag_exit;

	err = ip6_output_init();
	if (err)
		goto error_frag6_exit;

	return 0;

error_frag6_exit:
	nf_ct_frag6_cleanup();
error_ipfrag_exit:
	rpl_ipfrag_fini();
	return err;
}
static inline void compat_exit(void)
{
	ip6_output_exit();
	nf_ct_frag6_cleanup();
	rpl_ipfrag_fini();
}
#else
static inline int __init compat_init(void) { return 0; }
static inline void compat_exit(void) { }
#endif

#endif /* compat.h */
