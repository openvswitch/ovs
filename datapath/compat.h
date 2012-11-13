/*
 * Copyright (c) 2007-2012 Nicira, Inc.
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

#include <linux/netlink.h>

#ifndef HAVE_NLA_NUL_STRING
static inline int CHECK_NUL_STRING(struct nlattr *attr, int maxlen)
{
	char *s;
	int len;
	if (!attr)
		return 0;

	len = nla_len(attr);
	if (len >= maxlen)
		return -EINVAL;

	s = nla_data(attr);
	if (s[len - 1] != '\0')
		return -EINVAL;

	return 0;
}
#else
static inline int CHECK_NUL_STRING(struct nlattr *attr, int maxlen)
{
	return 0;
}
#endif  /* !HAVE_NLA_NUL_STRING */

static inline void skb_clear_rxhash(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	skb->rxhash = 0;
#endif
}

/*
 * Enforces, mutual exclusion with the Linux bridge module, by declaring and
 * exporting br_should_route_hook.  Because the bridge module also exports the
 * same symbol, the module loader will refuse to load both modules at the same
 * time (e.g. "bridge: exports duplicate symbol br_should_route_hook (owned by
 * openvswitch)").
 *
 * Before Linux 2.6.36, Open vSwitch cannot safely coexist with the Linux
 * bridge module, so openvswitch uses this macro in those versions.  In
 * Linux 2.6.36 and later, Open vSwitch can coexist with the bridge module,
 * but it makes no sense to load both bridge and brcompat, so brcompat uses
 * this macro in those versions.
 *
 * The use of "typeof" here avoids the need to track changes in the type of
 * br_should_route_hook over various kernel versions.
 */
#define BRIDGE_MUTUAL_EXCLUSION					\
	typeof(br_should_route_hook) br_should_route_hook;	\
	EXPORT_SYMBOL(br_should_route_hook)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define GENL_SOCK(net) (genl_sock)
#define SET_NETNSOK
#else
#define GENL_SOCK(net) ((net)->genl_sock)
#define SET_NETNSOK    .netnsok = true,
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#ifdef CONFIG_NETFILTER
static inline u32 skb_get_mark(struct sk_buff *skb)
{
	return skb->nfmark;
}

static inline void skb_set_mark(struct sk_buff *skb, u32 mark)
{
	skb->nfmark = mark;
}
#else /* CONFIG_NETFILTER */
static inline u32 skb_get_mark(struct sk_buff *skb)
{
	return 0;
}

static inline void skb_set_mark(struct sk_buff *skb, u32 mark)
{
}
#endif
#else /* before 2.6.20 */
static inline u32 skb_get_mark(struct sk_buff *skb)
{
	return skb->mark;
}

static inline void skb_set_mark(struct sk_buff *skb, u32 mark)
{
	skb->mark = mark;
}
#endif /* after 2.6.20 */

#endif /* compat.h */
