/*
 * Copyright (c) 2007-2013 Nicira, Inc.
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

#include <linux/version.h>
#include <linux/kconfig.h>
#include <linux/module.h>
#include <linux/if.h>
#include <linux/if_tunnel.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>

#include <net/gre.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>

#include "gso.h"

#ifndef USE_UPSTREAM_TUNNEL
#if IS_ENABLED(CONFIG_NET_IPGRE_DEMUX)

#ifndef HAVE_GRE_HANDLE_OFFLOADS

#ifndef HAVE_GRE_CISCO_REGISTER

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)

#define GREPROTO_CISCO		0
#define GREPROTO_MAX		1

struct gre_protocol {
	int  (*handler)(struct sk_buff *skb);
};
static const struct gre_protocol __rcu *gre_proto[GREPROTO_MAX] __read_mostly;

static int gre_rcv(struct sk_buff *skb)
{
	const struct gre_protocol *proto;
	u8 ver;
	int ret;

	if (!pskb_may_pull(skb, 12))
		goto drop;

	ver = skb->data[1] & 0x7f;
	if (ver >= GREPROTO_MAX)
		goto drop;

	rcu_read_lock();
	proto = rcu_dereference(gre_proto[ver]);
	if (!proto || !proto->handler)
		goto drop_unlock;
	ret = proto->handler(skb);
	rcu_read_unlock();
	return ret;

drop_unlock:
	rcu_read_unlock();
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static const struct net_protocol net_gre_protocol = {
	.handler     = gre_rcv,
	.netns_ok    = 1,
};

static int gre_add_protocol(const struct gre_protocol *proto, u8 version)
{
	if (version >= GREPROTO_MAX)
		return -EINVAL;

	if (inet_add_protocol(&net_gre_protocol, IPPROTO_GRE) < 0) {
		pr_err("%s: cannot register gre protocol handler\n", __func__);
		return -EAGAIN;
	}

	return (cmpxchg((const struct gre_protocol **)&gre_proto[version], NULL, proto) == NULL) ?
		0 : -EBUSY;
}

static int gre_del_protocol(const struct gre_protocol *proto, u8 version)
{
	int ret;

	if (version >= GREPROTO_MAX)
		return -EINVAL;

	ret = (cmpxchg((const struct gre_protocol **)&gre_proto[version], proto, NULL) == proto) ?
		0 : -EBUSY;

	if (ret)
		return ret;

	synchronize_net();

	ret = inet_del_protocol(&net_gre_protocol, IPPROTO_GRE);
	if (ret)
		return ret;

	return 0;
}

#endif

static __sum16 check_checksum(struct sk_buff *skb)
{
	__sum16 csum = 0;

	switch (skb->ip_summed) {
	case CHECKSUM_COMPLETE:
		csum = csum_fold(skb->csum);

		if (!csum)
			break;
		/* Fall through. */

	case CHECKSUM_NONE:
		skb->csum = 0;
		csum = __skb_checksum_complete(skb);
		skb->ip_summed = CHECKSUM_COMPLETE;
		break;
	}

	return csum;
}

#define ip_gre_calc_hlen rpl_ip_gre_calc_hlen
static int ip_gre_calc_hlen(__be16 o_flags)
{
	int addend = 4;

	if (o_flags & TUNNEL_CSUM)
		addend += 4;
	if (o_flags & TUNNEL_KEY)
		addend += 4;
	if (o_flags & TUNNEL_SEQ)
		addend += 4;
	return addend;
}

#define gre_flags_to_tnl_flags rpl_gre_flags_to_tnl_flags
static __be16 gre_flags_to_tnl_flags(__be16 flags)
{
	__be16 tflags = 0;

	if (flags & GRE_CSUM)
		tflags |= TUNNEL_CSUM;
	if (flags & GRE_ROUTING)
		tflags |= TUNNEL_ROUTING;
	if (flags & GRE_KEY)
		tflags |= TUNNEL_KEY;
	if (flags & GRE_SEQ)
		tflags |= TUNNEL_SEQ;
	if (flags & GRE_STRICT)
		tflags |= TUNNEL_STRICT;
	if (flags & GRE_REC)
		tflags |= TUNNEL_REC;
	if (flags & GRE_VERSION)
		tflags |= TUNNEL_VERSION;

	return tflags;
}

static int parse_gre_header(struct sk_buff *skb, struct tnl_ptk_info *tpi,
			    bool *csum_err)
{
	unsigned int ip_hlen = ip_hdrlen(skb);
	struct gre_base_hdr *greh;
	__be32 *options;
	int hdr_len;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct gre_base_hdr))))
		return -EINVAL;

	greh = (struct gre_base_hdr *)(skb_network_header(skb) + ip_hlen);
	if (unlikely(greh->flags & (GRE_VERSION | GRE_ROUTING)))
		return -EINVAL;

	tpi->flags = gre_flags_to_tnl_flags(greh->flags);
	hdr_len = ip_gre_calc_hlen(tpi->flags);

	if (!pskb_may_pull(skb, hdr_len))
		return -EINVAL;

	greh = (struct gre_base_hdr *)(skb_network_header(skb) + ip_hlen);
	tpi->proto = greh->protocol;

	options = (__be32 *)(greh + 1);
	if (greh->flags & GRE_CSUM) {
		if (check_checksum(skb)) {
			*csum_err = true;
			return -EINVAL;
		}
		options++;
	}

	if (greh->flags & GRE_KEY) {
		tpi->key = *options;
		options++;
	} else
		tpi->key = 0;

	if (unlikely(greh->flags & GRE_SEQ)) {
		tpi->seq = *options;
		options++;
	} else
		tpi->seq = 0;

	/* WCCP version 1 and 2 protocol decoding.
	 * - Change protocol to IP
	 * - When dealing with WCCPv2, Skip extra 4 bytes in GRE header
	 */
	if (greh->flags == 0 && tpi->proto == htons(ETH_P_WCCP)) {
		tpi->proto = htons(ETH_P_IP);
		if ((*(u8 *)options & 0xF0) != 0x40) {
			hdr_len += 4;
			if (!pskb_may_pull(skb, hdr_len))
				return -EINVAL;
		}
	}

	return iptunnel_pull_header(skb, hdr_len, tpi->proto, false);
}

static struct gre_cisco_protocol __rcu *gre_cisco_proto;
static int gre_cisco_rcv(struct sk_buff *skb)
{
	struct tnl_ptk_info tpi;
	bool csum_err = false;
	struct gre_cisco_protocol *proto;

	rcu_read_lock();
	proto = rcu_dereference(gre_cisco_proto);
	if (!proto)
		goto drop;

	if (parse_gre_header(skb, &tpi, &csum_err) < 0)
		goto drop;
	proto->handler(skb, &tpi);
	rcu_read_unlock();
	return 0;

drop:
	rcu_read_unlock();
	kfree_skb(skb);
	return 0;
}

static const struct gre_protocol ipgre_protocol = {
	.handler	=	gre_cisco_rcv,
};

int rpl_gre_cisco_register(struct gre_cisco_protocol *newp)
{
	int err;

	err = gre_add_protocol(&ipgre_protocol, GREPROTO_CISCO);
	if (err) {
		pr_warn("%s: cannot register gre_cisco protocol handler\n", __func__);
		return err;
	}


	return (cmpxchg((struct gre_cisco_protocol **)&gre_cisco_proto, NULL, newp) == NULL) ?
		0 : -EBUSY;
}
EXPORT_SYMBOL_GPL(rpl_gre_cisco_register);

int rpl_gre_cisco_unregister(struct gre_cisco_protocol *proto)
{
	int ret;

	ret = (cmpxchg((struct gre_cisco_protocol **)&gre_cisco_proto, proto, NULL) == proto) ?
		0 : -EINVAL;

	if (ret)
		return ret;

	synchronize_net();
	ret = gre_del_protocol(&ipgre_protocol, GREPROTO_CISCO);
	return ret;
}
EXPORT_SYMBOL_GPL(rpl_gre_cisco_unregister);

#endif /* !HAVE_GRE_CISCO_REGISTER */
#endif

#endif /* CONFIG_NET_IPGRE_DEMUX */
#endif /* USE_UPSTREAM_TUNNEL */
