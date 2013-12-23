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

#include <linux/kconfig.h>
#if IS_ENABLED(CONFIG_NET_IPGRE_DEMUX)

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

	return iptunnel_pull_header(skb, hdr_len, tpi->proto);
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

int gre_cisco_register(struct gre_cisco_protocol *newp)
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

int gre_cisco_unregister(struct gre_cisco_protocol *proto)
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

#endif /* !HAVE_GRE_CISCO_REGISTER */

/* GRE TX side. */
static void gre_csum_fix(struct sk_buff *skb)
{
	struct gre_base_hdr *greh;
	__be32 *options;
	int gre_offset = skb_transport_offset(skb);

	greh = (struct gre_base_hdr *)skb_transport_header(skb);
	options = ((__be32 *)greh + 1);

	*options = 0;
	*(__sum16 *)options = csum_fold(skb_checksum(skb, gre_offset,
						     skb->len - gre_offset, 0));
}

struct sk_buff *gre_handle_offloads(struct sk_buff *skb, bool gre_csum)
{
	int err;

	skb_reset_inner_headers(skb);

	if (skb_is_gso(skb)) {
		if (gre_csum)
			OVS_GSO_CB(skb)->fix_segment = gre_csum_fix;
	} else {
		if (skb->ip_summed == CHECKSUM_PARTIAL && gre_csum) {
			err = skb_checksum_help(skb);
			if (err)
				goto error;

		} else if (skb->ip_summed != CHECKSUM_PARTIAL)
			skb->ip_summed = CHECKSUM_NONE;
	}
	return skb;
error:
	kfree_skb(skb);
	return ERR_PTR(err);
}

static bool is_gre_gso(struct sk_buff *skb)
{
	return skb_is_gso(skb);
}

void gre_build_header(struct sk_buff *skb, const struct tnl_ptk_info *tpi,
		      int hdr_len)
{
	struct gre_base_hdr *greh;

	__skb_push(skb, hdr_len);

	greh = (struct gre_base_hdr *)skb->data;
	greh->flags = tnl_flags_to_gre_flags(tpi->flags);
	greh->protocol = tpi->proto;

	if (tpi->flags & (TUNNEL_KEY | TUNNEL_CSUM | TUNNEL_SEQ)) {
		__be32 *ptr = (__be32 *)(((u8 *)greh) + hdr_len - 4);

		if (tpi->flags & TUNNEL_SEQ) {
			*ptr = tpi->seq;
			ptr--;
		}
		if (tpi->flags & TUNNEL_KEY) {
			*ptr = tpi->key;
			ptr--;
		}
		if (tpi->flags & TUNNEL_CSUM && !is_gre_gso(skb)) {
			*ptr = 0;
			*(__sum16 *)ptr = csum_fold(skb_checksum(skb, 0,
						skb->len, 0));
		}
	}
}

#endif /* CONFIG_NET_IPGRE_DEMUX */
