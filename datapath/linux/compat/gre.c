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

#define ip_gre_calc_hlen rpl_ip_gre_calc_hlen
#define gre_calc_hlen rpl_ip_gre_calc_hlen
static int rpl_ip_gre_calc_hlen(__be16 o_flags)
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

#ifndef HAVE_GRE_HANDLE_OFFLOADS
#ifndef HAVE_GRE_CISCO_REGISTER

#ifdef HAVE_DEMUX_PARSE_GRE_HEADER
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
	tpi->hdr_len = hdr_len;
	tpi->proto = greh->protocol;

	if (!pskb_may_pull(skb, hdr_len))
		return -EINVAL;

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

#endif /* HAVE_DEMUX_PARSE_GRE_HEADER */

static struct gre_cisco_protocol __rcu *gre_cisco_proto;
static int gre_cisco_rcv(struct sk_buff *skb)
{
	struct tnl_ptk_info tpi;
	struct gre_cisco_protocol *proto;

	rcu_read_lock();
	proto = rcu_dereference(gre_cisco_proto);
	if (!proto)
		goto drop;
#ifdef HAVE_DEMUX_PARSE_GRE_HEADER
	{
		bool csum_err = false;
		if (parse_gre_header(skb, &tpi, &csum_err) < 0)
			goto drop;
	}
#endif
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

void rpl_gre_build_header(struct sk_buff *skb, const struct tnl_ptk_info *tpi,
			  int hdr_len)
{
	struct gre_base_hdr *greh;

	skb_push(skb, hdr_len);

	skb_reset_transport_header(skb);
	greh = (struct gre_base_hdr *)skb->data;
	greh->flags = tnl_flags_to_gre_flags(tpi->flags);
	greh->protocol = tpi->proto;

	if (tpi->flags&(TUNNEL_KEY|TUNNEL_CSUM|TUNNEL_SEQ)) {
		__be32 *ptr = (__be32 *)(((u8 *)greh) + hdr_len - 4);

		if (tpi->flags&TUNNEL_SEQ) {
			*ptr = tpi->seq;
			ptr--;
		}
		if (tpi->flags&TUNNEL_KEY) {
			*ptr = tpi->key;
			ptr--;
		}
		if (tpi->flags&TUNNEL_CSUM &&
		    !(skb_shinfo(skb)->gso_type &
		      (SKB_GSO_GRE|SKB_GSO_GRE_CSUM))) {
			*ptr = 0;
			*(__sum16 *)ptr = csum_fold(skb_checksum(skb, 0,
								 skb->len, 0));
		}
	}
}
EXPORT_SYMBOL_GPL(rpl_gre_build_header);

/* Fills in tpi and returns header length to be pulled. */
int rpl_gre_parse_header(struct sk_buff *skb, struct tnl_ptk_info *tpi,
		     bool *csum_err, __be16 proto, int nhs)
{
	const struct gre_base_hdr *greh;
	__be32 *options;
	int hdr_len;

	if (unlikely(!pskb_may_pull(skb, nhs + sizeof(struct gre_base_hdr))))
		return -EINVAL;

	greh = (struct gre_base_hdr *)(skb->data + nhs);
	if (unlikely(greh->flags & (GRE_VERSION | GRE_ROUTING)))
		return -EINVAL;

	tpi->flags = gre_flags_to_tnl_flags(greh->flags);
	hdr_len = gre_calc_hlen(tpi->flags);

	if (!pskb_may_pull(skb, nhs + hdr_len))
		return -EINVAL;

	greh = (struct gre_base_hdr *)(skb->data + nhs);
	tpi->proto = greh->protocol;

	options = (__be32 *)(greh + 1);
	if (greh->flags & GRE_CSUM) {
		if (skb_checksum_simple_validate(skb)) {
			*csum_err = true;
			return -EINVAL;
		}

		skb_checksum_try_convert(skb, IPPROTO_GRE, 0,
					 null_compute_pseudo);
		options++;
	}

	if (greh->flags & GRE_KEY) {
		tpi->key = *options;
		options++;
	} else {
		tpi->key = 0;
	}
	if (unlikely(greh->flags & GRE_SEQ)) {
		tpi->seq = *options;
		options++;
	} else {
		tpi->seq = 0;
	}
	/* WCCP version 1 and 2 protocol decoding.
 	 * - Change protocol to IPv4/IPv6
	 * - When dealing with WCCPv2, Skip extra 4 bytes in GRE header
	 */
	if (greh->flags == 0 && tpi->proto == htons(ETH_P_WCCP)) {
		tpi->proto = proto;
		if ((*(u8 *)options & 0xF0) != 0x40)
			hdr_len += 4;
	}
	tpi->hdr_len = hdr_len;
	return hdr_len;
}
EXPORT_SYMBOL(rpl_gre_parse_header);

#endif /* CONFIG_NET_IPGRE_DEMUX */
#endif /* USE_UPSTREAM_TUNNEL */
