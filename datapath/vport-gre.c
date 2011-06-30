/*
 * Copyright (c) 2010, 2011 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/if.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <linux/if_vlan.h>
#include <linux/in.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/protocol.h>

#include "tunnel.h"
#include "vport.h"
#include "vport-generic.h"

/*
 * The GRE header is composed of a series of sections: a base and then a variable
 * number of options.
 */
#define GRE_HEADER_SECTION 4

struct gre_base_hdr {
	__be16 flags;
	__be16 protocol;
};

static int gre_hdr_len(const struct tnl_mutable_config *mutable)
{
	int len;

	len = GRE_HEADER_SECTION;

	if (mutable->flags & TNL_F_CSUM)
		len += GRE_HEADER_SECTION;

	if (mutable->out_key || mutable->flags & TNL_F_OUT_KEY_ACTION)
		len += GRE_HEADER_SECTION;

	return len;
}

/* Returns the least-significant 32 bits of a __be64. */
static __be32 be64_get_low32(__be64 x)
{
#ifdef __BIG_ENDIAN
	return (__force __be32)x;
#else
	return (__force __be32)((__force u64)x >> 32);
#endif
}

static void gre_build_header(const struct vport *vport,
			     const struct tnl_mutable_config *mutable,
			     void *header)
{
	struct gre_base_hdr *greh = header;
	__be32 *options = (__be32 *)(greh + 1);

	greh->protocol = htons(ETH_P_TEB);
	greh->flags = 0;

	if (mutable->flags & TNL_F_CSUM) {
		greh->flags |= GRE_CSUM;
		*options = 0;
		options++;
	}

	if (mutable->out_key || mutable->flags & TNL_F_OUT_KEY_ACTION)
		greh->flags |= GRE_KEY;

	if (mutable->out_key)
		*options = be64_get_low32(mutable->out_key);
}

static struct sk_buff *gre_update_header(const struct vport *vport,
					 const struct tnl_mutable_config *mutable,
					 struct dst_entry *dst,
					 struct sk_buff *skb)
{
	__be32 *options = (__be32 *)(skb_network_header(skb) + mutable->tunnel_hlen
					       - GRE_HEADER_SECTION);

	/* Work backwards over the options so the checksum is last. */
	if (mutable->flags & TNL_F_OUT_KEY_ACTION) {
		*options = be64_get_low32(OVS_CB(skb)->tun_id);
		options--;
	}

	if (mutable->flags & TNL_F_CSUM)
		*(__sum16 *)options = csum_fold(skb_checksum(skb,
						skb_transport_offset(skb),
						skb->len - skb_transport_offset(skb),
						0));
	/*
	 * Allow our local IP stack to fragment the outer packet even if the
	 * DF bit is set as a last resort.  We also need to force selection of
	 * an IP ID here because Linux will otherwise leave it at 0 if the
	 * packet originally had DF set.
	 */
	skb->local_df = 1;
	__ip_select_ident(ip_hdr(skb), dst, 0);

	return skb;
}

/* Zero-extends a __be32 into the least-significant 32 bits of a __be64. */
static __be64 be32_extend_to_be64(__be32 x)
{
#ifdef __BIG_ENDIAN
	return (__force __be64)x;
#else
	return (__force __be64)((__force u64)x << 32);
#endif
}

static int parse_header(struct iphdr *iph, __be16 *flags, __be64 *key)
{
	/* IP and ICMP protocol handlers check that the IHL is valid. */
	struct gre_base_hdr *greh = (struct gre_base_hdr *)((u8 *)iph + (iph->ihl << 2));
	__be32 *options = (__be32 *)(greh + 1);
	int hdr_len;

	*flags = greh->flags;

	if (unlikely(greh->flags & (GRE_VERSION | GRE_ROUTING)))
		return -EINVAL;

	if (unlikely(greh->protocol != htons(ETH_P_TEB)))
		return -EINVAL;

	hdr_len = GRE_HEADER_SECTION;

	if (greh->flags & GRE_CSUM) {
		hdr_len += GRE_HEADER_SECTION;
		options++;
	}

	if (greh->flags & GRE_KEY) {
		hdr_len += GRE_HEADER_SECTION;

		*key = be32_extend_to_be64(*options);
		options++;
	} else
		*key = 0;

	if (unlikely(greh->flags & GRE_SEQ))
		hdr_len += GRE_HEADER_SECTION;

	return hdr_len;
}

/* Called with rcu_read_lock and BH disabled. */
static void gre_err(struct sk_buff *skb, u32 info)
{
	struct vport *vport;
	const struct tnl_mutable_config *mutable;
	const int type = icmp_hdr(skb)->type;
	const int code = icmp_hdr(skb)->code;
	int mtu = ntohs(icmp_hdr(skb)->un.frag.mtu);

	struct iphdr *iph;
	__be16 flags;
	__be64 key;
	int tunnel_hdr_len, tot_hdr_len;
	unsigned int orig_mac_header;
	unsigned int orig_nw_header;

	if (type != ICMP_DEST_UNREACH || code != ICMP_FRAG_NEEDED)
		return;

	/*
	 * The mimimum size packet that we would actually be able to process:
	 * encapsulating IP header, minimum GRE header, Ethernet header,
	 * inner IPv4 header.
	 */
	if (!pskb_may_pull(skb, sizeof(struct iphdr) + GRE_HEADER_SECTION +
				ETH_HLEN + sizeof(struct iphdr)))
		return;

	iph = (struct iphdr *)skb->data;

	tunnel_hdr_len = parse_header(iph, &flags, &key);
	if (tunnel_hdr_len < 0)
		return;

	vport = tnl_find_port(iph->saddr, iph->daddr, key,
			      TNL_T_PROTO_GRE | TNL_T_KEY_EITHER, &mutable);
	if (!vport)
		return;

	/*
	 * Packets received by this function were previously sent by us, so
	 * any comparisons should be to the output values, not the input.
	 * However, it's not really worth it to have a hash table based on
	 * output keys (especially since ICMP error handling of tunneled packets
	 * isn't that reliable anyways).  Therefore, we do a lookup based on the
	 * out key as if it were the in key and then check to see if the input
	 * and output keys are the same.
	 */
	if (mutable->in_key != mutable->out_key)
		return;

	if (!!(mutable->flags & TNL_F_IN_KEY_MATCH) !=
	    !!(mutable->flags & TNL_F_OUT_KEY_ACTION))
		return;

	if ((mutable->flags & TNL_F_CSUM) && !(flags & GRE_CSUM))
		return;

	tunnel_hdr_len += iph->ihl << 2;

	orig_mac_header = skb_mac_header(skb) - skb->data;
	orig_nw_header = skb_network_header(skb) - skb->data;
	skb_set_mac_header(skb, tunnel_hdr_len);

	tot_hdr_len = tunnel_hdr_len + ETH_HLEN;

	skb->protocol = eth_hdr(skb)->h_proto;
	if (skb->protocol == htons(ETH_P_8021Q)) {
		tot_hdr_len += VLAN_HLEN;
		skb->protocol = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
	}

	skb_set_network_header(skb, tot_hdr_len);
	mtu -= tot_hdr_len;

	if (skb->protocol == htons(ETH_P_IP))
		tot_hdr_len += sizeof(struct iphdr);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (skb->protocol == htons(ETH_P_IPV6))
		tot_hdr_len += sizeof(struct ipv6hdr);
#endif
	else
		goto out;

	if (!pskb_may_pull(skb, tot_hdr_len))
		goto out;

	if (skb->protocol == htons(ETH_P_IP)) {
		if (mtu < IP_MIN_MTU) {
			if (ntohs(ip_hdr(skb)->tot_len) >= IP_MIN_MTU)
				mtu = IP_MIN_MTU;
			else
				goto out;
		}

	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		if (mtu < IPV6_MIN_MTU) {
			unsigned int packet_length = sizeof(struct ipv6hdr) +
					      ntohs(ipv6_hdr(skb)->payload_len);

			if (packet_length >= IPV6_MIN_MTU
			    || ntohs(ipv6_hdr(skb)->payload_len) == 0)
				mtu = IPV6_MIN_MTU;
			else
				goto out;
		}
	}
#endif

	__skb_pull(skb, tunnel_hdr_len);
	tnl_frag_needed(vport, mutable, skb, mtu, key);
	__skb_push(skb, tunnel_hdr_len);

out:
	skb_set_mac_header(skb, orig_mac_header);
	skb_set_network_header(skb, orig_nw_header);
	skb->protocol = htons(ETH_P_IP);
}

static bool check_checksum(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct gre_base_hdr *greh = (struct gre_base_hdr *)(iph + 1);
	__sum16 csum = 0;

	if (greh->flags & GRE_CSUM) {
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
	}

	return (csum == 0);
}

/* Called with rcu_read_lock and BH disabled. */
static int gre_rcv(struct sk_buff *skb)
{
	struct vport *vport;
	const struct tnl_mutable_config *mutable;
	int hdr_len;
	struct iphdr *iph;
	__be16 flags;
	__be64 key;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct gre_base_hdr) + ETH_HLEN)))
		goto error;

	if (unlikely(!check_checksum(skb)))
		goto error;

	hdr_len = parse_header(ip_hdr(skb), &flags, &key);
	if (unlikely(hdr_len < 0))
		goto error;

	if (unlikely(!pskb_may_pull(skb, hdr_len + ETH_HLEN)))
		goto error;

	iph = ip_hdr(skb);
	vport = tnl_find_port(iph->daddr, iph->saddr, key,
			      TNL_T_PROTO_GRE | TNL_T_KEY_EITHER, &mutable);
	if (unlikely(!vport)) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
		goto error;
	}

	if (mutable->flags & TNL_F_IN_KEY_MATCH)
		OVS_CB(skb)->tun_id = key;
	else
		OVS_CB(skb)->tun_id = 0;

	__skb_pull(skb, hdr_len);
	skb_postpull_rcsum(skb, skb_transport_header(skb), hdr_len + ETH_HLEN);

	tnl_rcv(vport, skb, iph->tos);
	return 0;

error:
	kfree_skb(skb);
	return 0;
}

static const struct tnl_ops gre_tnl_ops = {
	.tunnel_type	= TNL_T_PROTO_GRE,
	.ipproto	= IPPROTO_GRE,
	.hdr_len	= gre_hdr_len,
	.build_header	= gre_build_header,
	.update_header	= gre_update_header,
};

static struct vport *gre_create(const struct vport_parms *parms)
{
	return tnl_create(parms, &gre_vport_ops, &gre_tnl_ops);
}

static const struct net_protocol gre_protocol_handlers = {
	.handler	=	gre_rcv,
	.err_handler	=	gre_err,
};

static int gre_init(void)
{
	int err;

	err = inet_add_protocol(&gre_protocol_handlers, IPPROTO_GRE);
	if (err)
		pr_warn("cannot register gre protocol handler\n");

	return err;
}

static void gre_exit(void)
{
	inet_del_protocol(&gre_protocol_handlers, IPPROTO_GRE);
}

const struct vport_ops gre_vport_ops = {
	.type		= ODP_VPORT_TYPE_GRE,
	.flags		= VPORT_F_GEN_STATS | VPORT_F_TUN_ID,
	.init		= gre_init,
	.exit		= gre_exit,
	.create		= gre_create,
	.destroy	= tnl_destroy,
	.set_addr	= tnl_set_addr,
	.get_name	= tnl_get_name,
	.get_addr	= tnl_get_addr,
	.get_options	= tnl_get_options,
	.set_options	= tnl_set_options,
	.get_dev_flags	= vport_gen_get_dev_flags,
	.is_running	= vport_gen_is_running,
	.get_operstate	= vport_gen_get_operstate,
	.send		= tnl_send,
};
