/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008, 2009, 2010 Nicira Networks.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

/* Functions for executing flow actions. */

#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in6.h>
#include <linux/if_vlan.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/checksum.h>
#include "datapath.h"
#include "dp_dev.h"
#include "actions.h"
#include "openvswitch/datapath-protocol.h"

static struct sk_buff *
make_writable(struct sk_buff *skb, unsigned min_headroom, gfp_t gfp)
{
	if (skb_shared(skb) || skb_cloned(skb)) {
		struct sk_buff *nskb;
		unsigned headroom = max(min_headroom, skb_headroom(skb));

		nskb = skb_copy_expand(skb, headroom, skb_tailroom(skb), gfp);
		if (nskb) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
			/* Before 2.6.24 these fields were not copied when
			 * doing an skb_copy_expand. */
			nskb->ip_summed = skb->ip_summed;
			nskb->csum = skb->csum;
#endif
#if defined(CONFIG_XEN) && defined(HAVE_PROTO_DATA_VALID)
			/* These fields are copied in skb_clone but not in
			 * skb_copy or related functions.  We need to manually
			 * copy them over here. */
			nskb->proto_data_valid = skb->proto_data_valid;
			nskb->proto_csum_blank = skb->proto_csum_blank;
#endif
			kfree_skb(skb);
			return nskb;
		}
	} else {
		unsigned int hdr_len = (skb_transport_offset(skb)
					+ sizeof(struct tcphdr));
		if (pskb_may_pull(skb, min(hdr_len, skb->len)))
			return skb;
	}
	kfree_skb(skb);
	return NULL;
}


static struct sk_buff *
vlan_pull_tag(struct sk_buff *skb)
{
	struct vlan_ethhdr *vh = vlan_eth_hdr(skb);
	struct ethhdr *eh;


	/* Verify we were given a vlan packet */
	if (vh->h_vlan_proto != htons(ETH_P_8021Q))
		return skb;

	memmove(skb->data + VLAN_HLEN, skb->data, 2 * VLAN_ETH_ALEN);

	eh = (struct ethhdr *)skb_pull(skb, VLAN_HLEN);

	skb->protocol = eh->h_proto;
	skb->mac_header += VLAN_HLEN;

	return skb;
}


static struct sk_buff *
modify_vlan_tci(struct datapath *dp, struct sk_buff *skb,
		struct odp_flow_key *key, const union odp_action *a,
		int n_actions, gfp_t gfp)
{
	u16 tci, mask;

	if (a->type == ODPAT_SET_VLAN_VID) {
		tci = ntohs(a->vlan_vid.vlan_vid);
		mask = VLAN_VID_MASK;
		key->dl_vlan = htons(tci & mask);
	} else {
		tci = a->vlan_pcp.vlan_pcp << 13;
		mask = VLAN_PCP_MASK;
	}

	skb = make_writable(skb, VLAN_HLEN, gfp);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	if (skb->protocol == htons(ETH_P_8021Q)) {
		/* Modify vlan id, but maintain other TCI values */
		struct vlan_ethhdr *vh = vlan_eth_hdr(skb);
		vh->h_vlan_TCI = htons((ntohs(vh->h_vlan_TCI) & ~mask) | tci);
	} else {
		/* Add vlan header */

		/* Set up checksumming pointers for checksum-deferred packets
		 * on Xen.  Otherwise, dev_queue_xmit() will try to do this
		 * when we send the packet out on the wire, and it will fail at
		 * that point because skb_checksum_setup() will not look inside
		 * an 802.1Q header. */
		vswitch_skb_checksum_setup(skb);

		/* GSO is not implemented for packets with an 802.1Q header, so
		 * we have to do segmentation before we add that header.
		 *
		 * GSO does work with hardware-accelerated VLAN tagging, but we
		 * can't use hardware-accelerated VLAN tagging since it
		 * requires the device to have a VLAN group configured (with
		 * e.g. vconfig(8)) and we don't do that.
		 *
		 * Having to do this here may be a performance loss, since we
		 * can't take advantage of TSO hardware support, although it
		 * does not make a measurable network performance difference
		 * for 1G Ethernet.  Fixing that would require patching the
		 * kernel (either to add GSO support to the VLAN protocol or to
		 * support hardware-accelerated VLAN tagging without VLAN
		 * groups configured). */
		if (skb_is_gso(skb)) {
			struct sk_buff *segs;

			segs = skb_gso_segment(skb, 0);
			kfree_skb(skb);
			if (unlikely(IS_ERR(segs)))
				return ERR_CAST(segs);

			do {
				struct sk_buff *nskb = segs->next;
				int err;

				segs->next = NULL;

				segs = __vlan_put_tag(segs, tci);
				err = -ENOMEM;
				if (segs) {
					struct odp_flow_key segkey = *key;
					err = execute_actions(dp, segs,
							      &segkey, a + 1,
							      n_actions - 1,
							      gfp);
				}

				if (unlikely(err)) {
					while ((segs = nskb)) {
						nskb = segs->next;
						segs->next = NULL;
						kfree_skb(segs);
					}
					return ERR_PTR(err);
				}

				segs = nskb;
			} while (segs->next);

			skb = segs;
		}

		/* The hardware-accelerated version of vlan_put_tag() works
		 * only for a device that has a VLAN group configured (with
		 * e.g. vconfig(8)), so call the software-only version
		 * __vlan_put_tag() directly instead.
		 */
		skb = __vlan_put_tag(skb, tci);
		if (!skb)
			return ERR_PTR(-ENOMEM);
	}

	return skb;
}

static struct sk_buff *strip_vlan(struct sk_buff *skb,
				  struct odp_flow_key *key, gfp_t gfp)
{
	skb = make_writable(skb, 0, gfp);
	if (skb) {
		vlan_pull_tag(skb);
		key->dl_vlan = htons(ODP_VLAN_NONE);
	}
	return skb;
}

static struct sk_buff *set_dl_addr(struct sk_buff *skb,
				   const struct odp_action_dl_addr *a,
				   gfp_t gfp)
{
	skb = make_writable(skb, 0, gfp);
	if (skb) {
		struct ethhdr *eh = eth_hdr(skb);
		memcpy(a->type == ODPAT_SET_DL_SRC ? eh->h_source : eh->h_dest,
		       a->dl_addr, ETH_ALEN);
	}
	return skb;
}

/* Updates 'sum', which is a field in 'skb''s data, given that a 4-byte field
 * covered by the sum has been changed from 'from' to 'to'.  If set,
 * 'pseudohdr' indicates that the field is in the TCP or UDP pseudo-header.
 * Based on nf_proto_csum_replace4. */
static void update_csum(__sum16 *sum, struct sk_buff *skb,
			__be32 from, __be32 to, int pseudohdr)
{
	__be32 diff[] = { ~from, to };
	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		*sum = csum_fold(csum_partial((char *)diff, sizeof(diff),
				~csum_unfold(*sum)));
		if (skb->ip_summed == CHECKSUM_COMPLETE && pseudohdr)
			skb->csum = ~csum_partial((char *)diff, sizeof(diff),
						~skb->csum);
	} else if (pseudohdr)
		*sum = ~csum_fold(csum_partial((char *)diff, sizeof(diff),
				csum_unfold(*sum)));
}

static struct sk_buff *set_nw_addr(struct sk_buff *skb,
				   struct odp_flow_key *key,
				   const struct odp_action_nw_addr *a,
				   gfp_t gfp)
{
	if (key->dl_type != htons(ETH_P_IP))
		return skb;

	skb = make_writable(skb, 0, gfp);
	if (skb) {
		struct iphdr *nh = ip_hdr(skb);
		u32 *f = a->type == ODPAT_SET_NW_SRC ? &nh->saddr : &nh->daddr;
		u32 old = *f;
		u32 new = a->nw_addr;

		if (key->nw_proto == IPPROTO_TCP) {
			struct tcphdr *th = tcp_hdr(skb);
			update_csum(&th->check, skb, old, new, 1);
		} else if (key->nw_proto == IPPROTO_UDP) {
			struct udphdr *th = udp_hdr(skb);
			update_csum(&th->check, skb, old, new, 1);
		}
		update_csum(&nh->check, skb, old, new, 0);
		*f = new;
	}
	return skb;
}

static struct sk_buff *set_nw_tos(struct sk_buff *skb,
				   struct odp_flow_key *key,
				   const struct odp_action_nw_tos *a,
				   gfp_t gfp)
{
	if (key->dl_type != htons(ETH_P_IP))
		return skb;

	skb = make_writable(skb, 0, gfp);
	if (skb) {
		struct iphdr *nh = ip_hdr(skb);
		u8 *f = &nh->tos;
		u8 old = *f;
		u8 new;

		/* Set the DSCP bits and preserve the ECN bits. */
		new = (a->nw_tos & ~INET_ECN_MASK) | (nh->tos & INET_ECN_MASK);
		update_csum(&nh->check, skb, htons((uint16_t)old),
				htons((uint16_t)new), 0);
		*f = new;
	}
	return skb;
}

static struct sk_buff *
set_tp_port(struct sk_buff *skb, struct odp_flow_key *key,
	    const struct odp_action_tp_port *a,
	    gfp_t gfp)
{
	int check_ofs;

	if (key->dl_type != htons(ETH_P_IP))
		return skb;

	if (key->nw_proto == IPPROTO_TCP)
		check_ofs = offsetof(struct tcphdr, check);
	else if (key->nw_proto == IPPROTO_UDP)
		check_ofs = offsetof(struct udphdr, check);
	else
		return skb;

	skb = make_writable(skb, 0, gfp);
	if (skb) {
		struct udphdr *th = udp_hdr(skb);
		u16 *f = a->type == ODPAT_SET_TP_SRC ? &th->source : &th->dest;
		u16 old = *f;
		u16 new = a->tp_port;
		update_csum((u16*)(skb_transport_header(skb) + check_ofs), 
				skb, old, new, 1);
		*f = new;
	}
	return skb;
}

static inline unsigned packet_length(const struct sk_buff *skb)
{
	unsigned length = skb->len - ETH_HLEN;
	if (skb->protocol == htons(ETH_P_8021Q))
		length -= VLAN_HLEN;
	return length;
}

int dp_xmit_skb(struct sk_buff *skb)
{
	struct datapath *dp = skb->dev->br_port->dp;
	int len = skb->len;

	if (packet_length(skb) > skb->dev->mtu && !skb_is_gso(skb)) {
		printk(KERN_WARNING "%s: dropped over-mtu packet: %d > %d\n",
		       dp_name(dp), packet_length(skb), skb->dev->mtu);
		kfree_skb(skb);
		return -E2BIG;
	}

	dev_queue_xmit(skb);

	return len;
}

static void
do_output(struct datapath *dp, struct sk_buff *skb, int out_port)
{
	struct net_bridge_port *p;
	struct net_device *dev;

	if (!skb)
		goto error;

	p = dp->ports[out_port];
	if (!p)
		goto error;

	dev = skb->dev = p->dev;
	if (is_dp_dev(dev))
		dp_dev_recv(dev, skb);
	else
		dp_xmit_skb(skb);
	return;

error:
	kfree_skb(skb);
}

/* Never consumes 'skb'.  Returns a port that 'skb' should be sent to, -1 if
 * none.  */
static int output_group(struct datapath *dp, __u16 group,
			struct sk_buff *skb, gfp_t gfp)
{
	struct dp_port_group *g = rcu_dereference(dp->groups[group]);
	int prev_port = -1;
	int i;

	if (!g)
		return -1;
	for (i = 0; i < g->n_ports; i++) {
		struct net_bridge_port *p = dp->ports[g->ports[i]];
		if (!p || skb->dev == p->dev)
			continue;
		if (prev_port != -1) {
			struct sk_buff *clone = skb_clone(skb, gfp);
			if (!clone)
				return -1;
			do_output(dp, clone, prev_port);
		}
		prev_port = p->port_no;
	}
	return prev_port;
}

static int
output_control(struct datapath *dp, struct sk_buff *skb, u32 arg, gfp_t gfp)
{
	skb = skb_clone(skb, gfp);
	if (!skb)
		return -ENOMEM;
	return dp_output_control(dp, skb, _ODPL_ACTION_NR, arg);
}

/* Execute a list of actions against 'skb'. */
int execute_actions(struct datapath *dp, struct sk_buff *skb,
		    struct odp_flow_key *key,
		    const union odp_action *a, int n_actions,
		    gfp_t gfp)
{
	/* Every output action needs a separate clone of 'skb', but the common
	 * case is just a single output action, so that doing a clone and
	 * then freeing the original skbuff is wasteful.  So the following code
	 * is slightly obscure just to avoid that. */
	int prev_port = -1;
	int err;
	for (; n_actions > 0; a++, n_actions--) {
		WARN_ON_ONCE(skb_shared(skb));
		if (prev_port != -1) {
			do_output(dp, skb_clone(skb, gfp), prev_port);
			prev_port = -1;
		}

		switch (a->type) {
		case ODPAT_OUTPUT:
			prev_port = a->output.port;
			break;

		case ODPAT_OUTPUT_GROUP:
			prev_port = output_group(dp, a->output_group.group,
						 skb, gfp);
			break;

		case ODPAT_CONTROLLER:
			err = output_control(dp, skb, a->controller.arg, gfp);
			if (err) {
				kfree_skb(skb);
				return err;
			}
			break;

		case ODPAT_SET_VLAN_VID:
		case ODPAT_SET_VLAN_PCP:
			skb = modify_vlan_tci(dp, skb, key, a, n_actions, gfp);
			if (IS_ERR(skb))
				return PTR_ERR(skb);
			break;

		case ODPAT_STRIP_VLAN:
			skb = strip_vlan(skb, key, gfp);
			break;

		case ODPAT_SET_DL_SRC:
		case ODPAT_SET_DL_DST:
			skb = set_dl_addr(skb, &a->dl_addr, gfp);
			break;

		case ODPAT_SET_NW_SRC:
		case ODPAT_SET_NW_DST:
			skb = set_nw_addr(skb, key, &a->nw_addr, gfp);
			break;

		case ODPAT_SET_NW_TOS:
			skb = set_nw_tos(skb, key, &a->nw_tos, gfp);
			break;

		case ODPAT_SET_TP_SRC:
		case ODPAT_SET_TP_DST:
			skb = set_tp_port(skb, key, &a->tp_port, gfp);
			break;
		}
		if (!skb)
			return -ENOMEM;
	}
	if (prev_port != -1)
		do_output(dp, skb, prev_port);
	else
		kfree_skb(skb);
	return 0;
}
