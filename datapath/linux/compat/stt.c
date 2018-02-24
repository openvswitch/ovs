/*
 * Stateless TCP Tunnel (STT) vport.
 *
 * Copyright (c) 2015 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <asm/unaligned.h>

#include <linux/delay.h>
#include <linux/flex_array.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/percpu.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>

#include <net/dst_metadata.h>
#include <net/icmp.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/ip_tunnels.h>
#include <net/ip6_checksum.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include <net/stt.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "gso.h"
#include "compat.h"

#define STT_NETDEV_VER	"0.1"
#define STT_DST_PORT 7471

#ifdef OVS_STT
#ifdef CONFIG_SLUB
/*
 * We saw better performance with skipping zero copy in case of SLUB.
 * So skip zero copy for SLUB case.
 */
#define SKIP_ZERO_COPY
#endif

#define STT_VER 0

/* @list: Per-net list of STT ports.
 * @rcv: The callback is called on STT packet recv, STT reassembly can generate
 * multiple packets, in this case first packet has tunnel outer header, rest
 * of the packets are inner packet segments with no stt header.
 * @rcv_data: user data.
 * @sock: Fake TCP socket for the STT port.
 */
struct stt_dev {
	struct net_device	*dev;
	struct net		*net;
	struct list_head	next;
	struct list_head	up_next;
	struct socket		*sock;
	__be16			dst_port;
};

#define STT_CSUM_VERIFIED	BIT(0)
#define STT_CSUM_PARTIAL	BIT(1)
#define STT_PROTO_IPV4		BIT(2)
#define STT_PROTO_TCP		BIT(3)
#define STT_PROTO_TYPES		(STT_PROTO_IPV4 | STT_PROTO_TCP)

#ifdef HAVE_SKB_GSO_UDP
#define SUPPORTED_GSO_TYPES (SKB_GSO_TCPV4 | SKB_GSO_UDP | SKB_GSO_DODGY | \
			     SKB_GSO_TCPV6)
#else
#define SUPPORTED_GSO_TYPES (SKB_GSO_TCPV4 | SKB_GSO_DODGY | \
			     SKB_GSO_TCPV6)
#endif

/* The length and offset of a fragment are encoded in the sequence number.
 * STT_SEQ_LEN_SHIFT is the left shift needed to store the length.
 * STT_SEQ_OFFSET_MASK is the mask to extract the offset.
 */
#define STT_SEQ_LEN_SHIFT 16
#define STT_SEQ_OFFSET_MASK (BIT(STT_SEQ_LEN_SHIFT) - 1)

/* The maximum amount of memory used to store packets waiting to be reassembled
 * on a given CPU.  Once this threshold is exceeded we will begin freeing the
 * least recently used fragments.
 */
#define REASM_HI_THRESH (4 * 1024 * 1024)
/* The target for the high memory evictor.  Once we have exceeded
 * REASM_HI_THRESH, we will continue freeing fragments until we hit
 * this limit.
 */
#define REASM_LO_THRESH (3 * 1024 * 1024)
/* The length of time a given packet has to be reassembled from the time the
 * first fragment arrives.  Once this limit is exceeded it becomes available
 * for cleaning.
 */
#define FRAG_EXP_TIME (30 * HZ)
/* Number of hash entries.  Each entry has only a single slot to hold a packet
 * so if there are collisions, we will drop packets.  This is allocated
 * per-cpu and each entry consists of struct pkt_frag.
 */
#define FRAG_HASH_SHIFT		8
#define FRAG_HASH_ENTRIES	BIT(FRAG_HASH_SHIFT)
#define FRAG_HASH_SEGS		((sizeof(u32) * 8) / FRAG_HASH_SHIFT)

#define CLEAN_PERCPU_INTERVAL (30 * HZ)

struct pkt_key {
	__be32 saddr;
	__be32 daddr;
	__be32 pkt_seq;
	u32 mark;
};

struct pkt_frag {
	struct sk_buff *skbs;
	unsigned long timestamp;
	struct list_head lru_node;
	struct pkt_key key;
};

struct stt_percpu {
	struct flex_array *frag_hash;
	struct list_head frag_lru;
	unsigned int frag_mem_used;

	/* Protect frags table. */
	spinlock_t lock;
};

struct first_frag {
	struct sk_buff *last_skb;
	unsigned int mem_used;
	u16 tot_len;
	u16 rcvd_len;
	bool set_ecn_ce;
};

struct frag_skb_cb {
	u16 offset;

	/* Only valid for the first skb in the chain. */
	struct first_frag first;
};

#define FRAG_CB(skb) ((struct frag_skb_cb *)(skb)->cb)

/* per-network namespace private data for this module */
struct stt_net {
	struct list_head stt_list;
	struct list_head stt_up_list;	/* Devices which are in IFF_UP state. */
	int n_tunnels;
#ifdef HAVE_NF_REGISTER_NET_HOOK
	bool nf_hook_reg_done;
#endif
};

static int stt_net_id;

static struct stt_percpu __percpu *stt_percpu_data __read_mostly;
static u32 frag_hash_seed __read_mostly;

/* Protects sock-hash and refcounts. */
static DEFINE_MUTEX(stt_mutex);

static int n_tunnels;
static DEFINE_PER_CPU(u32, pkt_seq_counter);

static void clean_percpu(struct work_struct *work);
static DECLARE_DELAYED_WORK(clean_percpu_wq, clean_percpu);

static struct stt_dev *stt_find_up_dev(struct net *net, __be16 port)
{
	struct stt_net *sn = net_generic(net, stt_net_id);
	struct stt_dev *stt_dev;

	list_for_each_entry_rcu(stt_dev, &sn->stt_up_list, up_next) {
		if (stt_dev->dst_port == port)
			return stt_dev;
	}
	return NULL;
}

static __be32 ack_seq(void)
{
#if NR_CPUS <= 65536
	u32 pkt_seq, ack;

	pkt_seq = this_cpu_read(pkt_seq_counter);
	ack = pkt_seq << ilog2(NR_CPUS) | smp_processor_id();
	this_cpu_inc(pkt_seq_counter);

	return (__force __be32)ack;
#else
#error "Support for greater than 64k CPUs not implemented"
#endif
}

static int clear_gso(struct sk_buff *skb)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	int err;

	if (shinfo->gso_type == 0 && shinfo->gso_size == 0 &&
	    shinfo->gso_segs == 0)
		return 0;

	err = skb_unclone(skb, GFP_ATOMIC);
	if (unlikely(err))
		return err;

	shinfo = skb_shinfo(skb);
	shinfo->gso_type = 0;
	shinfo->gso_size = 0;
	shinfo->gso_segs = 0;
	return 0;
}

static void copy_skb_metadata(struct sk_buff *to, struct sk_buff *from)
{
	to->protocol = from->protocol;
	to->tstamp = from->tstamp;
	to->priority = from->priority;
	to->mark = from->mark;
	to->vlan_tci = from->vlan_tci;
	to->vlan_proto = from->vlan_proto;
	skb_copy_secmark(to, from);
}

static void update_headers(struct sk_buff *skb, bool head,
			       unsigned int l4_offset, unsigned int hdr_len,
			       bool ipv4, u32 tcp_seq)
{
	u16 old_len, new_len;
	__be32 delta;
	struct tcphdr *tcph;
	int gso_size;

	if (ipv4) {
		struct iphdr *iph = (struct iphdr *)(skb->data + ETH_HLEN);

		old_len = ntohs(iph->tot_len);
		new_len = skb->len - ETH_HLEN;
		iph->tot_len = htons(new_len);

		ip_send_check(iph);
	} else {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(skb->data + ETH_HLEN);

		old_len = ntohs(ip6h->payload_len);
		new_len = skb->len - ETH_HLEN - sizeof(struct ipv6hdr);
		ip6h->payload_len = htons(new_len);
	}

	tcph = (struct tcphdr *)(skb->data + l4_offset);
	if (!head) {
		tcph->seq = htonl(tcp_seq);
		tcph->cwr = 0;
	}

	if (skb->next) {
		tcph->fin = 0;
		tcph->psh = 0;
	}

	delta = htonl(~old_len + new_len);
	tcph->check = ~csum_fold((__force __wsum)((__force u32)tcph->check +
				 (__force u32)delta));

	gso_size = skb_shinfo(skb)->gso_size;
	if (gso_size && skb->len - hdr_len <= gso_size)
		BUG_ON(clear_gso(skb));
}

static bool can_segment(struct sk_buff *head, bool ipv4, bool tcp, bool csum_partial)
{
	/* If no offloading is in use then we don't have enough information
	 * to process the headers.
	 */
	if (!csum_partial)
		goto linearize;

	/* Handling UDP packets requires IP fragmentation, which means that
	 * the L4 checksum can no longer be calculated by hardware (since the
	 * fragments are in different packets.  If we have to compute the
	 * checksum it's faster just to linearize and large UDP packets are
	 * pretty uncommon anyways, so it's not worth dealing with for now.
	 */
	if (!tcp)
		goto linearize;

	if (ipv4) {
		struct iphdr *iph = (struct iphdr *)(head->data + ETH_HLEN);

		/* It's difficult to get the IP IDs exactly right here due to
		 * varying segment sizes and potentially multiple layers of
		 * segmentation.  IP ID isn't important when DF is set and DF
		 * is generally set for TCP packets, so just linearize if it's
		 * not.
		 */
		if (!(iph->frag_off & htons(IP_DF)))
			goto linearize;
	} else {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(head->data + ETH_HLEN);

		/* Jumbograms require more processing to update and we'll
		 * probably never see them, so just linearize.
		 */
		if (ip6h->payload_len == 0)
			goto linearize;
	}
	return true;

linearize:
	return false;
}

static int copy_headers(struct sk_buff *head, struct sk_buff *frag,
			    int hdr_len)
{
	u16 csum_start;

	if (skb_cloned(frag) || skb_headroom(frag) < hdr_len) {
		int extra_head = hdr_len - skb_headroom(frag);

		extra_head = extra_head > 0 ? extra_head : 0;
		if (unlikely(pskb_expand_head(frag, extra_head, 0,
					      GFP_ATOMIC)))
			return -ENOMEM;
	}

	memcpy(__skb_push(frag, hdr_len), head->data, hdr_len);

	csum_start = head->csum_start - skb_headroom(head);
	frag->csum_start = skb_headroom(frag) + csum_start;
	frag->csum_offset = head->csum_offset;
	frag->ip_summed = head->ip_summed;

	skb_shinfo(frag)->gso_size = skb_shinfo(head)->gso_size;
	skb_shinfo(frag)->gso_type = skb_shinfo(head)->gso_type;
	skb_shinfo(frag)->gso_segs = 0;

	copy_skb_metadata(frag, head);
	return 0;
}

static int skb_list_segment(struct sk_buff *head, bool ipv4, int l4_offset)
{
	struct sk_buff *skb;
	struct tcphdr *tcph;
	int seg_len;
	int hdr_len;
	int tcp_len;
	u32 seq;

	if (unlikely(!pskb_may_pull(head, l4_offset + sizeof(*tcph))))
		return -ENOMEM;

	tcph = (struct tcphdr *)(head->data + l4_offset);
	tcp_len = tcph->doff * 4;
	hdr_len = l4_offset + tcp_len;

	if (unlikely((tcp_len < sizeof(struct tcphdr)) ||
		     (head->len < hdr_len)))
		return -EINVAL;

	if (unlikely(!pskb_may_pull(head, hdr_len)))
		return -ENOMEM;

	tcph = (struct tcphdr *)(head->data + l4_offset);
	/* Update header of each segment. */
	seq = ntohl(tcph->seq);
	seg_len = skb_pagelen(head) - hdr_len;

	skb = skb_shinfo(head)->frag_list;
	skb_shinfo(head)->frag_list = NULL;
	head->next = skb;
	for (; skb; skb = skb->next) {
		int err;

		head->len -= skb->len;
		head->data_len -= skb->len;
		head->truesize -= skb->truesize;

		seq += seg_len;
		seg_len = skb->len;
		err = copy_headers(head, skb, hdr_len);
		if (err)
			return err;
		update_headers(skb, false, l4_offset, hdr_len, ipv4, seq);
	}
	update_headers(head, true, l4_offset, hdr_len, ipv4, 0);
	return 0;
}

#ifndef SKIP_ZERO_COPY
static struct sk_buff *normalize_frag_list(struct sk_buff *head,
					   struct sk_buff **skbp)
{
	struct sk_buff *skb = *skbp;
	struct sk_buff *last;

	do {
		struct sk_buff *frags;

		if (skb_shared(skb)) {
			struct sk_buff *nskb = skb_clone(skb, GFP_ATOMIC);

			if (unlikely(!nskb))
				return ERR_PTR(-ENOMEM);

			nskb->next = skb->next;
			consume_skb(skb);
			skb = nskb;
			*skbp = skb;
		}

		if (head) {
			head->len -= skb->len;
			head->data_len -= skb->len;
			head->truesize -= skb->truesize;
		}

		frags = skb_shinfo(skb)->frag_list;
		if (frags) {
			int err;

			err = skb_unclone(skb, GFP_ATOMIC);
			if (unlikely(err))
				return ERR_PTR(err);

			last = normalize_frag_list(skb, &frags);
			if (IS_ERR(last))
				return last;

			skb_shinfo(skb)->frag_list = NULL;
			last->next = skb->next;
			skb->next = frags;
		} else {
			last = skb;
		}

		skbp = &skb->next;
	} while ((skb = skb->next));

	return last;
}

/* Takes a linked list of skbs, which potentially contain frag_list
 * (whose members in turn potentially contain frag_lists, etc.) and
 * converts them into a single linear linked list.
 */
static int straighten_frag_list(struct sk_buff **skbp)
{
	struct sk_buff *err_skb;

	err_skb = normalize_frag_list(NULL, skbp);
	if (IS_ERR(err_skb))
		return PTR_ERR(err_skb);

	return 0;
}

static int coalesce_skb(struct sk_buff **headp)
{
	struct sk_buff *frag, *head, *prev;
	int err;

	err = straighten_frag_list(headp);
	if (unlikely(err))
		return err;
	head = *headp;

	/* Coalesce frag list. */
	prev = head;
	for (frag = head->next; frag; frag = frag->next) {
		bool headstolen;
		int delta;

		if (unlikely(skb_unclone(prev, GFP_ATOMIC)))
			return -ENOMEM;

		if (!skb_try_coalesce(prev, frag, &headstolen, &delta)) {
			prev = frag;
			continue;
		}

		prev->next = frag->next;
		frag->len = 0;
		frag->data_len = 0;
		frag->truesize -= delta;
		kfree_skb_partial(frag, headstolen);
		frag = prev;
	}

	if (!head->next)
		return 0;

	for (frag = head->next; frag; frag = frag->next) {
		head->len += frag->len;
		head->data_len += frag->len;
		head->truesize += frag->truesize;
	}

	skb_shinfo(head)->frag_list = head->next;
	head->next = NULL;
	return 0;
}
#else
static int coalesce_skb(struct sk_buff **headp)
{
	struct sk_buff *frag, *head = *headp, *next;
	int delta = FRAG_CB(head)->first.tot_len - skb_headlen(head);
	int err;

	if (unlikely(!head->next))
		return 0;

	err = pskb_expand_head(head, 0, delta, GFP_ATOMIC);
	if (unlikely(err))
		return err;

	if (unlikely(!__pskb_pull_tail(head, head->data_len)))
		BUG();

	for (frag = head->next; frag; frag = next) {
		skb_copy_bits(frag, 0, skb_put(head, frag->len), frag->len);
		next = frag->next;
		kfree_skb(frag);
	}

	head->next = NULL;
	head->truesize = SKB_TRUESIZE(head->len);
	return 0;
}
#endif

static int __try_to_segment(struct sk_buff *skb, bool csum_partial,
			    bool ipv4, bool tcp, int l4_offset)
{
	if (can_segment(skb, ipv4, tcp, csum_partial))
		return skb_list_segment(skb, ipv4, l4_offset);
	else
		return skb_linearize(skb);
}

static int try_to_segment(struct sk_buff *skb)
{
#ifdef SKIP_ZERO_COPY
	/* coalesce_skb() since does not generate frag-list no need to
	 * linearize it here.
	 */
	return 0;
#else
	struct stthdr *stth = stt_hdr(skb);
	bool csum_partial = !!(stth->flags & STT_CSUM_PARTIAL);
	bool ipv4 = !!(stth->flags & STT_PROTO_IPV4);
	bool tcp = !!(stth->flags & STT_PROTO_TCP);
	int l4_offset = stth->l4_offset;

	return __try_to_segment(skb, csum_partial, ipv4, tcp, l4_offset);
#endif
}

static int segment_skb(struct sk_buff **headp, bool csum_partial,
		       bool ipv4, bool tcp, int l4_offset)
{
#ifndef SKIP_ZERO_COPY
	int err;

	err = coalesce_skb(headp);
	if (err)
		return err;
#endif

	if (skb_shinfo(*headp)->frag_list)
		return __try_to_segment(*headp, csum_partial,
					ipv4, tcp, l4_offset);
	return 0;
}

static int __push_stt_header(struct sk_buff *skb, __be64 tun_id,
			     __be16 s_port, __be16 d_port,
			     __be32 saddr, __be32 dst,
			     __be16 l3_proto, u8 l4_proto,
			     int dst_mtu)
{
	int data_len = skb->len + sizeof(struct stthdr) + STT_ETH_PAD;
	unsigned short encap_mss;
	struct tcphdr *tcph;
	struct stthdr *stth;

	skb_push(skb, STT_HEADER_LEN);
	skb_reset_transport_header(skb);
	tcph = tcp_hdr(skb);
	memset(tcph, 0, STT_HEADER_LEN);
	stth = stt_hdr(skb);

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		stth->flags |= STT_CSUM_PARTIAL;

		stth->l4_offset = skb->csum_start -
					(skb_headroom(skb) +
					STT_HEADER_LEN);

		if (l3_proto == htons(ETH_P_IP))
			stth->flags |= STT_PROTO_IPV4;

		if (l4_proto == IPPROTO_TCP)
			stth->flags |= STT_PROTO_TCP;

		stth->mss = htons(skb_shinfo(skb)->gso_size);
	} else if (skb->ip_summed == CHECKSUM_UNNECESSARY) {
		stth->flags |= STT_CSUM_VERIFIED;
	}

	stth->vlan_tci = htons(skb->vlan_tci);
	skb->vlan_tci = 0;
	put_unaligned(tun_id, &stth->key);

	tcph->source	= s_port;
	tcph->dest	= d_port;
	tcph->doff	= sizeof(struct tcphdr) / 4;
	tcph->ack	= 1;
	tcph->psh	= 1;
	tcph->window	= htons(USHRT_MAX);
	tcph->seq	= htonl(data_len << STT_SEQ_LEN_SHIFT);
	tcph->ack_seq	= ack_seq();
	tcph->check	= ~tcp_v4_check(skb->len, saddr, dst, 0);

	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb->ip_summed = CHECKSUM_PARTIAL;

	encap_mss = dst_mtu - sizeof(struct iphdr) - sizeof(struct tcphdr);
	if (data_len > encap_mss) {
		if (unlikely(skb_unclone(skb, GFP_ATOMIC)))
			return -EINVAL;

		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
		skb_shinfo(skb)->gso_size = encap_mss;
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(data_len, encap_mss);
	} else {
		if (unlikely(clear_gso(skb)))
			return -EINVAL;
	}
	return 0;
}

static struct sk_buff *push_stt_header(struct sk_buff *head, __be64 tun_id,
				       __be16 s_port, __be16 d_port,
				       __be32 saddr, __be32 dst,
				       __be16 l3_proto, u8 l4_proto,
				       int dst_mtu)
{
	struct sk_buff *skb;

	if (skb_shinfo(head)->frag_list) {
		bool ipv4 = (l3_proto == htons(ETH_P_IP));
		bool tcp = (l4_proto == IPPROTO_TCP);
		bool csum_partial = (head->ip_summed == CHECKSUM_PARTIAL);
		int l4_offset = skb_transport_offset(head);

		/* Need to call skb_orphan() to report currect true-size.
		 * calling skb_orphan() in this layer is odd but SKB with
		 * frag-list should not be associated with any socket, so
		 * skb-orphan should be no-op. */
		skb_orphan(head);
		if (unlikely(segment_skb(&head, csum_partial,
					 ipv4, tcp, l4_offset)))
			goto error;
	}

	for (skb = head; skb; skb = skb->next) {
		if (__push_stt_header(skb, tun_id, s_port, d_port, saddr, dst,
				      l3_proto, l4_proto, dst_mtu))
			goto error;
	}

	return head;
error:
	kfree_skb_list(head);
	return NULL;
}

static int stt_can_offload(struct sk_buff *skb, __be16 l3_proto, u8 l4_proto)
{
	if (skb_is_gso(skb) && skb->ip_summed != CHECKSUM_PARTIAL) {
		int csum_offset;
		__sum16 *csum;
		int len;

		if (l4_proto == IPPROTO_TCP)
			csum_offset = offsetof(struct tcphdr, check);
		else if (l4_proto == IPPROTO_UDP)
			csum_offset = offsetof(struct udphdr, check);
		else
			return 0;

		len = skb->len - skb_transport_offset(skb);
		csum = (__sum16 *)(skb_transport_header(skb) + csum_offset);

		if (unlikely(!pskb_may_pull(skb, skb_transport_offset(skb) +
						 csum_offset + sizeof(*csum))))
			return -EINVAL;

		if (l3_proto == htons(ETH_P_IP)) {
			struct iphdr *iph = ip_hdr(skb);

			*csum = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
						   len, l4_proto, 0);
		} else if (l3_proto == htons(ETH_P_IPV6)) {
			struct ipv6hdr *ip6h = ipv6_hdr(skb);

			*csum = ~csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
						 len, l4_proto, 0);
		} else {
			return 0;
		}
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = csum_offset;
		skb->ip_summed = CHECKSUM_PARTIAL;
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		/* Assume receiver can only offload TCP/UDP over IPv4/6,
		 * and require 802.1Q VLANs to be accelerated.
		 */
		if (l3_proto != htons(ETH_P_IP) &&
		    l3_proto != htons(ETH_P_IPV6))
			return 0;

		if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP)
			return 0;

		/* L4 offset must fit in a 1-byte field. */
		if (skb->csum_start - skb_headroom(skb) > 255)
			return 0;

		if (skb_shinfo(skb)->gso_type & ~SUPPORTED_GSO_TYPES)
			return 0;
	}
	/* Total size of encapsulated packet must fit in 16 bits. */
	if (skb->len + STT_HEADER_LEN + sizeof(struct iphdr) > 65535)
		return 0;

	if (skb_vlan_tag_present(skb) && skb->vlan_proto != htons(ETH_P_8021Q))
		return 0;
	return 1;
}

static bool need_linearize(const struct sk_buff *skb)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	int i;

	if (unlikely(shinfo->frag_list))
		return true;

	/* Generally speaking we should linearize if there are paged frags.
	 * However, if all of the refcounts are 1 we know nobody else can
	 * change them from underneath us and we can skip the linearization.
	 */
	for (i = 0; i < shinfo->nr_frags; i++)
		if (unlikely(page_count(skb_frag_page(&shinfo->frags[i])) > 1))
			return true;

	return false;
}

static struct sk_buff *handle_offloads(struct sk_buff *skb, int min_headroom)
{
	int err;

	if (skb_vlan_tag_present(skb) && skb->vlan_proto != htons(ETH_P_8021Q)) {

		min_headroom += VLAN_HLEN;
		if (skb_headroom(skb) < min_headroom) {
			int head_delta = SKB_DATA_ALIGN(min_headroom -
							skb_headroom(skb) + 16);

			err = pskb_expand_head(skb, max_t(int, head_delta, 0),
					       0, GFP_ATOMIC);
			if (unlikely(err))
				goto error;
		}

		skb = __vlan_hwaccel_push_inside(skb);
		if (!skb) {
			err = -ENOMEM;
			goto error;
		}
	}

	if (skb_is_gso(skb)) {
		struct sk_buff *nskb;
		char cb[sizeof(skb->cb)];

		memcpy(cb, skb->cb, sizeof(cb));

		nskb = __skb_gso_segment(skb, 0, false);
		if (IS_ERR(nskb)) {
			err = PTR_ERR(nskb);
			goto error;
		}

		consume_skb(skb);
		skb = nskb;
		while (nskb) {
			memcpy(nskb->cb, cb, sizeof(cb));
			nskb = nskb->next;
		}
	} else if (skb->ip_summed == CHECKSUM_PARTIAL) {
		/* Pages aren't locked and could change at any time.
		 * If this happens after we compute the checksum, the
		 * checksum will be wrong.  We linearize now to avoid
		 * this problem.
		 */
		if (unlikely(need_linearize(skb))) {
			err = __skb_linearize(skb);
			if (unlikely(err))
				goto error;
		}

		err = skb_checksum_help(skb);
		if (unlikely(err))
			goto error;
	}
	skb->ip_summed = CHECKSUM_NONE;

	return skb;
error:
	kfree_skb(skb);
	return ERR_PTR(err);
}

static void skb_list_xmit(struct rtable *rt, struct sk_buff *skb, __be32 src,
			  __be32 dst, __u8 tos, __u8 ttl, __be16 df)
{
	while (skb) {
		struct sk_buff *next = skb->next;

		if (next)
			dst_clone(&rt->dst);

		skb->next = NULL;
		iptunnel_xmit(NULL, rt, skb, src, dst, IPPROTO_TCP,
			      tos, ttl, df, false);

		skb = next;
	}
}

static u8 parse_ipv6_l4_proto(struct sk_buff *skb)
{
	unsigned int nh_ofs = skb_network_offset(skb);
	int payload_ofs;
	struct ipv6hdr *nh;
	uint8_t nexthdr;
	__be16 frag_off;

	if (unlikely(!pskb_may_pull(skb, nh_ofs + sizeof(struct ipv6hdr))))
		return 0;

	nh = ipv6_hdr(skb);
	nexthdr = nh->nexthdr;
	payload_ofs = (u8 *)(nh + 1) - skb->data;

	payload_ofs = ipv6_skip_exthdr(skb, payload_ofs, &nexthdr, &frag_off);
	if (unlikely(payload_ofs < 0))
		return 0;

	return nexthdr;
}

static u8 skb_get_l4_proto(struct sk_buff *skb, __be16 l3_proto)
{
	if (l3_proto == htons(ETH_P_IP)) {
		unsigned int nh_ofs = skb_network_offset(skb);

		if (unlikely(!pskb_may_pull(skb, nh_ofs + sizeof(struct iphdr))))
			return 0;

		return ip_hdr(skb)->protocol;
	} else if (l3_proto == htons(ETH_P_IPV6)) {
		return parse_ipv6_l4_proto(skb);
	}
	return 0;
}

static int stt_xmit_skb(struct sk_buff *skb, struct rtable *rt,
			__be32 src, __be32 dst, __u8 tos,
			__u8 ttl, __be16 df, __be16 src_port, __be16 dst_port,
			__be64 tun_id)
{
	struct ethhdr *eh = eth_hdr(skb);
	int ret = 0, min_headroom;
	__be16 inner_l3_proto;
	 u8 inner_l4_proto;

	inner_l3_proto = eh->h_proto;
	inner_l4_proto = skb_get_l4_proto(skb, inner_l3_proto);

	min_headroom = LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len
			+ STT_HEADER_LEN + sizeof(struct iphdr);

	if (skb_headroom(skb) < min_headroom || skb_header_cloned(skb)) {
		int head_delta = SKB_DATA_ALIGN(min_headroom -
						skb_headroom(skb) +
						16);

		ret = pskb_expand_head(skb, max_t(int, head_delta, 0),
				       0, GFP_ATOMIC);
		if (unlikely(ret))
			goto err_free_rt;
	}

	ret = stt_can_offload(skb, inner_l3_proto, inner_l4_proto);
	if (ret < 0)
		goto err_free_rt;
	if (!ret) {
		skb = handle_offloads(skb, min_headroom);
		if (IS_ERR(skb)) {
			ret = PTR_ERR(skb);
			skb = NULL;
			goto err_free_rt;
		}
	}

	ret = 0;
	while (skb) {
		struct sk_buff *next_skb = skb->next;

		skb->next = NULL;

		if (next_skb)
			dst_clone(&rt->dst);

		/* Push STT and TCP header. */
		skb = push_stt_header(skb, tun_id, src_port, dst_port, src,
				      dst, inner_l3_proto, inner_l4_proto,
				      dst_mtu(&rt->dst));
		if (unlikely(!skb)) {
			ip_rt_put(rt);
			goto next;
		}

		/* Push IP header. */
		skb_list_xmit(rt, skb, src, dst, tos, ttl, df);

next:
		skb = next_skb;
	}

	return 0;

err_free_rt:
	ip_rt_put(rt);
	kfree_skb(skb);
	return ret;
}

static struct rtable *stt_get_rt(struct sk_buff *skb,
				 struct net_device *dev,
				 struct flowi4 *fl,
				 const struct ip_tunnel_key *key)
{
	struct net *net = dev_net(dev);

	/* Route lookup */
	memset(fl, 0, sizeof(*fl));
	fl->daddr = key->u.ipv4.dst;
	fl->saddr = key->u.ipv4.src;
	fl->flowi4_tos = RT_TOS(key->tos);
	fl->flowi4_mark = skb->mark;
	fl->flowi4_proto = IPPROTO_TCP;

	return ip_route_output_key(net, fl);
}

netdev_tx_t ovs_stt_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct stt_dev *stt_dev = netdev_priv(dev);
	struct net *net = stt_dev->net;
	__be16 dport = stt_dev->dst_port;
	struct ip_tunnel_key *tun_key;
	struct ip_tunnel_info *tun_info;
	struct rtable *rt;
	struct flowi4 fl;
	__be16 sport;
	__be16 df;
	int err;

	tun_info = skb_tunnel_info(skb);
	if (unlikely(!tun_info)) {
		err = -EINVAL;
		goto error;
	}

	tun_key = &tun_info->key;

	rt = stt_get_rt(skb, dev, &fl, tun_key);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto error;
	}

	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;
	sport = udp_flow_src_port(net, skb, 1, USHRT_MAX, true);
	skb->ignore_df = 1;

	stt_xmit_skb(skb, rt, fl.saddr, tun_key->u.ipv4.dst,
		    tun_key->tos, tun_key->ttl,
		    df, sport, dport, tun_key->tun_id);
	return NETDEV_TX_OK;
error:
	kfree_skb(skb);
	dev->stats.tx_errors++;
	return NETDEV_TX_OK;
}
EXPORT_SYMBOL(ovs_stt_xmit);

static void free_frag(struct stt_percpu *stt_percpu,
		      struct pkt_frag *frag)
{
	stt_percpu->frag_mem_used -= FRAG_CB(frag->skbs)->first.mem_used;
	kfree_skb_list(frag->skbs);
	list_del(&frag->lru_node);
	frag->skbs = NULL;
}

static void evict_frags(struct stt_percpu *stt_percpu)
{
	while (!list_empty(&stt_percpu->frag_lru) &&
	       stt_percpu->frag_mem_used > REASM_LO_THRESH) {
		struct pkt_frag *frag;

		frag = list_first_entry(&stt_percpu->frag_lru,
					struct pkt_frag,
					lru_node);
		free_frag(stt_percpu, frag);
	}
}

static bool pkt_key_match(struct net *net,
			  const struct pkt_frag *a, const struct pkt_key *b)
{
	return a->key.saddr == b->saddr && a->key.daddr == b->daddr &&
	       a->key.pkt_seq == b->pkt_seq && a->key.mark == b->mark &&
	       net_eq(dev_net(a->skbs->dev), net);
}

static u32 pkt_key_hash(const struct net *net, const struct pkt_key *key)
{
	u32 initval = frag_hash_seed ^ (u32)(unsigned long)net ^ key->mark;

	return jhash_3words((__force u32)key->saddr, (__force u32)key->daddr,
			    (__force u32)key->pkt_seq, initval);
}

static struct pkt_frag *lookup_frag(struct net *net,
				    struct stt_percpu *stt_percpu,
				    const struct pkt_key *key, u32 hash)
{
	struct pkt_frag *frag, *victim_frag = NULL;
	int i;

	for (i = 0; i < FRAG_HASH_SEGS; i++) {
		frag = flex_array_get(stt_percpu->frag_hash,
				      hash & (FRAG_HASH_ENTRIES - 1));

		if (frag->skbs &&
		    time_before(jiffies, frag->timestamp + FRAG_EXP_TIME) &&
		    pkt_key_match(net, frag, key))
			return frag;

		if (!victim_frag ||
		    (victim_frag->skbs &&
		     (!frag->skbs ||
		      time_before(frag->timestamp, victim_frag->timestamp))))
			victim_frag = frag;

		hash >>= FRAG_HASH_SHIFT;
	}

	if (victim_frag->skbs)
		free_frag(stt_percpu, victim_frag);

	return victim_frag;
}

#ifdef SKIP_ZERO_COPY
static int __copy_skb(struct sk_buff *to, struct sk_buff *from,
		      int *delta, bool *headstolen)
{
	int err;

	if (unlikely(to->next))
		return -EINVAL;

	if (unlikely(FRAG_CB(to)->offset))
		return -EINVAL;

	if (unlikely(skb_unclone(to, GFP_ATOMIC)))
		return -ENOMEM;

	if (skb_try_coalesce(to, from, headstolen, delta))
		return 0;

	*headstolen = false;
	err = pskb_expand_head(to, 0, to->data_len + from->len, GFP_ATOMIC);
	if (unlikely(err))
		return err;

	if (unlikely(!__pskb_pull_tail(to, to->data_len)))
		BUG();

	skb_copy_bits(from, 0, skb_put(to, from->len), from->len);

	*delta = from->len;
	to->truesize += from->len;
	return 0;
}
#else
static int __copy_skb(struct sk_buff *to, struct sk_buff *from,
		      int *delta, bool *headstolen)
{
	*headstolen = false;
	return -EINVAL;
}
#endif

static struct sk_buff *reassemble(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(skb);
	u32 seq = ntohl(tcph->seq);
	struct stt_percpu *stt_percpu;
	struct sk_buff *last_skb, *copied_skb = NULL;
	struct pkt_frag *frag;
	struct pkt_key key;
	int tot_len, delta = skb->truesize;
	bool headstolen;
	u32 hash;

	tot_len = seq >> STT_SEQ_LEN_SHIFT;
	FRAG_CB(skb)->offset = seq & STT_SEQ_OFFSET_MASK;

	if (unlikely(skb->len == 0))
		goto out_free;

	if (unlikely(FRAG_CB(skb)->offset + skb->len > tot_len))
		goto out_free;

	if (tot_len == skb->len)
		goto out;

	key.saddr = iph->saddr;
	key.daddr = iph->daddr;
	key.pkt_seq = tcph->ack_seq;
	key.mark = skb->mark;
	hash = pkt_key_hash(dev_net(skb->dev), &key);

	stt_percpu = per_cpu_ptr(stt_percpu_data, smp_processor_id());

	spin_lock(&stt_percpu->lock);

	if (unlikely(stt_percpu->frag_mem_used + skb->truesize > REASM_HI_THRESH))
		evict_frags(stt_percpu);

	frag = lookup_frag(dev_net(skb->dev), stt_percpu, &key, hash);
	if (!frag->skbs) {
		frag->skbs = skb;
		frag->key = key;
		frag->timestamp = jiffies;
		FRAG_CB(skb)->first.last_skb = skb;
		FRAG_CB(skb)->first.mem_used = skb->truesize;
		FRAG_CB(skb)->first.tot_len = tot_len;
		FRAG_CB(skb)->first.rcvd_len = skb->len;
		FRAG_CB(skb)->first.set_ecn_ce = false;
		list_add_tail(&frag->lru_node, &stt_percpu->frag_lru);
		stt_percpu->frag_mem_used += skb->truesize;
		skb = NULL;
		goto unlock;
	}

	/* Optimize for the common case where fragments are received in-order
	 * and not overlapping.
	 */
	last_skb = FRAG_CB(frag->skbs)->first.last_skb;
	if (likely(FRAG_CB(last_skb)->offset + last_skb->len ==
		   FRAG_CB(skb)->offset)) {

		if (!__copy_skb(frag->skbs, skb, &delta, &headstolen)) {
			copied_skb = skb;
		} else {
			last_skb->next = skb;
			FRAG_CB(frag->skbs)->first.last_skb = skb;
		}
	} else {
		struct sk_buff *prev = NULL, *next;

		for (next = frag->skbs; next; next = next->next) {
			if (FRAG_CB(next)->offset >= FRAG_CB(skb)->offset)
				break;
			prev = next;
		}

		/* Overlapping fragments aren't allowed.  We shouldn't start
		 * before the end of the previous fragment.
		 */
		if (prev &&
		    FRAG_CB(prev)->offset + prev->len > FRAG_CB(skb)->offset)
			goto unlock_free;

		/* We also shouldn't end after the beginning of the next
		 * fragment.
		 */
		if (next &&
		    FRAG_CB(skb)->offset + skb->len > FRAG_CB(next)->offset)
			goto unlock_free;

		if (prev) {
			prev->next = skb;
		} else {
			FRAG_CB(skb)->first = FRAG_CB(frag->skbs)->first;
			frag->skbs = skb;
		}

		if (next)
			skb->next = next;
		else
			FRAG_CB(frag->skbs)->first.last_skb = skb;
	}

	FRAG_CB(frag->skbs)->first.set_ecn_ce |= INET_ECN_is_ce(iph->tos);
	FRAG_CB(frag->skbs)->first.rcvd_len += skb->len;
	stt_percpu->frag_mem_used += delta;
	FRAG_CB(frag->skbs)->first.mem_used += delta;

	if (FRAG_CB(frag->skbs)->first.tot_len ==
	    FRAG_CB(frag->skbs)->first.rcvd_len) {
		struct sk_buff *frag_head = frag->skbs;

		frag_head->tstamp = skb->tstamp;
		if (FRAG_CB(frag_head)->first.set_ecn_ce)
			INET_ECN_set_ce(frag_head);

		list_del(&frag->lru_node);
		stt_percpu->frag_mem_used -= FRAG_CB(frag_head)->first.mem_used;
		frag->skbs = NULL;
		skb = frag_head;
	} else {
		list_move_tail(&frag->lru_node, &stt_percpu->frag_lru);
		skb = NULL;
	}

	if (copied_skb)
		kfree_skb_partial(copied_skb, headstolen);
	goto unlock;

unlock_free:
	kfree_skb(skb);
	skb = NULL;
unlock:
	spin_unlock(&stt_percpu->lock);
	return skb;
out_free:
	kfree_skb(skb);
	skb = NULL;
out:
	return skb;
}

static bool validate_checksum(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	if (skb_csum_unnecessary(skb))
		return true;

	if (skb->ip_summed == CHECKSUM_COMPLETE &&
	    !tcp_v4_check(skb->len, iph->saddr, iph->daddr, skb->csum))
		return true;

	skb->csum = csum_tcpudp_nofold(iph->saddr, iph->daddr, skb->len,
				       IPPROTO_TCP, 0);

	return __tcp_checksum_complete(skb) == 0;
}

static bool set_offloads(struct sk_buff *skb)
{
	struct stthdr *stth = stt_hdr(skb);
	unsigned int gso_type = 0;
	int l3_header_size;
	int l4_header_size;
	u16 csum_offset;
	u8 proto_type;

	if (stth->vlan_tci)
		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
				       ntohs(stth->vlan_tci));

	if (!(stth->flags & STT_CSUM_PARTIAL)) {
		if (stth->flags & STT_CSUM_VERIFIED)
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		else
			skb->ip_summed = CHECKSUM_NONE;

		return clear_gso(skb) == 0;
	}

	proto_type = stth->flags & STT_PROTO_TYPES;

	switch (proto_type) {
	case (STT_PROTO_IPV4 | STT_PROTO_TCP):
		/* TCP/IPv4 */
		csum_offset = offsetof(struct tcphdr, check);
		gso_type = SKB_GSO_TCPV4;
		l3_header_size = sizeof(struct iphdr);
		l4_header_size = sizeof(struct tcphdr);
		skb->protocol = htons(ETH_P_IP);
		break;
	case STT_PROTO_TCP:
		/* TCP/IPv6 */
		csum_offset = offsetof(struct tcphdr, check);
		gso_type = SKB_GSO_TCPV6;
		l3_header_size = sizeof(struct ipv6hdr);
		l4_header_size = sizeof(struct tcphdr);
		skb->protocol = htons(ETH_P_IPV6);
		break;
	case STT_PROTO_IPV4:
		/* UDP/IPv4 */
		csum_offset = offsetof(struct udphdr, check);
#ifdef HAVE_SKB_GSO_UDP
		gso_type = SKB_GSO_UDP;
#endif
		l3_header_size = sizeof(struct iphdr);
		l4_header_size = sizeof(struct udphdr);
		skb->protocol = htons(ETH_P_IP);
		break;
	default:
		/* UDP/IPv6 */
		csum_offset = offsetof(struct udphdr, check);
#ifdef HAVE_SKB_GSO_UDP
		gso_type = SKB_GSO_UDP;
#endif
		l3_header_size = sizeof(struct ipv6hdr);
		l4_header_size = sizeof(struct udphdr);
		skb->protocol = htons(ETH_P_IPV6);
	}

	if (unlikely(stth->l4_offset < ETH_HLEN + l3_header_size))
		return false;

	if (unlikely(!pskb_may_pull(skb, stth->l4_offset + l4_header_size)))
		return false;

	stth = stt_hdr(skb);

	skb->csum_start = skb_headroom(skb) + stth->l4_offset;
	skb->csum_offset = csum_offset;
	skb->ip_summed = CHECKSUM_PARTIAL;

	if (stth->mss) {
		if (unlikely(skb_unclone(skb, GFP_ATOMIC)))
			return false;

		skb_shinfo(skb)->gso_type = gso_type | SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_size = ntohs(stth->mss);
		skb_shinfo(skb)->gso_segs = 0;
	} else {
		if (unlikely(clear_gso(skb)))
			return false;
	}

	return true;
}

static void rcv_list(struct net_device *dev, struct sk_buff *skb,
		     struct metadata_dst *tun_dst)
{
	struct sk_buff *next;

	do {
		next = skb->next;
		skb->next = NULL;
		if (next) {
			ovs_dst_hold((struct dst_entry *)tun_dst);
			ovs_skb_dst_set(next, (struct dst_entry *)tun_dst);
		}
		ovs_ip_tunnel_rcv(dev, skb, tun_dst);
	} while ((skb = next));
}

#ifndef USE_UPSTREAM_TUNNEL
static int __stt_rcv(struct stt_dev *stt_dev, struct sk_buff *skb)
{
	struct metadata_dst tun_dst;

	ovs_ip_tun_rx_dst(&tun_dst, skb, TUNNEL_KEY | TUNNEL_CSUM,
			  get_unaligned(&stt_hdr(skb)->key), 0);
	tun_dst.u.tun_info.key.tp_src = tcp_hdr(skb)->source;
	tun_dst.u.tun_info.key.tp_dst = tcp_hdr(skb)->dest;

	rcv_list(stt_dev->dev, skb, &tun_dst);
	return 0;
}
#else
static int __stt_rcv(struct stt_dev *stt_dev, struct sk_buff *skb)
{
	struct metadata_dst *tun_dst;
	__be16 flags;
	__be64 tun_id;

	flags = TUNNEL_KEY | TUNNEL_CSUM;
	tun_id = get_unaligned(&stt_hdr(skb)->key);
	tun_dst = ip_tun_rx_dst(skb, flags, tun_id, 0);
	if (!tun_dst)
		return -ENOMEM;
	tun_dst->u.tun_info.key.tp_src = tcp_hdr(skb)->source;
	tun_dst->u.tun_info.key.tp_dst = tcp_hdr(skb)->dest;

	rcv_list(stt_dev->dev, skb, tun_dst);
	return 0;
}
#endif

static void stt_rcv(struct stt_dev *stt_dev, struct sk_buff *skb)
{
	int err;

	if (unlikely(!validate_checksum(skb)))
		goto drop;

	__skb_pull(skb, sizeof(struct tcphdr));
	skb = reassemble(skb);
	if (!skb)
		return;

	if (skb->next && coalesce_skb(&skb))
		goto drop;

	err = iptunnel_pull_header(skb,
				   sizeof(struct stthdr) + STT_ETH_PAD,
				   htons(ETH_P_TEB),
				   !net_eq(stt_dev->net, dev_net(stt_dev->dev)));
	if (unlikely(err))
		goto drop;

	if (unlikely(stt_hdr(skb)->version != 0))
		goto drop;

	if (unlikely(!set_offloads(skb)))
		goto drop;

	if (skb_shinfo(skb)->frag_list && try_to_segment(skb))
		goto drop;

	err = __stt_rcv(stt_dev, skb);
	if (err)
		goto drop;
	return;
drop:
	/* Consume bad packet */
	kfree_skb_list(skb);
	stt_dev->dev->stats.rx_errors++;
}

static void tcp_sock_release(struct socket *sock)
{
	kernel_sock_shutdown(sock, SHUT_RDWR);
	sock_release(sock);
}

static int tcp_sock_create4(struct net *net, __be16 port,
			    struct socket **sockp)
{
	struct sockaddr_in tcp_addr;
	struct socket *sock = NULL;
	int err;

	err = sock_create_kern(net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (err < 0)
		goto error;

	memset(&tcp_addr, 0, sizeof(tcp_addr));
	tcp_addr.sin_family = AF_INET;
	tcp_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	tcp_addr.sin_port = port;
	err = kernel_bind(sock, (struct sockaddr *)&tcp_addr,
			  sizeof(tcp_addr));
	if (err < 0)
		goto error;

	*sockp = sock;
	return 0;

error:
	if (sock)
		tcp_sock_release(sock);
	*sockp = NULL;
	return err;
}

static void schedule_clean_percpu(void)
{
	schedule_delayed_work(&clean_percpu_wq, CLEAN_PERCPU_INTERVAL);
}

static void clean_percpu(struct work_struct *work)
{
	int i;

	for_each_possible_cpu(i) {
		struct stt_percpu *stt_percpu = per_cpu_ptr(stt_percpu_data, i);
		int j;

		for (j = 0; j < FRAG_HASH_ENTRIES; j++) {
			struct pkt_frag *frag;

			frag = flex_array_get(stt_percpu->frag_hash, j);
			if (!frag->skbs ||
			    time_before(jiffies, frag->timestamp + FRAG_EXP_TIME))
				continue;

			spin_lock_bh(&stt_percpu->lock);

			if (frag->skbs &&
			    time_after(jiffies, frag->timestamp + FRAG_EXP_TIME))
				free_frag(stt_percpu, frag);

			spin_unlock_bh(&stt_percpu->lock);
		}
	}
	schedule_clean_percpu();
}

#ifdef HAVE_NF_HOOKFN_ARG_OPS
#define FIRST_PARAM const struct nf_hook_ops *ops
#else
#ifdef HAVE_NF_HOOKFN_ARG_PRIV
#define FIRST_PARAM void *priv
#else
#define FIRST_PARAM unsigned int hooknum
#endif
#endif

#ifdef HAVE_NF_HOOK_STATE
#if RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,0)
/* RHEL nfhook hacks. */
#ifndef __GENKSYMS__
#define LAST_PARAM const struct net_device *in, const struct net_device *out, \
		   const struct nf_hook_state *state
#else
#define LAST_PARAM const struct net_device *in, const struct net_device *out, \
		   int (*okfn)(struct sk_buff *)
#endif
#else
#define LAST_PARAM const struct nf_hook_state *state
#endif
#else
#define LAST_PARAM const struct net_device *in, const struct net_device *out, \
		   int (*okfn)(struct sk_buff *)
#endif

static unsigned int nf_ip_hook(FIRST_PARAM, struct sk_buff *skb, LAST_PARAM)
{
	struct stt_dev *stt_dev;
	int ip_hdr_len;

	if (ip_hdr(skb)->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	ip_hdr_len = ip_hdrlen(skb);
	if (unlikely(!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr))))
		return NF_ACCEPT;

	skb_set_transport_header(skb, ip_hdr_len);

	stt_dev = stt_find_up_dev(dev_net(skb->dev), tcp_hdr(skb)->dest);
	if (!stt_dev)
		return NF_ACCEPT;

	__skb_pull(skb, ip_hdr_len);
	stt_rcv(stt_dev, skb);
	return NF_STOLEN;
}

static struct nf_hook_ops nf_hook_ops __read_mostly = {
	.hook           = nf_ip_hook,
#ifdef HAVE_NF_HOOKS_OPS_OWNER
	.owner          = THIS_MODULE,
#endif
	.pf             = NFPROTO_IPV4,
	.hooknum        = NF_INET_LOCAL_IN,
	.priority       = INT_MAX,
};

static int stt_start(struct net *net)
{
	struct stt_net *sn = net_generic(net, stt_net_id);
	int err;
	int i;

	if (n_tunnels) {
		n_tunnels++;
		return 0;
	}
	get_random_bytes(&frag_hash_seed, sizeof(u32));

	stt_percpu_data = alloc_percpu(struct stt_percpu);
	if (!stt_percpu_data) {
		err = -ENOMEM;
		goto error;
	}

	for_each_possible_cpu(i) {
		struct stt_percpu *stt_percpu = per_cpu_ptr(stt_percpu_data, i);
		struct flex_array *frag_hash;

		spin_lock_init(&stt_percpu->lock);
		INIT_LIST_HEAD(&stt_percpu->frag_lru);
		get_random_bytes(&per_cpu(pkt_seq_counter, i), sizeof(u32));

		frag_hash = flex_array_alloc(sizeof(struct pkt_frag),
					     FRAG_HASH_ENTRIES,
					     GFP_KERNEL | __GFP_ZERO);
		if (!frag_hash) {
			err = -ENOMEM;
			goto free_percpu;
		}
		stt_percpu->frag_hash = frag_hash;

		err = flex_array_prealloc(stt_percpu->frag_hash, 0,
					  FRAG_HASH_ENTRIES,
					  GFP_KERNEL | __GFP_ZERO);
		if (err)
			goto free_percpu;
	}
	schedule_clean_percpu();
	n_tunnels++;

	if (sn->n_tunnels) {
		sn->n_tunnels++;
		return 0;
	}
#ifdef HAVE_NF_REGISTER_NET_HOOK
	/* On kernel which support per net nf-hook, nf_register_hook() takes
	 * rtnl-lock, which results in dead lock in stt-dev-create. Therefore
	 * use this new API.
	 */

	if (sn->nf_hook_reg_done)
		goto out;

	err = nf_register_net_hook(net, &nf_hook_ops);
	if (!err)
		sn->nf_hook_reg_done = true;
#else
	/* Register STT only on very first STT device addition. */
	if (!list_empty(&nf_hook_ops.list))
		goto out;

	err = nf_register_hook(&nf_hook_ops);
#endif
	if (err)
		goto dec_n_tunnel;
out:
	sn->n_tunnels++;
	return 0;

dec_n_tunnel:
	n_tunnels--;
free_percpu:
	for_each_possible_cpu(i) {
		struct stt_percpu *stt_percpu = per_cpu_ptr(stt_percpu_data, i);

		if (stt_percpu->frag_hash)
			flex_array_free(stt_percpu->frag_hash);
	}

	free_percpu(stt_percpu_data);

error:
	return err;
}

static void stt_cleanup(struct net *net)
{
	struct stt_net *sn = net_generic(net, stt_net_id);
	int i;

	sn->n_tunnels--;
	if (sn->n_tunnels)
		goto out;
out:
	n_tunnels--;
	if (n_tunnels)
		return;

	cancel_delayed_work_sync(&clean_percpu_wq);
	for_each_possible_cpu(i) {
		struct stt_percpu *stt_percpu = per_cpu_ptr(stt_percpu_data, i);
		int j;

		for (j = 0; j < FRAG_HASH_ENTRIES; j++) {
			struct pkt_frag *frag;

			frag = flex_array_get(stt_percpu->frag_hash, j);
			kfree_skb_list(frag->skbs);
		}

		flex_array_free(stt_percpu->frag_hash);
	}

	free_percpu(stt_percpu_data);
}

static netdev_tx_t stt_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
#ifdef USE_UPSTREAM_TUNNEL
	return ovs_stt_xmit(skb);
#else
	/* Drop All packets coming from networking stack. OVS-CB is
	 * not initialized for these packets.
	 */
	dev_kfree_skb(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
#endif
}

/* Setup stats when device is created */
static int stt_init(struct net_device *dev)
{
	dev->tstats = (typeof(dev->tstats)) netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

static void stt_uninit(struct net_device *dev)
{
	free_percpu(dev->tstats);
}

static int stt_open(struct net_device *dev)
{
	struct stt_dev *stt = netdev_priv(dev);
	struct net *net = stt->net;
	struct stt_net *sn = net_generic(net, stt_net_id);
	int err;

	err = stt_start(net);
	if (err)
		return err;

	err = tcp_sock_create4(net, stt->dst_port, &stt->sock);
	if (err)
		return err;
	list_add_rcu(&stt->up_next, &sn->stt_up_list);
	return 0;
}

static int stt_stop(struct net_device *dev)
{
	struct stt_dev *stt_dev = netdev_priv(dev);
	struct net *net = stt_dev->net;

	list_del_rcu(&stt_dev->up_next);
	synchronize_net();
	tcp_sock_release(stt_dev->sock);
	stt_dev->sock = NULL;
	stt_cleanup(net);
	return 0;
}

static int __stt_change_mtu(struct net_device *dev, int new_mtu, bool strict)
{
	int max_mtu = IP_MAX_MTU - STT_HEADER_LEN - sizeof(struct iphdr)
		      - dev->hard_header_len;

	if (new_mtu < 68)
		return -EINVAL;

	if (new_mtu > max_mtu) {
		if (strict)
			return -EINVAL;

		new_mtu = max_mtu;
	}

	dev->mtu = new_mtu;
	return 0;
}

static int stt_change_mtu(struct net_device *dev, int new_mtu)
{
	return __stt_change_mtu(dev, new_mtu, true);
}

int ovs_stt_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb)
{
	struct ip_tunnel_info *info = skb_tunnel_info(skb);
	struct stt_dev *stt_dev = netdev_priv(dev);
	struct net *net = stt_dev->net;
	__be16 dport = stt_dev->dst_port;
	struct flowi4 fl4;
	struct rtable *rt;

	if (ip_tunnel_info_af(info) != AF_INET)
		return -EINVAL;

	rt = stt_get_rt(skb, dev, &fl4, &info->key);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	ip_rt_put(rt);

	info->key.u.ipv4.src = fl4.saddr;
	info->key.tp_src = udp_flow_src_port(net, skb, 1, USHRT_MAX, true);
	info->key.tp_dst = dport;
	return 0;
}
EXPORT_SYMBOL_GPL(ovs_stt_fill_metadata_dst);

static const struct net_device_ops stt_netdev_ops = {
	.ndo_init               = stt_init,
	.ndo_uninit             = stt_uninit,
	.ndo_open               = stt_open,
	.ndo_stop               = stt_stop,
	.ndo_start_xmit         = stt_dev_xmit,
	.ndo_get_stats64        = ip_tunnel_get_stats64,
#ifdef  HAVE_RHEL7_MAX_MTU
	.extended.ndo_change_mtu = stt_change_mtu,
#else
	.ndo_change_mtu         = stt_change_mtu,
#endif
	.ndo_validate_addr      = eth_validate_addr,
	.ndo_set_mac_address    = eth_mac_addr,
#ifdef USE_UPSTREAM_TUNNEL
#ifdef HAVE_NDO_FILL_METADATA_DST
	.ndo_fill_metadata_dst  = stt_fill_metadata_dst,
#endif
#endif
};

static void stt_get_drvinfo(struct net_device *dev,
		struct ethtool_drvinfo *drvinfo)
{
	strlcpy(drvinfo->version, STT_NETDEV_VER, sizeof(drvinfo->version));
	strlcpy(drvinfo->driver, "stt", sizeof(drvinfo->driver));
}

static const struct ethtool_ops stt_ethtool_ops = {
	.get_drvinfo    = stt_get_drvinfo,
	.get_link       = ethtool_op_get_link,
};

/* Info for udev, that this is a virtual tunnel endpoint */
static struct device_type stt_type = {
	.name = "stt",
};

/* Initialize the device structure. */
static void stt_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->netdev_ops = &stt_netdev_ops;
	dev->ethtool_ops = &stt_ethtool_ops;
#ifndef HAVE_NEEDS_FREE_NETDEV
	dev->destructor = free_netdev;
#else
	dev->needs_free_netdev = true;
#endif

	SET_NETDEV_DEVTYPE(dev, &stt_type);

	dev->features    |= NETIF_F_LLTX | NETIF_F_NETNS_LOCAL;
	dev->features    |= NETIF_F_SG | NETIF_F_HW_CSUM;
	dev->features    |= NETIF_F_RXCSUM;
	dev->features    |= NETIF_F_GSO_SOFTWARE;

	dev->hw_features |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_RXCSUM;
	dev->hw_features |= NETIF_F_GSO_SOFTWARE;

#ifdef USE_UPSTREAM_TUNNEL
	netif_keep_dst(dev);
#endif
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;
	eth_hw_addr_random(dev);
}

static const struct nla_policy stt_policy[IFLA_STT_MAX + 1] = {
	[IFLA_STT_PORT]              = { .type = NLA_U16 },
};

#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
static int stt_validate(struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack __always_unused *extack)
#else
static int stt_validate(struct nlattr *tb[], struct nlattr *data[])
#endif
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;

		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}

	return 0;
}

static struct stt_dev *find_dev(struct net *net, __be16 dst_port)
{
	struct stt_net *sn = net_generic(net, stt_net_id);
	struct stt_dev *dev;

	list_for_each_entry(dev, &sn->stt_list, next) {
		if (dev->dst_port == dst_port)
			return dev;
	}
	return NULL;
}

static int stt_configure(struct net *net, struct net_device *dev,
			  __be16 dst_port)
{
	struct stt_net *sn = net_generic(net, stt_net_id);
	struct stt_dev *stt = netdev_priv(dev);
	int err;

	stt->net = net;
	stt->dev = dev;

	stt->dst_port = dst_port;

	if (find_dev(net, dst_port))
		return -EBUSY;

	err = __stt_change_mtu(dev, IP_MAX_MTU, false);
	if (err)
		return err;

	err = register_netdevice(dev);
	if (err)
		return err;

	list_add(&stt->next, &sn->stt_list);
	return 0;
}

#ifdef HAVE_EXT_ACK_IN_RTNL_LINKOPS
static int stt_newlink(struct net *net, struct net_device *dev,
		struct nlattr *tb[], struct nlattr *data[],
		struct netlink_ext_ack __always_unused *extack)
#else
static int stt_newlink(struct net *net, struct net_device *dev,
		struct nlattr *tb[], struct nlattr *data[])
#endif
{
	__be16 dst_port = htons(STT_DST_PORT);

	if (data[IFLA_STT_PORT])
		dst_port = nla_get_be16(data[IFLA_STT_PORT]);

	return stt_configure(net, dev, dst_port);
}

static void stt_dellink(struct net_device *dev, struct list_head *head)
{
	struct stt_dev *stt = netdev_priv(dev);

	list_del(&stt->next);
	unregister_netdevice_queue(dev, head);
}

static size_t stt_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(__be32));  /* IFLA_STT_PORT */
}

static int stt_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct stt_dev *stt = netdev_priv(dev);

	if (nla_put_be16(skb, IFLA_STT_PORT, stt->dst_port))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static struct rtnl_link_ops stt_link_ops __read_mostly = {
	.kind           = "stt",
	.maxtype        = IFLA_STT_MAX,
	.policy         = stt_policy,
	.priv_size      = sizeof(struct stt_dev),
	.setup          = stt_setup,
	.validate       = stt_validate,
	.newlink        = stt_newlink,
	.dellink        = stt_dellink,
	.get_size       = stt_get_size,
	.fill_info      = stt_fill_info,
};

struct net_device *ovs_stt_dev_create_fb(struct net *net, const char *name,
				      u8 name_assign_type, u16 dst_port)
{
	struct nlattr *tb[IFLA_MAX + 1];
	struct net_device *dev;
	int err;

	memset(tb, 0, sizeof(tb));
	dev = rtnl_create_link(net, (char *) name, name_assign_type,
			&stt_link_ops, tb);
	if (IS_ERR(dev))
		return dev;

	err = stt_configure(net, dev, htons(dst_port));
	if (err) {
		free_netdev(dev);
		return ERR_PTR(err);
	}
	return dev;
}
EXPORT_SYMBOL_GPL(ovs_stt_dev_create_fb);

static int stt_init_net(struct net *net)
{
	struct stt_net *sn = net_generic(net, stt_net_id);

	INIT_LIST_HEAD(&sn->stt_list);
	INIT_LIST_HEAD(&sn->stt_up_list);
#ifdef HAVE_NF_REGISTER_NET_HOOK
	sn->nf_hook_reg_done = false;
#endif
	return 0;
}

static void stt_exit_net(struct net *net)
{
	struct stt_net *sn = net_generic(net, stt_net_id);
	struct stt_dev *stt, *next;
	struct net_device *dev, *aux;
	LIST_HEAD(list);

#ifdef HAVE_NF_REGISTER_NET_HOOK
	/* Ideally this should be done from stt_stop(), But on some kernels
	 * nf-unreg operation needs RTNL-lock, which can cause deallock.
	 * So it is done from here. */
	if (sn->nf_hook_reg_done)
		nf_unregister_net_hook(net, &nf_hook_ops);
#endif

	rtnl_lock();

	/* gather any stt devices that were moved into this ns */
	for_each_netdev_safe(net, dev, aux)
		if (dev->rtnl_link_ops == &stt_link_ops)
			unregister_netdevice_queue(dev, &list);

	list_for_each_entry_safe(stt, next, &sn->stt_list, next) {
		/* If stt->dev is in the same netns, it was already added
		 * to the stt by the previous loop.
		 */
		if (!net_eq(dev_net(stt->dev), net))
			unregister_netdevice_queue(stt->dev, &list);
	}

	/* unregister the devices gathered above */
	unregister_netdevice_many(&list);
	rtnl_unlock();
}

static struct pernet_operations stt_net_ops = {
	.init = stt_init_net,
	.exit = stt_exit_net,
	.id   = &stt_net_id,
	.size = sizeof(struct stt_net),
};

int stt_init_module(void)
{
	int rc;

	rc = register_pernet_subsys(&stt_net_ops);
	if (rc)
		goto out1;

	rc = rtnl_link_register(&stt_link_ops);
	if (rc)
		goto out2;

#ifdef HAVE_LIST_IN_NF_HOOK_OPS
	INIT_LIST_HEAD(&nf_hook_ops.list);
#endif
	pr_info("STT tunneling driver\n");
	return 0;
out2:
	unregister_pernet_subsys(&stt_net_ops);
out1:
	pr_err("Error while initializing STT %d\n", rc);
	return rc;
}

void stt_cleanup_module(void)
{
#ifndef HAVE_NF_REGISTER_NET_HOOK
	if (!list_empty(&nf_hook_ops.list))
		nf_unregister_hook(&nf_hook_ops);
#endif
	rtnl_link_unregister(&stt_link_ops);
	unregister_pernet_subsys(&stt_net_ops);
}
#endif
