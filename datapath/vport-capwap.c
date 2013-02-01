/*
 * Copyright (c) 2007-2012 Nicira, Inc.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)

#include <linux/if.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/list.h>
#include <linux/net.h>
#include <net/net_namespace.h>

#include <net/icmp.h>
#include <net/inet_frag.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/udp.h>

#include "datapath.h"
#include "tunnel.h"
#include "vport.h"
#include "vport-generic.h"

#define CAPWAP_SRC_PORT 58881
#define CAPWAP_DST_PORT 58882

#define CAPWAP_FRAG_TIMEOUT (30 * HZ)
#define CAPWAP_FRAG_MAX_MEM (256 * 1024)
#define CAPWAP_FRAG_PRUNE_MEM (192 * 1024)
#define CAPWAP_FRAG_SECRET_INTERVAL (10 * 60 * HZ)

/*
 * The CAPWAP header is a mess, with all kinds of odd size bit fields that
 * cross byte boundaries, which are difficult to represent correctly in
 * various byte orderings.  Luckily we only care about a few permutations, so
 * statically create them and we can do very fast parsing by checking all 12
 * fields in one go.
 */
#define CAPWAP_PREAMBLE_MASK __cpu_to_be32(0xFF000000)
#define CAPWAP_HLEN_SHIFT    17
#define CAPWAP_HLEN_MASK     __cpu_to_be32(0x00F80000)
#define CAPWAP_RID_MASK      __cpu_to_be32(0x0007C000)
#define CAPWAP_WBID_MASK     __cpu_to_be32(0x00003E00)
#define CAPWAP_F_MASK        __cpu_to_be32(0x000001FF)

#define CAPWAP_F_FRAG        __cpu_to_be32(0x00000080)
#define CAPWAP_F_LASTFRAG    __cpu_to_be32(0x00000040)
#define CAPWAP_F_WSI         __cpu_to_be32(0x00000020)
#define CAPWAP_F_RMAC        __cpu_to_be32(0x00000010)

#define CAPWAP_RMAC_LEN      4

/*  Standard CAPWAP looks for a WBID value of 2.
 *  When we insert WSI field, use WBID value of 30, which has been
 *  proposed for all "experimental" usage - users with no reserved WBID value
 *  of their own.
*/
#define CAPWAP_WBID_30   __cpu_to_be32(0x00003C00)
#define CAPWAP_WBID_2    __cpu_to_be32(0x00000200)

#define FRAG_HDR (CAPWAP_F_FRAG)
#define FRAG_LAST_HDR (FRAG_HDR | CAPWAP_F_LASTFRAG)

/* Keyed packet, WBID 30, and length long enough to include WSI key */
#define CAPWAP_KEYED (CAPWAP_WBID_30 | CAPWAP_F_WSI | htonl(20 << CAPWAP_HLEN_SHIFT))
/* A backward-compatible packet, WBID 2 and length of 2 words (no WSI fields) */
#define CAPWAP_NO_WSI (CAPWAP_WBID_2 | htonl(8 << CAPWAP_HLEN_SHIFT))

/* Mask for all parts of header that must be 0. */
#define CAPWAP_ZERO_MASK (CAPWAP_PREAMBLE_MASK | \
		(CAPWAP_F_MASK ^ (CAPWAP_F_WSI | CAPWAP_F_FRAG | CAPWAP_F_LASTFRAG | CAPWAP_F_RMAC)))

struct capwaphdr {
	__be32 begin;
	__be16 frag_id;
	/* low 3 bits of frag_off are reserved */
	__be16 frag_off;
};

/*
 * We use the WSI field to hold additional tunnel data.
 * The first eight bits store the size of the wsi data in bytes.
 */
struct capwaphdr_wsi {
	u8 wsi_len;
	u8 flags;
	__be16 reserved_padding;
};

struct capwaphdr_wsi_key {
	__be64 key;
};

/* Flag indicating a 64bit key is stored in WSI data field */
#define CAPWAP_WSI_F_KEY64 0x80

static struct capwaphdr *capwap_hdr(const struct sk_buff *skb)
{
	return (struct capwaphdr *)(udp_hdr(skb) + 1);
}

/*
 * The fragment offset is actually the high 13 bits of the last 16 bit field,
 * so we would normally need to right shift 3 places.  However, it stores the
 * offset in 8 byte chunks, which would involve a 3 place left shift.  So we
 * just mask off the last 3 bits and be done with it.
 */
#define FRAG_OFF_MASK (~0x7U)

/*
 * The minimum header length.  The header may be longer if the optional
 * WSI field is used.
 */
#define CAPWAP_MIN_HLEN (sizeof(struct udphdr) + sizeof(struct capwaphdr))

struct frag_match {
	__be32 saddr;
	__be32 daddr;
	__be16 id;
};

struct frag_queue {
	struct inet_frag_queue ifq;
	struct frag_match match;
};

struct frag_skb_cb {
	u16 offset;
};
#define FRAG_CB(skb) ((struct frag_skb_cb *)(skb)->cb)

static struct sk_buff *fragment(struct sk_buff *, const struct vport *,
				struct dst_entry *dst, unsigned int hlen);
static struct sk_buff *defrag(struct sk_buff *, bool frag_last);

static void capwap_frag_init(struct inet_frag_queue *, void *match);
static unsigned int capwap_frag_hash(struct inet_frag_queue *);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
static int capwap_frag_match(struct inet_frag_queue *, void *match);
#else
static bool capwap_frag_match(struct inet_frag_queue *, void *match);
#endif
static void capwap_frag_expire(unsigned long ifq);

static struct inet_frags frag_state = {
	.constructor	= capwap_frag_init,
	.qsize		= sizeof(struct frag_queue),
	.hashfn		= capwap_frag_hash,
	.match		= capwap_frag_match,
	.frag_expire	= capwap_frag_expire,
	.secret_interval = CAPWAP_FRAG_SECRET_INTERVAL,
};

static int capwap_hdr_len(const struct tnl_mutable_config *mutable,
			  const struct ovs_key_ipv4_tunnel *tun_key)
{
	int size = CAPWAP_MIN_HLEN;
	u32 flags;
	__be64 out_key;

	tnl_get_param(mutable, tun_key, &flags, &out_key);

	/* CAPWAP has no checksums. */
	if (flags & TNL_F_CSUM)
		return -EINVAL;

	/* if keys are specified, then add WSI field */
	if (out_key || (flags & TNL_F_OUT_KEY_ACTION)) {
		size += sizeof(struct capwaphdr_wsi) +
			sizeof(struct capwaphdr_wsi_key);
	}

	return size;
}

static struct sk_buff *capwap_build_header(const struct vport *vport,
					    const struct tnl_mutable_config *mutable,
					    struct dst_entry *dst,
					    struct sk_buff *skb,
					    int tunnel_hlen)
{
	struct ovs_key_ipv4_tunnel *tun_key = OVS_CB(skb)->tun_key;
	struct udphdr *udph = udp_hdr(skb);
	struct capwaphdr *cwh = (struct capwaphdr *)(udph + 1);
	u32 flags;
	__be64 out_key;

	tnl_get_param(mutable, tun_key, &flags, &out_key);

	udph->source = htons(CAPWAP_SRC_PORT);
	udph->dest = htons(CAPWAP_DST_PORT);
	udph->check = 0;

	cwh->frag_id = 0;
	cwh->frag_off = 0;

	if (out_key || flags & TNL_F_OUT_KEY_ACTION) {
		/* first field in WSI is key */
		struct capwaphdr_wsi *wsi = (struct capwaphdr_wsi *)(cwh + 1);

		cwh->begin = CAPWAP_KEYED;

		/* -1 for wsi_len byte, not included in length as per spec */
		wsi->wsi_len = sizeof(struct capwaphdr_wsi) - 1
			+ sizeof(struct capwaphdr_wsi_key);
		wsi->flags = CAPWAP_WSI_F_KEY64;
		wsi->reserved_padding = 0;

		if (out_key) {
			struct capwaphdr_wsi_key *opt = (struct capwaphdr_wsi_key *)(wsi + 1);
			opt->key = out_key;
		}
	} else {
		/* make packet readable by old capwap code */
		cwh->begin = CAPWAP_NO_WSI;
	}
	udph->len = htons(skb->len - skb_transport_offset(skb));

	if (unlikely(skb->len - skb_network_offset(skb) > dst_mtu(dst))) {
		unsigned int hlen = skb_transport_offset(skb) + capwap_hdr_len(mutable, tun_key);
		skb = fragment(skb, vport, dst, hlen);
	}

	return skb;
}

static int process_capwap_wsi(struct sk_buff *skb, __be64 *key, bool *key_present)
{
	struct capwaphdr *cwh = capwap_hdr(skb);
	struct capwaphdr_wsi *wsi;
	int hdr_len;
	int rmac_len = 0;
	int wsi_len;

	if (((cwh->begin & CAPWAP_WBID_MASK) != CAPWAP_WBID_30))
		return 0;

	if (cwh->begin & CAPWAP_F_RMAC)
		rmac_len = CAPWAP_RMAC_LEN;

	hdr_len = ntohl(cwh->begin & CAPWAP_HLEN_MASK) >> CAPWAP_HLEN_SHIFT;

	if (unlikely(sizeof(struct capwaphdr) + rmac_len + sizeof(struct capwaphdr_wsi) > hdr_len))
		return -EINVAL;

	/* read wsi header to find out how big it really is */
	wsi = (struct capwaphdr_wsi *)((u8 *)(cwh + 1) + rmac_len);
	/* +1 for length byte not included in wsi_len */
	wsi_len = 1 + wsi->wsi_len;

	if (unlikely(sizeof(struct capwaphdr) + rmac_len + wsi_len != hdr_len))
		return -EINVAL;

	wsi_len -= sizeof(struct capwaphdr_wsi);

	if (wsi->flags & CAPWAP_WSI_F_KEY64) {
		struct capwaphdr_wsi_key *opt;

		if (unlikely(wsi_len < sizeof(struct capwaphdr_wsi_key)))
			return -EINVAL;

		opt = (struct capwaphdr_wsi_key *)(wsi + 1);
		*key = opt->key;
		*key_present = true;
	} else {
		*key_present = false;
	}

	return 0;
}

static struct sk_buff *process_capwap_proto(struct sk_buff *skb, __be64 *key, bool *key_present)
{
	struct capwaphdr *cwh = capwap_hdr(skb);
	int hdr_len = sizeof(struct udphdr);

	if (unlikely((cwh->begin & CAPWAP_ZERO_MASK) != 0))
		goto error;

	hdr_len += ntohl(cwh->begin & CAPWAP_HLEN_MASK) >> CAPWAP_HLEN_SHIFT;
	if (unlikely(hdr_len < CAPWAP_MIN_HLEN))
		goto error;

	if (unlikely(!pskb_may_pull(skb, hdr_len + ETH_HLEN)))
		goto error;

	cwh = capwap_hdr(skb);
	__skb_pull(skb, hdr_len);
	skb_postpull_rcsum(skb, skb_transport_header(skb), hdr_len + ETH_HLEN);

	if (cwh->begin & CAPWAP_F_FRAG) {
		skb = defrag(skb, (__force bool)(cwh->begin & CAPWAP_F_LASTFRAG));
		if (!skb)
			return NULL;
		cwh = capwap_hdr(skb);
	}

	if ((cwh->begin & CAPWAP_F_WSI) && process_capwap_wsi(skb, key, key_present))
		goto error;

	return skb;
error:
	kfree_skb(skb);
	return NULL;
}

/* Called with rcu_read_lock and BH disabled. */
static int capwap_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct vport *vport;
	const struct tnl_mutable_config *mutable;
	struct iphdr *iph;
	struct ovs_key_ipv4_tunnel tun_key;
	__be64 key = 0;
	bool key_present = false;

	if (unlikely(!pskb_may_pull(skb, CAPWAP_MIN_HLEN + ETH_HLEN)))
		goto error;

	skb = process_capwap_proto(skb, &key, &key_present);
	if (unlikely(!skb))
		goto out;

	iph = ip_hdr(skb);
	vport = ovs_tnl_find_port(sock_net(sk), iph->daddr, iph->saddr, key,
				  TNL_T_PROTO_CAPWAP, &mutable);
	if (unlikely(!vport))
		goto error;

	if (key_present && mutable->key.daddr &&
			 !(mutable->flags & TNL_F_IN_KEY_MATCH)) {
		key_present = false;
		key = 0;
	}

	tnl_tun_key_init(&tun_key, iph, key, key_present ? OVS_TNL_F_KEY : 0);
	OVS_CB(skb)->tun_key = &tun_key;

	ovs_tnl_rcv(vport, skb);
	goto out;

error:
	kfree_skb(skb);
out:
	return 0;
}

static const struct tnl_ops capwap_tnl_ops = {
	.tunnel_type	= TNL_T_PROTO_CAPWAP,
	.ipproto	= IPPROTO_UDP,
	.hdr_len	= capwap_hdr_len,
	.build_header	= capwap_build_header,
};

static inline struct capwap_net *ovs_get_capwap_net(struct net *net)
{
	struct ovs_net *ovs_net = net_generic(net, ovs_net_id);
	return &ovs_net->vport_net.capwap;
}

/* Arbitrary value.  Irrelevant as long as it's not 0 since we set the handler. */
#define UDP_ENCAP_CAPWAP 10
static int init_socket(struct net *net)
{
	int err;
	struct capwap_net *capwap_net = ovs_get_capwap_net(net);
	struct sockaddr_in sin;

	if (capwap_net->n_tunnels) {
		capwap_net->n_tunnels++;
		return 0;
	}

	err = sock_create_kern(AF_INET, SOCK_DGRAM, 0,
			       &capwap_net->capwap_rcv_socket);
	if (err)
		goto error;

	/* release net ref. */
	sk_change_net(capwap_net->capwap_rcv_socket->sk, net);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(CAPWAP_DST_PORT);

	err = kernel_bind(capwap_net->capwap_rcv_socket,
			  (struct sockaddr *)&sin,
			  sizeof(struct sockaddr_in));
	if (err)
		goto error_sock;

	udp_sk(capwap_net->capwap_rcv_socket->sk)->encap_type = UDP_ENCAP_CAPWAP;
	udp_sk(capwap_net->capwap_rcv_socket->sk)->encap_rcv = capwap_rcv;

	capwap_net->frag_state.timeout		= CAPWAP_FRAG_TIMEOUT;
	capwap_net->frag_state.high_thresh	= CAPWAP_FRAG_MAX_MEM;
	capwap_net->frag_state.low_thresh	= CAPWAP_FRAG_PRUNE_MEM;

	inet_frags_init_net(&capwap_net->frag_state);
	udp_encap_enable();
	capwap_net->n_tunnels++;
	return 0;

error_sock:
	sk_release_kernel(capwap_net->capwap_rcv_socket->sk);
error:
	pr_warn("cannot register capwap protocol handler : %d\n", err);
	return err;
}

static void release_socket(struct net *net)
{
	struct capwap_net *capwap_net = ovs_get_capwap_net(net);

	capwap_net->n_tunnels--;
	if (capwap_net->n_tunnels)
		return;

	inet_frags_exit_net(&capwap_net->frag_state, &frag_state);
	sk_release_kernel(capwap_net->capwap_rcv_socket->sk);
}

static struct vport *capwap_create(const struct vport_parms *parms)
{
	struct vport *vport;
	int err;

	err = init_socket(ovs_dp_get_net(parms->dp));
	if (err)
		return ERR_PTR(err);

	vport = ovs_tnl_create(parms, &ovs_capwap_vport_ops, &capwap_tnl_ops);
	if (IS_ERR(vport))
		release_socket(ovs_dp_get_net(parms->dp));

	return vport;
}

static void capwap_destroy(struct vport *vport)
{
	ovs_tnl_destroy(vport);
	release_socket(ovs_dp_get_net(vport->dp));
}

static int capwap_init(void)
{
	inet_frags_init(&frag_state);
	return 0;
}

static void capwap_exit(void)
{
	inet_frags_fini(&frag_state);
}

static void copy_skb_metadata(struct sk_buff *from, struct sk_buff *to)
{
	to->pkt_type = from->pkt_type;
	to->priority = from->priority;
	to->protocol = from->protocol;
	skb_dst_set(to, dst_clone(skb_dst(from)));
	to->dev = from->dev;
	to->mark = from->mark;

	if (from->sk)
		skb_set_owner_w(to, from->sk);

#ifdef CONFIG_NET_SCHED
	to->tc_index = from->tc_index;
#endif
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
	to->ipvs_property = from->ipvs_property;
#endif
	skb_copy_secmark(to, from);
}

static struct sk_buff *fragment(struct sk_buff *skb, const struct vport *vport,
				struct dst_entry *dst, unsigned int hlen)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	unsigned int headroom;
	unsigned int max_frame_len = dst_mtu(dst) + skb_network_offset(skb);
	struct sk_buff *result = NULL, *list_cur = NULL;
	unsigned int remaining;
	unsigned int offset;
	__be16 frag_id;

	if (hlen + ~FRAG_OFF_MASK + 1 > max_frame_len) {
		if (net_ratelimit())
			pr_warn("capwap link mtu (%d) is less than minimum packet (%d)\n",
				dst_mtu(dst),
				hlen - skb_network_offset(skb) + ~FRAG_OFF_MASK + 1);
		goto error;
	}

	remaining = skb->len - hlen;
	offset = 0;
	frag_id = htons(atomic_inc_return(&tnl_vport->frag_id));

	headroom = dst->header_len + 16;
	if (!skb_network_offset(skb))
		headroom += LL_RESERVED_SPACE(dst->dev);

	while (remaining) {
		struct sk_buff *skb2;
		int frag_size;
		struct udphdr *udph;
		struct capwaphdr *cwh;

		frag_size = min(remaining, max_frame_len - hlen);
		if (remaining > frag_size)
			frag_size &= FRAG_OFF_MASK;

		skb2 = alloc_skb(headroom + hlen + frag_size, GFP_ATOMIC);
		if (!skb2)
			goto error;

		skb_reserve(skb2, headroom);
		__skb_put(skb2, hlen + frag_size);

		if (skb_network_offset(skb))
			skb_reset_mac_header(skb2);
		skb_set_network_header(skb2, skb_network_offset(skb));
		skb_set_transport_header(skb2, skb_transport_offset(skb));

		/* Copy (Ethernet)/IP/UDP/CAPWAP header. */
		copy_skb_metadata(skb, skb2);
		skb_copy_from_linear_data(skb, skb2->data, hlen);

		/* Copy this data chunk. */
		if (skb_copy_bits(skb, hlen + offset, skb2->data + hlen, frag_size))
			BUG();

		udph = udp_hdr(skb2);
		udph->len = htons(skb2->len - skb_transport_offset(skb2));

		cwh = capwap_hdr(skb2);
		if (remaining > frag_size)
			cwh->begin |= FRAG_HDR;
		else
			cwh->begin |= FRAG_LAST_HDR;
		cwh->frag_id = frag_id;
		cwh->frag_off = htons(offset);

		if (result) {
			list_cur->next = skb2;
			list_cur = skb2;
		} else
			result = list_cur = skb2;

		offset += frag_size;
		remaining -= frag_size;
	}

	consume_skb(skb);
	return result;

error:
	ovs_tnl_free_linked_skbs(result);
	kfree_skb(skb);
	return NULL;
}

/* All of the following functions relate to fragmentation reassembly. */

static struct frag_queue *ifq_cast(struct inet_frag_queue *ifq)
{
	return container_of(ifq, struct frag_queue, ifq);
}

static u32 frag_hash(struct frag_match *match)
{
	return jhash_3words((__force u16)match->id, (__force u32)match->saddr,
			    (__force u32)match->daddr,
			    frag_state.rnd) & (INETFRAGS_HASHSZ - 1);
}

static struct frag_queue *queue_find(struct netns_frags *ns_frag_state,
				     struct frag_match *match)
{
	struct inet_frag_queue *ifq;

	read_lock(&frag_state.lock);

	ifq = inet_frag_find(ns_frag_state, &frag_state, match, frag_hash(match));
	if (!ifq)
		return NULL;

	/* Unlock happens inside inet_frag_find(). */

	return ifq_cast(ifq);
}

static struct sk_buff *frag_reasm(struct frag_queue *fq, struct net_device *dev)
{
	struct sk_buff *head = fq->ifq.fragments;
	struct sk_buff *frag;

	/* Succeed or fail, we're done with this queue. */
	inet_frag_kill(&fq->ifq, &frag_state);

	if (fq->ifq.len > 65535)
		return NULL;

	/* Can't have the head be a clone. */
	if (skb_cloned(head) && pskb_expand_head(head, 0, 0, GFP_ATOMIC))
		return NULL;

	/*
	 * We're about to build frag list for this SKB.  If it already has a
	 * frag list, alloc a new SKB and put the existing frag list there.
	 */
	if (skb_shinfo(head)->frag_list) {
		int i;
		int paged_len = 0;

		frag = alloc_skb(0, GFP_ATOMIC);
		if (!frag)
			return NULL;

		frag->next = head->next;
		head->next = frag;
		skb_shinfo(frag)->frag_list = skb_shinfo(head)->frag_list;
		skb_shinfo(head)->frag_list = NULL;

		for (i = 0; i < skb_shinfo(head)->nr_frags; i++)
			paged_len += skb_shinfo(head)->frags[i].size;
		frag->len = frag->data_len = head->data_len - paged_len;
		head->data_len -= frag->len;
		head->len -= frag->len;

		frag->ip_summed = head->ip_summed;
		atomic_add(frag->truesize, &fq->ifq.net->mem);
	}

	skb_shinfo(head)->frag_list = head->next;
	atomic_sub(head->truesize, &fq->ifq.net->mem);

	/* Properly account for data in various packets. */
	for (frag = head->next; frag; frag = frag->next) {
		head->data_len += frag->len;
		head->len += frag->len;

		if (head->ip_summed != frag->ip_summed)
			head->ip_summed = CHECKSUM_NONE;
		else if (head->ip_summed == CHECKSUM_COMPLETE)
			head->csum = csum_add(head->csum, frag->csum);

		head->truesize += frag->truesize;
		atomic_sub(frag->truesize, &fq->ifq.net->mem);
	}

	head->next = NULL;
	head->dev = dev;
	head->tstamp = fq->ifq.stamp;
	fq->ifq.fragments = NULL;

	return head;
}

static struct sk_buff *frag_queue(struct frag_queue *fq, struct sk_buff *skb,
				  u16 offset, bool frag_last)
{
	struct sk_buff *prev, *next;
	struct net_device *dev;
	int end;

	if (fq->ifq.last_in & INET_FRAG_COMPLETE)
		goto error;

	if (!skb->len)
		goto error;

	end = offset + skb->len;

	if (frag_last) {
		/*
		 * Last fragment, shouldn't already have data past our end or
		 * have another last fragment.
		 */
		if (end < fq->ifq.len || fq->ifq.last_in & INET_FRAG_LAST_IN)
			goto error;

		fq->ifq.last_in |= INET_FRAG_LAST_IN;
		fq->ifq.len = end;
	} else {
		/* Fragments should align to 8 byte chunks. */
		if (end & ~FRAG_OFF_MASK)
			goto error;

		if (end > fq->ifq.len) {
			/*
			 * Shouldn't have data past the end, if we already
			 * have one.
			 */
			if (fq->ifq.last_in & INET_FRAG_LAST_IN)
				goto error;

			fq->ifq.len = end;
		}
	}

	/* Find where we fit in. */
	prev = NULL;
	for (next = fq->ifq.fragments; next != NULL; next = next->next) {
		if (FRAG_CB(next)->offset >= offset)
			break;
		prev = next;
	}

	/*
	 * Overlapping fragments aren't allowed.  We shouldn't start before
	 * the end of the previous fragment.
	 */
	if (prev && FRAG_CB(prev)->offset + prev->len > offset)
		goto error;

	/* We also shouldn't end after the beginning of the next fragment. */
	if (next && end > FRAG_CB(next)->offset)
		goto error;

	FRAG_CB(skb)->offset = offset;

	/* Link into list. */
	skb->next = next;
	if (prev)
		prev->next = skb;
	else
		fq->ifq.fragments = skb;

	dev = skb->dev;
	skb->dev = NULL;

	fq->ifq.stamp = skb->tstamp;
	fq->ifq.meat += skb->len;
	atomic_add(skb->truesize, &fq->ifq.net->mem);
	if (offset == 0)
		fq->ifq.last_in |= INET_FRAG_FIRST_IN;

	/* If we have all fragments do reassembly. */
	if (fq->ifq.last_in == (INET_FRAG_FIRST_IN | INET_FRAG_LAST_IN) &&
	    fq->ifq.meat == fq->ifq.len)
		return frag_reasm(fq, dev);

	write_lock(&frag_state.lock);
	list_move_tail(&fq->ifq.lru_list, &fq->ifq.net->lru_list);
	write_unlock(&frag_state.lock);

	return NULL;

error:
	kfree_skb(skb);
	return NULL;
}

static struct sk_buff *defrag(struct sk_buff *skb, bool frag_last)
{
	struct iphdr *iph = ip_hdr(skb);
	struct capwaphdr *cwh = capwap_hdr(skb);
	struct capwap_net *capwap_net = ovs_get_capwap_net(dev_net(skb->dev));
	struct netns_frags *ns_frag_state = &capwap_net->frag_state;
	struct frag_match match;
	u16 frag_off;
	struct frag_queue *fq;

	inet_frag_evictor(ns_frag_state, &frag_state, false);

	match.daddr = iph->daddr;
	match.saddr = iph->saddr;
	match.id = cwh->frag_id;
	frag_off = ntohs(cwh->frag_off) & FRAG_OFF_MASK;

	fq = queue_find(ns_frag_state, &match);
	if (fq) {
		spin_lock(&fq->ifq.lock);
		skb = frag_queue(fq, skb, frag_off, frag_last);
		spin_unlock(&fq->ifq.lock);

		inet_frag_put(&fq->ifq, &frag_state);

		return skb;
	}

	kfree_skb(skb);
	return NULL;
}

static void capwap_frag_init(struct inet_frag_queue *ifq, void *match_)
{
	struct frag_match *match = match_;

	ifq_cast(ifq)->match = *match;
}

static unsigned int capwap_frag_hash(struct inet_frag_queue *ifq)
{
	return frag_hash(&ifq_cast(ifq)->match);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
static int capwap_frag_match(struct inet_frag_queue *ifq, void *a_)
#else
static bool capwap_frag_match(struct inet_frag_queue *ifq, void *a_)
#endif
{
	struct frag_match *a = a_;
	struct frag_match *b = &ifq_cast(ifq)->match;

	return a->id == b->id && a->saddr == b->saddr && a->daddr == b->daddr;
}

/* Run when the timeout for a given queue expires. */
static void capwap_frag_expire(unsigned long ifq)
{
	struct frag_queue *fq;

	fq = ifq_cast((struct inet_frag_queue *)ifq);

	spin_lock(&fq->ifq.lock);

	if (!(fq->ifq.last_in & INET_FRAG_COMPLETE))
		inet_frag_kill(&fq->ifq, &frag_state);

	spin_unlock(&fq->ifq.lock);
	inet_frag_put(&fq->ifq, &frag_state);
}

const struct vport_ops ovs_capwap_vport_ops = {
	.type		= OVS_VPORT_TYPE_CAPWAP,
	.flags		= VPORT_F_TUN_ID,
	.init		= capwap_init,
	.exit		= capwap_exit,
	.create		= capwap_create,
	.destroy	= capwap_destroy,
	.set_addr	= ovs_tnl_set_addr,
	.get_name	= ovs_tnl_get_name,
	.get_addr	= ovs_tnl_get_addr,
	.get_options	= ovs_tnl_get_options,
	.set_options	= ovs_tnl_set_options,
	.get_dev_flags	= ovs_vport_gen_get_dev_flags,
	.is_running	= ovs_vport_gen_is_running,
	.get_operstate	= ovs_vport_gen_get_operstate,
	.send		= ovs_tnl_send,
};
#else
#warning CAPWAP tunneling will not be available on kernels before 2.6.26
#endif /* Linux kernel < 2.6.26 */
