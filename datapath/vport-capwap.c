/*
 * Copyright (c) 2010, 2011 Nicira Networks.
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

#include <net/icmp.h>
#include <net/inet_frag.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/udp.h>

#include "tunnel.h"
#include "vport.h"
#include "vport-generic.h"

#define CAPWAP_SRC_PORT 58881
#define CAPWAP_DST_PORT 58882

#define CAPWAP_FRAG_TIMEOUT (30 * HZ)
#define CAPWAP_FRAG_MAX_MEM (256 * 1024)
#define CAPWAP_FRAG_PRUNE_MEM (192 *1024)
#define CAPWAP_FRAG_SECRET_INTERVAL (10 * 60 * HZ)

/*
 * The CAPWAP header is a mess, with all kinds of odd size bit fields that
 * cross byte boundaries, which are difficult to represent correctly in
 * various byte orderings.  Luckily we only care about a few permutations, so
 * statically create them and we can do very fast parsing by checking all 12
 * fields in one go.
 */
#define CAPWAP_BEGIN_HLEN __cpu_to_be32(0x00100000)
#define CAPWAP_BEGIN_WBID __cpu_to_be32(0x00000200)
#define CAPWAP_BEGIN_FRAG __cpu_to_be32(0x00000080)
#define CAPWAP_BEGIN_LAST __cpu_to_be32(0x00000040)

#define NO_FRAG_HDR (CAPWAP_BEGIN_HLEN | CAPWAP_BEGIN_WBID)
#define FRAG_HDR (NO_FRAG_HDR | CAPWAP_BEGIN_FRAG)
#define FRAG_LAST_HDR (FRAG_HDR | CAPWAP_BEGIN_LAST)

struct capwaphdr {
	__be32 begin;
	__be16 frag_id;
	__be16 frag_off;
};

static inline struct capwaphdr *capwap_hdr(const struct sk_buff *skb)
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

#define CAPWAP_HLEN (sizeof(struct udphdr) + sizeof(struct capwaphdr))

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
				struct dst_entry *);
static void defrag_init(void);
static void defrag_exit(void);
static struct sk_buff *defrag(struct sk_buff *, bool frag_last);

static void capwap_frag_init(struct inet_frag_queue *, void *match);
static unsigned int capwap_frag_hash(struct inet_frag_queue *);
static int capwap_frag_match(struct inet_frag_queue *, void *match);
static void capwap_frag_expire(unsigned long ifq);

static struct inet_frags frag_state = {
	.constructor	= capwap_frag_init,
	.qsize		= sizeof(struct frag_queue),
	.hashfn		= capwap_frag_hash,
	.match		= capwap_frag_match,
	.frag_expire	= capwap_frag_expire,
	.secret_interval = CAPWAP_FRAG_SECRET_INTERVAL,
};
static struct netns_frags frag_netns_state = {
	.timeout	= CAPWAP_FRAG_TIMEOUT,
	.high_thresh	= CAPWAP_FRAG_MAX_MEM,
	.low_thresh	= CAPWAP_FRAG_PRUNE_MEM,
};

static struct socket *capwap_rcv_socket;

static int capwap_hdr_len(const struct tnl_mutable_config *mutable)
{
	/* CAPWAP has no checksums. */
	if (mutable->flags & TNL_F_CSUM)
		return -EINVAL;

	/* CAPWAP has no keys, so check that the configuration for keys is the
	 * default if no key-specific attributes are used.
	 */
	if ((mutable->flags & (TNL_F_IN_KEY_MATCH | TNL_F_OUT_KEY_ACTION)) !=
	    (TNL_F_IN_KEY_MATCH | TNL_F_OUT_KEY_ACTION))
		return -EINVAL;

	return CAPWAP_HLEN;
}

static void capwap_build_header(const struct vport *vport,
				const struct tnl_mutable_config *mutable,
				void *header)
{
	struct udphdr *udph = header;
	struct capwaphdr *cwh = (struct capwaphdr *)(udph + 1);

	udph->source = htons(CAPWAP_SRC_PORT);
	udph->dest = htons(CAPWAP_DST_PORT);
	udph->check = 0;

	cwh->begin = NO_FRAG_HDR;
	cwh->frag_id = 0;
	cwh->frag_off = 0;
}

static struct sk_buff *capwap_update_header(const struct vport *vport,
					    const struct tnl_mutable_config *mutable,
					    struct dst_entry *dst,
					    struct sk_buff *skb)
{
	struct udphdr *udph = udp_hdr(skb);

	udph->len = htons(skb->len - skb_transport_offset(skb));

	if (unlikely(skb->len - skb_network_offset(skb) > dst_mtu(dst)))
		skb = fragment(skb, vport, dst);

	return skb;
}

static inline struct sk_buff *process_capwap_proto(struct sk_buff *skb)
{
	struct capwaphdr *cwh = capwap_hdr(skb);

	if (likely(cwh->begin == NO_FRAG_HDR))
		return skb;
	else if (cwh->begin == FRAG_HDR)
		return defrag(skb, false);
	else if (cwh->begin == FRAG_LAST_HDR)
		return defrag(skb, true);
	else {
		if (net_ratelimit())
			pr_warn("unparsable packet receive on capwap socket\n");

		kfree_skb(skb);
		return NULL;
	}
}

/* Called with rcu_read_lock and BH disabled. */
static int capwap_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct vport *vport;
	const struct tnl_mutable_config *mutable;
	struct iphdr *iph;

	if (unlikely(!pskb_may_pull(skb, CAPWAP_HLEN + ETH_HLEN)))
		goto error;

	__skb_pull(skb, CAPWAP_HLEN);
	skb_postpull_rcsum(skb, skb_transport_header(skb), CAPWAP_HLEN + ETH_HLEN);

	skb = process_capwap_proto(skb);
	if (unlikely(!skb))
		goto out;

	iph = ip_hdr(skb);
	vport = tnl_find_port(iph->daddr, iph->saddr, 0,
			      TNL_T_PROTO_CAPWAP | TNL_T_KEY_EXACT, &mutable);
	if (unlikely(!vport)) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
		goto error;
	}

	tnl_rcv(vport, skb, iph->tos);
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
	.update_header	= capwap_update_header,
};

static struct vport *capwap_create(const struct vport_parms *parms)
{
	return tnl_create(parms, &capwap_vport_ops, &capwap_tnl_ops);
}

/* Random value.  Irrelevant as long as it's not 0 since we set the handler. */
#define UDP_ENCAP_CAPWAP 10
static int capwap_init(void)
{
	int err;
	struct sockaddr_in sin;

	err = sock_create(AF_INET, SOCK_DGRAM, 0, &capwap_rcv_socket);
	if (err)
		goto error;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(CAPWAP_DST_PORT);

	err = kernel_bind(capwap_rcv_socket, (struct sockaddr *)&sin,
			  sizeof(struct sockaddr_in));
	if (err)
		goto error_sock;

	udp_sk(capwap_rcv_socket->sk)->encap_type = UDP_ENCAP_CAPWAP;
	udp_sk(capwap_rcv_socket->sk)->encap_rcv = capwap_rcv;

	defrag_init();

	return 0;

error_sock:
	sock_release(capwap_rcv_socket);
error:
	pr_warn("cannot register capwap protocol handler\n");
	return err;
}

static void capwap_exit(void)
{
	defrag_exit();
	sock_release(capwap_rcv_socket);
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
				struct dst_entry *dst)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	unsigned int hlen = skb_transport_offset(skb) + CAPWAP_HLEN;
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
			cwh->begin = FRAG_HDR;
		else
			cwh->begin = FRAG_LAST_HDR;
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

	goto out;

error:
	tnl_free_linked_skbs(result);
out:
	kfree_skb(skb);
	return result;
}

/* All of the following functions relate to fragmentation reassembly. */

static inline struct frag_queue *ifq_cast(struct inet_frag_queue *ifq)
{
	return container_of(ifq, struct frag_queue, ifq);
}

static u32 frag_hash(struct frag_match *match)
{
	return jhash_3words((__force u16)match->id, (__force u32)match->saddr,
			    (__force u32)match->daddr,
			    frag_state.rnd) & (INETFRAGS_HASHSZ - 1);
}

static struct frag_queue *queue_find(struct frag_match *match)
{
	struct inet_frag_queue *ifq;

	read_lock(&frag_state.lock);

	ifq = inet_frag_find(&frag_netns_state, &frag_state, match, frag_hash(match));
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
	struct frag_match match;
	u16 frag_off;
	struct frag_queue *fq;

	if (atomic_read(&frag_netns_state.mem) > frag_netns_state.high_thresh)
		inet_frag_evictor(&frag_netns_state, &frag_state);

	match.daddr = iph->daddr;
	match.saddr = iph->saddr;
	match.id = cwh->frag_id;
	frag_off = ntohs(cwh->frag_off) & FRAG_OFF_MASK;

	fq = queue_find(&match);
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

static void defrag_init(void)
{
	inet_frags_init(&frag_state);
	inet_frags_init_net(&frag_netns_state);
}

static void defrag_exit(void)
{
	inet_frags_exit_net(&frag_netns_state, &frag_state);
	inet_frags_fini(&frag_state);
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

static int capwap_frag_match(struct inet_frag_queue *ifq, void *a_)
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

const struct vport_ops capwap_vport_ops = {
	.type		= ODP_VPORT_TYPE_CAPWAP,
	.flags		= VPORT_F_GEN_STATS,
	.init		= capwap_init,
	.exit		= capwap_exit,
	.create		= capwap_create,
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
#else
#warning CAPWAP tunneling will not be available on kernels before 2.6.26
#endif /* Linux kernel < 2.6.26 */
