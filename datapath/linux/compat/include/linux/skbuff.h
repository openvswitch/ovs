#ifndef __LINUX_SKBUFF_WRAPPER_H
#define __LINUX_SKBUFF_WRAPPER_H 1

#include_next <linux/skbuff.h>

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
/* In version 2.6.24 the return type of skb_headroom() changed from 'int' to
 * 'unsigned int'.  We use skb_headroom() as one arm of a min(a,b) invocation
 * in make_writable() in actions.c, so we need the correct type. */
#define skb_headroom rpl_skb_headroom
static inline unsigned int rpl_skb_headroom(const struct sk_buff *skb)
{
	return skb->data - skb->head;
}
#endif

#ifndef HAVE_SKB_COPY_FROM_LINEAR_DATA_OFFSET
static inline void skb_copy_from_linear_data_offset(const struct sk_buff *skb,
						    const int offset, void *to,
						    const unsigned int len)
{
	memcpy(to, skb->data + offset, len);
}

static inline void skb_copy_to_linear_data_offset(struct sk_buff *skb,
						  const int offset,
						  const void *from,
						  const unsigned int len)
{
	memcpy(skb->data + offset, from, len);
}

#endif	/* !HAVE_SKB_COPY_FROM_LINEAR_DATA_OFFSET */

#ifndef HAVE_SKB_RESET_TAIL_POINTER
static inline void skb_reset_tail_pointer(struct sk_buff *skb)
{
	skb->tail = skb->data;
}
#endif
/*
 * The networking layer reserves some headroom in skb data (via
 * dev_alloc_skb). This is used to avoid having to reallocate skb data when
 * the header has to grow. In the default case, if the header has to grow
 * 16 bytes or less we avoid the reallocation.
 *
 * Unfortunately this headroom changes the DMA alignment of the resulting
 * network packet. As for NET_IP_ALIGN, this unaligned DMA is expensive
 * on some architectures. An architecture can override this value,
 * perhaps setting it to a cacheline in size (since that will maintain
 * cacheline alignment of the DMA). It must be a power of 2.
 *
 * Various parts of the networking layer expect at least 16 bytes of
 * headroom, you should not reduce this.
 */
#ifndef NET_SKB_PAD
#define NET_SKB_PAD	16
#endif

#ifndef HAVE_SKB_COW_HEAD
static inline int __skb_cow(struct sk_buff *skb, unsigned int headroom,
			    int cloned)
{
	int delta = 0;

	if (headroom < NET_SKB_PAD)
		headroom = NET_SKB_PAD;
	if (headroom > skb_headroom(skb))
		delta = headroom - skb_headroom(skb);

	if (delta || cloned)
		return pskb_expand_head(skb, ALIGN(delta, NET_SKB_PAD), 0,
					GFP_ATOMIC);
	return 0;
}

static inline int skb_cow_head(struct sk_buff *skb, unsigned int headroom)
{
	return __skb_cow(skb, headroom, skb_header_cloned(skb));
}
#endif	/* !HAVE_SKB_COW_HEAD */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
static inline int skb_clone_writable(struct sk_buff *skb, int len)
{
	return false;
}
#endif

#ifndef HAVE_SKB_DST_ACCESSOR_FUNCS
static inline struct dst_entry *skb_dst(const struct sk_buff *skb)
{
	return (struct dst_entry *)skb->dst;
}

static inline void skb_dst_set(struct sk_buff *skb, struct dst_entry *dst)
{
	skb->dst = dst;
}

static inline struct rtable *skb_rtable(const struct sk_buff *skb)
{
	return (struct rtable *)skb->dst;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
/* Emulate Linux 2.6.17 and later behavior, in which kfree_skb silently ignores
 * null pointer arguments. */
#define kfree_skb(skb) kfree_skb_maybe_null(skb)
static inline void kfree_skb_maybe_null(struct sk_buff *skb)
{
	if (likely(skb != NULL))
		(kfree_skb)(skb);
}
#endif


#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#endif
#ifndef CHECKSUM_COMPLETE
#define CHECKSUM_COMPLETE CHECKSUM_HW
#endif

#ifdef HAVE_MAC_RAW
#define mac_header mac.raw
#define network_header nh.raw
#define transport_header h.raw
#endif

#ifndef HAVE_SKBUFF_HEADER_HELPERS
static inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
	return skb->h.raw;
}

static inline void skb_reset_transport_header(struct sk_buff *skb)
{
	skb->h.raw = skb->data;
}

static inline void skb_set_transport_header(struct sk_buff *skb,
			const int offset)
{
	skb->h.raw = skb->data + offset;
}

static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
	return skb->nh.raw;
}

static inline void skb_reset_network_header(struct sk_buff *skb)
{
	skb->nh.raw = skb->data;
}

static inline void skb_set_network_header(struct sk_buff *skb, const int offset)
{
	skb->nh.raw = skb->data + offset;
}

static inline unsigned char *skb_mac_header(const struct sk_buff *skb)
{
	return skb->mac.raw;
}

static inline void skb_reset_mac_header(struct sk_buff *skb)
{
	skb->mac_header = skb->data;
}

static inline void skb_set_mac_header(struct sk_buff *skb, const int offset)
{
	skb->mac.raw = skb->data + offset;
}

static inline int skb_transport_offset(const struct sk_buff *skb)
{
	return skb_transport_header(skb) - skb->data;
}

static inline int skb_network_offset(const struct sk_buff *skb)
{
	return skb_network_header(skb) - skb->data;
}

static inline void skb_copy_to_linear_data(struct sk_buff *skb,
					   const void *from,
					   const unsigned int len)
{
	memcpy(skb->data, from, len);
}
#endif	/* !HAVE_SKBUFF_HEADER_HELPERS */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#warning "TSO/UFO not supported on kernels earlier than 2.6.18"

static inline int skb_is_gso(const struct sk_buff *skb)
{
	return 0;
}

static inline struct sk_buff *skb_gso_segment(struct sk_buff *skb,
					      int features)
{
	return NULL;
}
#endif	/* before 2.6.18 */

#ifndef HAVE_SKB_WARN_LRO
#ifndef NETIF_F_LRO
static inline bool skb_warn_if_lro(const struct sk_buff *skb)
{
	return false;
}
#else
extern void __skb_warn_lro_forwarding(const struct sk_buff *skb);

static inline bool skb_warn_if_lro(const struct sk_buff *skb)
{
	/* LRO sets gso_size but not gso_type, whereas if GSO is really
	 * wanted then gso_type will be set. */
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	if (shinfo->gso_size != 0 && unlikely(shinfo->gso_type == 0)) {
		__skb_warn_lro_forwarding(skb);
		return true;
	}
	return false;
}
#endif /* NETIF_F_LRO */
#endif /* HAVE_SKB_WARN_LRO */

#ifndef HAVE_CONSUME_SKB
#define consume_skb kfree_skb
#endif

#ifndef HAVE_SKB_FRAG_PAGE
static inline struct page *skb_frag_page(const skb_frag_t *frag)
{
	return frag->page;
}
#endif

#ifndef HAVE_SKB_RESET_MAC_LEN
static inline void skb_reset_mac_len(struct sk_buff *skb)
{
	skb->mac_len = skb->network_header - skb->mac_header;
}
#endif
#endif
