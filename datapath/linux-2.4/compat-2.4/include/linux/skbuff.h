#ifndef __LINUX_SKBUFF_WRAPPER_H
#define __LINUX_SKBUFF_WRAPPER_H 1

#include_next <linux/skbuff.h>


#define mac_header mac.raw
#define network_header nh.raw

/* Emulate Linux 2.6 behavior, in which kfree_skb silently ignores null pointer
 * arguments. */
#define kfree_skb(skb) kfree_skb_maybe_null(skb)
static inline void kfree_skb_maybe_null(struct sk_buff *skb) 
{
	if (likely(skb != NULL))
		(kfree_skb)(skb);
}

/* Note that CHECKSUM_PARTIAL is not implemented, but this allows us to at
 * least test against it: see update_csum() in forward.c. */
#define CHECKSUM_PARTIAL 3
#define CHECKSUM_COMPLETE CHECKSUM_HW

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

static inline int skb_mac_header_was_set(const struct sk_buff *skb)
{
	return skb->mac.raw != NULL;
}

static inline void skb_reset_mac_header(struct sk_buff *skb)
{
	skb->mac.raw = skb->data;
}

static inline void skb_set_mac_header(struct sk_buff *skb, const int offset)
{
	skb->mac.raw = skb->data + offset;
}
static inline int skb_transport_offset(const struct sk_buff *skb)
{
	return skb_transport_header(skb) - skb->data;
}

static inline u32 skb_network_header_len(const struct sk_buff *skb)
{
	return skb->h.raw - skb->nh.raw;
}

static inline int skb_network_offset(const struct sk_buff *skb)
{
	return skb_network_header(skb) - skb->data;
}

static inline unsigned char *skb_tail_pointer(const struct sk_buff *skb)
{
	return skb->tail;
}

static inline void skb_reset_tail_pointer(struct sk_buff *skb)
{
	skb->tail = skb->data;
}

static inline void skb_set_tail_pointer(struct sk_buff *skb, const int offset)
{
	skb->tail = skb->data + offset;
}

/*
 * CPUs often take a performance hit when accessing unaligned memory
 * locations. The actual performance hit varies, it can be small if the
 * hardware handles it or large if we have to take an exception and fix it
 * in software.
 *
 * Since an ethernet header is 14 bytes network drivers often end up with
 * the IP header at an unaligned offset. The IP header can be aligned by
 * shifting the start of the packet by 2 bytes. Drivers should do this
 * with:
 *
 * skb_reserve(NET_IP_ALIGN);
 *
 * The downside to this alignment of the IP header is that the DMA is now
 * unaligned. On some architectures the cost of an unaligned DMA is high
 * and this cost outweighs the gains made by aligning the IP header.
 *
 * Since this trade off varies between architectures, we allow NET_IP_ALIGN
 * to be overridden.
 */
#ifndef NET_IP_ALIGN
#define NET_IP_ALIGN	2
#endif

static inline void skb_copy_to_linear_data(struct sk_buff *skb,
					   const void *from,
					   const unsigned int len)
{
	memcpy(skb->data, from, len);
}

#endif
