#ifndef __LINUX_SKBUFF_WRAPPER_H
#define __LINUX_SKBUFF_WRAPPER_H 1

#include_next <linux/skbuff.h>

#include <linux/version.h>

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


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
/* Note that CHECKSUM_PARTIAL is not implemented, but this allows us to at
 * least test against it: see update_csum() in forward.c. */
#define CHECKSUM_PARTIAL 3
#define CHECKSUM_COMPLETE CHECKSUM_HW
#endif /* linux kernel < 2.6.19 */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)

#define mac_header mac.raw
#define network_header nh.raw

static inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
	return skb->h.raw;
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
#endif /* linux kernel < 2.6.22 */

#endif
