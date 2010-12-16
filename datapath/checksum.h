/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef CHECKSUM_H
#define CHECKSUM_H 1

#include <linux/skbuff.h>
#include <linux/version.h>

#include <net/checksum.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22) || \
	(defined(CONFIG_XEN) && defined(HAVE_PROTO_DATA_VALID))
#define NEED_CSUM_NORMALIZE
#endif

/* These are the same values as the checksum constants in 2.6.22+. */
enum csum_type {
	OVS_CSUM_NONE = 0,
	OVS_CSUM_UNNECESSARY = 1,
	OVS_CSUM_COMPLETE = 2,
	OVS_CSUM_PARTIAL = 3,
};

#ifdef NEED_CSUM_NORMALIZE
void compute_ip_summed(struct sk_buff *skb, bool xmit);
u8 get_ip_summed(struct sk_buff *skb);
#else
static inline void compute_ip_summed(struct sk_buff *skb, bool xmit) { }
static inline u8 get_ip_summed(struct sk_buff *skb)
{
	return skb->ip_summed;
}
#endif

/* This function closely resembles skb_forward_csum() used by the bridge.  It
 * is slightly different because we are only concerned with bridging and not
 * other types of forwarding and can get away with slightly more optimal
 * behavior.
 */
static inline void forward_ip_summed(struct sk_buff *skb)
{
#ifdef CHECKSUM_HW
	if (get_ip_summed(skb) == OVS_CSUM_COMPLETE)
		skb->ip_summed = CHECKSUM_NONE;
#endif
}

#if defined(CONFIG_XEN) && defined(HAVE_PROTO_DATA_VALID)
int vswitch_skb_checksum_setup(struct sk_buff *skb);
#else
static inline int vswitch_skb_checksum_setup(struct sk_buff *skb)
{
	return 0;
}
#endif

static inline void set_skb_csum_bits(const struct sk_buff *old_skb,
				     struct sk_buff *new_skb)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	/* Before 2.6.24 these fields were not copied when
	 * doing an skb_copy_expand. */
	new_skb->ip_summed = old_skb->ip_summed;
	new_skb->csum = old_skb->csum;
#endif
#if defined(CONFIG_XEN) && defined(HAVE_PROTO_DATA_VALID)
	/* These fields are copied in skb_clone but not in
	 * skb_copy or related functions.  We need to manually
	 * copy them over here. */
	new_skb->proto_data_valid = old_skb->proto_data_valid;
	new_skb->proto_csum_blank = old_skb->proto_csum_blank;
#endif
}

static inline void get_skb_csum_pointers(const struct sk_buff *skb,
					 u16 *csum_start, u16 *csum_offset)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	*csum_start = skb->csum_start;
	*csum_offset = skb->csum_offset;
#else
	*csum_start = skb_headroom(skb) + skb_transport_offset(skb);
	*csum_offset = skb->csum;
#endif
}

static inline void set_skb_csum_pointers(struct sk_buff *skb, u16 csum_start,
					 u16 csum_offset)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	skb->csum_start = csum_start;
	skb->csum_offset = csum_offset;
#else
	skb_set_transport_header(skb, csum_start - skb_headroom(skb));
	skb->csum = csum_offset;
#endif
}

#if defined(NEED_CSUM_NORMALIZE) || LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
/* This is really compatibility code that belongs in the compat directory.
 * However, it needs access to our normalized checksum values, so put it here.
 */
#define inet_proto_csum_replace4 rpl_inet_proto_csum_replace4
static inline void inet_proto_csum_replace4(__sum16 *sum, struct sk_buff *skb,
					    __be32 from, __be32 to,
					    int pseudohdr)
{
	__be32 diff[] = { ~from, to };

	if (get_ip_summed(skb) != OVS_CSUM_PARTIAL) {
		*sum = csum_fold(csum_partial((char *)diff, sizeof(diff),
				~csum_unfold(*sum)));
		if (get_ip_summed(skb) == OVS_CSUM_COMPLETE && pseudohdr)
			skb->csum = ~csum_partial((char *)diff, sizeof(diff),
						~skb->csum);
	} else if (pseudohdr)
		*sum = ~csum_fold(csum_partial((char *)diff, sizeof(diff),
				csum_unfold(*sum)));
}
#endif

#endif /* checksum.h */
