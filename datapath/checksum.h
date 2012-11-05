/*
 * Copyright (c) 2007-2011 Nicira, Inc.
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
int compute_ip_summed(struct sk_buff *skb, bool xmit);
void forward_ip_summed(struct sk_buff *skb, bool xmit);
u8 get_ip_summed(struct sk_buff *skb);
void set_ip_summed(struct sk_buff *skb, u8 ip_summed);
void get_skb_csum_pointers(const struct sk_buff *skb, u16 *csum_start,
			   u16 *csum_offset);
void set_skb_csum_pointers(struct sk_buff *skb, u16 csum_start,
			   u16 csum_offset);
#else
static inline int compute_ip_summed(struct sk_buff *skb, bool xmit)
{
	return 0;
}

static inline void forward_ip_summed(struct sk_buff *skb, bool xmit) { }

static inline u8 get_ip_summed(struct sk_buff *skb)
{
	return skb->ip_summed;
}

static inline void set_ip_summed(struct sk_buff *skb, u8 ip_summed)
{
	skb->ip_summed = ip_summed;
}

static inline void get_skb_csum_pointers(const struct sk_buff *skb,
					 u16 *csum_start, u16 *csum_offset)
{
	*csum_start = skb->csum_start;
	*csum_offset = skb->csum_offset;
}

static inline void set_skb_csum_pointers(struct sk_buff *skb, u16 csum_start,
					 u16 csum_offset)
{
	skb->csum_start = csum_start;
	skb->csum_offset = csum_offset;
}
#endif

/* This is really compatibility code that belongs in the compat directory.
 * However, it needs access to our normalized checksum values, so put it here.
 */
#if defined(NEED_CSUM_NORMALIZE) || LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
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

#if defined(NEED_CSUM_NORMALIZE) || LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#define inet_proto_csum_replace16 rpl_inet_proto_csum_replace16
static inline void inet_proto_csum_replace16(__sum16 *sum,
					     struct sk_buff *skb,
					     const __be32 *from,
					     const __be32 *to,
					     int pseudohdr)
{
	__be32 diff[] = {
		~from[0], ~from[1], ~from[2], ~from[3],
		to[0], to[1], to[2], to[3],
	};
	if (get_ip_summed(skb) != OVS_CSUM_PARTIAL) {
		*sum = csum_fold(csum_partial(diff, sizeof(diff),
				 ~csum_unfold(*sum)));
		if (get_ip_summed(skb) == OVS_CSUM_COMPLETE && pseudohdr)
			skb->csum = ~csum_partial(diff, sizeof(diff),
						  ~skb->csum);
	} else if (pseudohdr)
		*sum = ~csum_fold(csum_partial(diff, sizeof(diff),
				  csum_unfold(*sum)));
}
#endif

#ifdef NEED_CSUM_NORMALIZE
static inline void update_csum_start(struct sk_buff *skb, int delta)
{
	if (get_ip_summed(skb) == OVS_CSUM_PARTIAL) {
		u16 csum_start, csum_offset;

		get_skb_csum_pointers(skb, &csum_start, &csum_offset);
		set_skb_csum_pointers(skb, csum_start + delta, csum_offset);
	}
}

static inline int rpl_pskb_expand_head(struct sk_buff *skb, int nhead,
				       int ntail, gfp_t gfp_mask)
{
	int err;
	int old_headroom = skb_headroom(skb);

	err = pskb_expand_head(skb, nhead, ntail, gfp_mask);
	if (unlikely(err))
		return err;

	update_csum_start(skb, skb_headroom(skb) - old_headroom);

	return 0;
}
#define pskb_expand_head rpl_pskb_expand_head

static inline unsigned char *rpl__pskb_pull_tail(struct sk_buff *skb,
						  int delta)
{
	unsigned char *ret;
	int old_headroom = skb_headroom(skb);

	ret = __pskb_pull_tail(skb, delta);
	if (unlikely(!ret))
		return ret;

	update_csum_start(skb, skb_headroom(skb) - old_headroom);

	return ret;
}
#define __pskb_pull_tail rpl__pskb_pull_tail
#endif

#endif /* checksum.h */
