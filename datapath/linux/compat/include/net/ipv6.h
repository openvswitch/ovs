#ifndef __NET_IPV6_WRAPPER_H
#define __NET_IPV6_WRAPPER_H 1

#include <linux/version.h>

#include_next <net/ipv6.h>

#ifndef NEXTHDR_SCTP
#define NEXTHDR_SCTP    132 /* Stream Control Transport Protocol */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
#define ipv6_skip_exthdr rpl_ipv6_skip_exthdr
extern int rpl_ipv6_skip_exthdr(const struct sk_buff *skb, int start,
			        u8 *nexthdrp, __be16 *frag_offp);
#endif

#ifndef HAVE_IP6_FH_F_SKIP_RH

enum {
	IP6_FH_F_FRAG           = (1 << 0),
	IP6_FH_F_AUTH           = (1 << 1),
	IP6_FH_F_SKIP_RH        = (1 << 2),
};

/* This function is upstream, but not the version which skips routing
 * headers with 0 segments_left. We fixed it when we introduced
 * IP6_FH_F_SKIP_RH.
 */
#define ipv6_find_hdr rpl_ipv6_find_hdr
extern int rpl_ipv6_find_hdr(const struct sk_buff *skb, unsigned int *offset,
			     int target, unsigned short *fragoff, int *fragflg);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
static inline u32 ipv6_addr_hash(const struct in6_addr *a)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	const unsigned long *ul = (const unsigned long *)a;
	unsigned long x = ul[0] ^ ul[1];

	return (u32)(x ^ (x >> 32));
#else
	return (__force u32)(a->s6_addr32[0] ^ a->s6_addr32[1] ^
			     a->s6_addr32[2] ^ a->s6_addr32[3]);
#endif
}
#endif

#endif
