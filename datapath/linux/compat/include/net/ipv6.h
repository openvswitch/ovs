#ifndef __NET_IPV6_WRAPPER_H
#define __NET_IPV6_WRAPPER_H 1

#include_next <net/ipv6.h>

/* This function is upstream but not the version which supplies the
 * fragment offset.  We plan to propose the extended version.
 */
#define ipv6_skip_exthdr rpl_ipv6_skip_exthdr
extern int ipv6_skip_exthdr(const struct sk_buff *skb, int start,
				u8 *nexthdrp, __be16 *frag_offp);

#endif
