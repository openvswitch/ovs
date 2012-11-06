#ifndef __NET_IPV6_WRAPPER_H
#define __NET_IPV6_WRAPPER_H 1

#include_next <net/ipv6.h>

enum {
	OVS_IP6T_FH_F_FRAG	= (1 << 0),
	OVS_IP6T_FH_F_AUTH	= (1 << 1),
	OVS_IP6T_FH_F_SKIP_RH	= (1 << 2),
};

/* This function is upstream but not the version which supplies the
 * fragment offset.  We plan to propose the extended version.
 */
#define ipv6_skip_exthdr rpl_ipv6_skip_exthdr
extern int ipv6_skip_exthdr(const struct sk_buff *skb, int start,
				u8 *nexthdrp, __be16 *frag_offp);

/* This function is upstream, but not the version which skips routing
 * headers with 0 segments_left. We plan to propose the extended version. */
#define ipv6_find_hdr rpl_ipv6_find_hdr
extern int ipv6_find_hdr(const struct sk_buff *skb, unsigned int *offset,
			 int target, unsigned short *fragoff, int *fragflg);

#endif
