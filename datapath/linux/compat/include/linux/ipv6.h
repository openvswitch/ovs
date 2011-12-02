#ifndef __LINUX_IPV6_WRAPPER_H
#define __LINUX_IPV6_WRAPPER_H 1

#include_next <linux/ipv6.h>
#include <net/ipv6.h>

#ifndef HAVE_SKBUFF_HEADER_HELPERS
static inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
	return (struct ipv6hdr *)skb_network_header(skb);
}
#endif

/* This function is upstream but not the version which supplies the
 * fragment offset.  We plan to propose the extended version.
 */
#define ipv6_skip_exthdr rpl_ipv6_skip_exthdr
extern int rpl_ipv6_skip_exthdr(const struct sk_buff *skb, int start,
				u8 *nexthdrp, __be16 *frag_offp);

#endif
