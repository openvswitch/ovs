#ifndef __NET_UDP_WRAPPER_H
#define __NET_UDP_WRAPPER_H  1

#include <linux/version.h>

#ifdef inet_get_local_port_range
/* RHEL7 backports udp_flow_src_port() using an older version of
 * inet_get_local_port_range(). */
#undef inet_get_local_port_range
#include_next <net/udp.h>
#define inet_get_local_port_range rpl_inet_get_local_port_range
#else
#include_next <net/udp.h>
#endif

#ifndef HAVE_UDP_FLOW_SRC_PORT
static inline __be16 rpl_udp_flow_src_port(struct net *net, struct sk_buff *skb,
                                           int min, int max, bool use_eth)
{
	u32 hash;

	if (min >= max) {
		/* Use default range */
		inet_get_local_port_range(net, &min, &max);
	}

	hash = skb_get_hash(skb);
	if (unlikely(!hash) && use_eth) {
		/* Can't find a normal hash, caller has indicated an Ethernet
		 * packet so use that to compute a hash.
		 */
		hash = jhash(skb->data, 2 * ETH_ALEN,
			     (__force u32) skb->protocol);
	}

	/* Since this is being sent on the wire obfuscate hash a bit
	 * to minimize possbility that any useful information to an
	 * attacker is leaked. Only upper 16 bits are relevant in the
	 * computation for 16 bit port value.
	 */
	hash ^= hash << 16;

	return htons((((u64) hash * (max - min)) >> 32) + min);
}

#define udp_flow_src_port rpl_udp_flow_src_port
#endif

#ifndef HAVE_UDP_V4_CHECK
static inline __sum16 udp_v4_check(int len, __be32 saddr,
				   __be32 daddr, __wsum base)
{
	return csum_tcpudp_magic(saddr, daddr, len, IPPROTO_UDP, base);
}
#endif

#ifndef HAVE_UDP_SET_CSUM
#define udp_set_csum rpl_udp_set_csum
void rpl_udp_set_csum(bool nocheck, struct sk_buff *skb,
		      __be32 saddr, __be32 daddr, int len);
#endif

#endif
