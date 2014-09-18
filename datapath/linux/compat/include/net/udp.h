#ifndef __NET_UDP_WRAPPER_H
#define __NET_UDP_WRAPPER_H  1

#include_next <net/udp.h>

#ifndef HAVE_UDP_FLOW_SRC_PORT
static inline __be16 udp_flow_src_port(struct net *net, struct sk_buff *skb,
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
#endif

#endif
