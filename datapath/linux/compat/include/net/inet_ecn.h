#ifndef _INET_ECN_WRAPPER_H_
#define _INET_ECN_WRAPPER_H_

#include_next <net/inet_ecn.h>

#define INET_ECN_decapsulate rpl_INET_ECN_decapsulate
static inline int INET_ECN_decapsulate(struct sk_buff *skb,
				       __u8 outer, __u8 inner)
{
	if (INET_ECN_is_not_ect(inner)) {
		switch (outer & INET_ECN_MASK) {
			case INET_ECN_NOT_ECT:
				return 0;
			case INET_ECN_ECT_0:
			case INET_ECN_ECT_1:
				return 1;
			case INET_ECN_CE:
				return 2;
		}
	}

	if (INET_ECN_is_ce(outer))
		INET_ECN_set_ce(skb);

	return 0;
}

#define IP_ECN_decapsulate rpl_IP_ECN_decapsulate
static inline int IP_ECN_decapsulate(const struct iphdr *oiph,
		struct sk_buff *skb)
{
	__u8 inner;

	if (skb->protocol == htons(ETH_P_IP))
		inner = ip_hdr(skb)->tos;
	else if (skb->protocol == htons(ETH_P_IPV6))
		inner = ipv6_get_dsfield(ipv6_hdr(skb));
	else
		return 0;

	return INET_ECN_decapsulate(skb, oiph->tos, inner);
}

#define IP6_ECN_decapsulate rpl_IP6_ECN_decapsulate
static inline int IP6_ECN_decapsulate(const struct ipv6hdr *oipv6h,
				      struct sk_buff *skb)
{
	__u8 inner;

	if (skb->protocol == htons(ETH_P_IP))
		inner = ip_hdr(skb)->tos;
	else if (skb->protocol == htons(ETH_P_IPV6))
		inner = ipv6_get_dsfield(ipv6_hdr(skb));
	else
		return 0;

	return INET_ECN_decapsulate(skb, ipv6_get_dsfield(oipv6h), inner);
}
#endif
