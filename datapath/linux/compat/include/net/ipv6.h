#ifndef __NET_IPV6_WRAPPER_H
#define __NET_IPV6_WRAPPER_H 1

#include <linux/version.h>

#include_next <net/ipv6.h>

#ifndef NEXTHDR_SCTP
#define NEXTHDR_SCTP    132 /* Stream Control Transport Protocol */
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

#ifndef HAVE___IPV6_ADDR_JHASH
static inline u32 __ipv6_addr_jhash(const struct in6_addr *a, const u32 unused)
{
       return ipv6_addr_jhash(a);
}
#endif

#define ip6_flowlabel rpl_ip6_flowlabel
static inline __be32 ip6_flowlabel(const struct ipv6hdr *hdr)
{
	return *(__be32 *)hdr & IPV6_FLOWLABEL_MASK;
}

#ifndef HAVE_IP6_MAKE_FLOWLABEL_FL6
#define ip6_make_flowlabel rpl_ip6_make_flowlabel
static inline __be32 rpl_ip6_make_flowlabel(struct net *net,
					    struct sk_buff *skb,
					    __be32 flowlabel, bool autolabel,
					    struct flowi6 *fl6)
{
#ifndef HAVE_NETNS_SYSCTL_IPV6_AUTO_FLOWLABELS
	if (!flowlabel && autolabel) {
#else
	if (!flowlabel && (autolabel || net->ipv6.sysctl.auto_flowlabels)) {
#endif
		u32 hash;

		hash = skb_get_hash(skb);

		/* Since this is being sent on the wire obfuscate hash a bit
		 * to minimize possbility that any useful information to an
		 * attacker is leaked. Only lower 20 bits are relevant.
		 */
		hash ^= hash >> 12;

		flowlabel = (__force __be32)hash & IPV6_FLOWLABEL_MASK;
	}

	return flowlabel;
}
#endif

#ifndef IPV6_TCLASS_SHIFT
#define IPV6_TCLASS_MASK (IPV6_FLOWINFO_MASK & ~IPV6_FLOWLABEL_MASK)
#define IPV6_TCLASS_SHIFT	20
#endif

#define ip6_tclass rpl_ip6_tclass
static inline u8 ip6_tclass(__be32 flowinfo)
{
	return ntohl(flowinfo & IPV6_TCLASS_MASK) >> IPV6_TCLASS_SHIFT;
}

#define ip6_make_flowinfo rpl_ip6_make_flowinfo
static inline __be32 ip6_make_flowinfo(unsigned int tclass, __be32 flowlabel)
{
	return htonl(tclass << IPV6_TCLASS_SHIFT) | flowlabel;
}

#endif
