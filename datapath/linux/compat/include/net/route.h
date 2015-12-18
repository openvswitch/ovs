#ifndef __NET_ROUTE_H_WRAPPER
#define __NET_ROUTE_H_WRAPPER

#include_next <net/route.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
struct flowi_common {
	int	flowic_oif;
	__u32   flowic_mark;
	__u8    flowic_tos;
	__u8    flowic_proto;
};

union flowi_uli {
	struct {
		__be16	dport;
		__be16	sport;
	} ports;

	struct {
		__u8	type;
		__u8	code;
	} icmpt;

	struct {
		__le16	dport;
		__le16	sport;
	} dnports;

	__be32		spi;
	__be32		gre_key;

	struct {
		__u8	type;
	} mht;
};

struct flowi4 {
	struct flowi_common	__fl_common;
#define flowi4_oif		__fl_common.flowic_oif
#define flowi4_iif		__fl_common.flowic_iif
#define flowi4_mark		__fl_common.flowic_mark
#define flowi4_tos		__fl_common.flowic_tos
#define flowi4_scope		__fl_common.flowic_scope
#define flowi4_proto		__fl_common.flowic_proto
#define flowi4_flags		__fl_common.flowic_flags
#define flowi4_secid		__fl_common.flowic_secid
#define flowi4_tun_key		__fl_common.flowic_tun_key

	union flowi_uli		uli;
#define fl4_gre_key		uli.gre_key

	/* (saddr,daddr) must be grouped, same order as in IP header */
	__be32			saddr;
	__be32			daddr;

} __attribute__((__aligned__(BITS_PER_LONG/8)));

struct flowi6 {
	struct flowi_common	__fl_common;
#define flowi6_oif		__fl_common.flowic_oif
#define flowi6_iif		__fl_common.flowic_iif
#define flowi6_mark		__fl_common.flowic_mark
#define flowi6_tos		__fl_common.flowic_tos
#define flowi6_scope		__fl_common.flowic_scope
#define flowi6_proto		__fl_common.flowic_proto
#define flowi6_flags		__fl_common.flowic_flags
#define flowi6_secid		__fl_common.flowic_secid
#define flowi6_tun_key		__fl_common.flowic_tun_key
	struct in6_addr		daddr;
	struct in6_addr		saddr;
	__be32			flowlabel;
	union flowi_uli		uli;
#define fl6_sport		uli.ports.sport
#define fl6_dport		uli.ports.dport
#define fl6_icmp_type		uli.icmpt.type
#define fl6_icmp_code		uli.icmpt.code
#define fl6_ipsec_spi		uli.spi
#define fl6_mh_type		uli.mht.type
#define fl6_gre_key		uli.gre_key
} __attribute__((__aligned__(BITS_PER_LONG/8)));

static inline struct rtable *rpl_ip_route_output_key(struct net *net, struct flowi4 *flp)
{
	struct rtable *rt;
	/* Tunnel configuration keeps DSCP part of TOS bits, But Linux
	 * router expect RT_TOS bits only.
	 */

	struct flowi fl = { .nl_u = { .ip4_u = {
					.daddr = flp->daddr,
					.saddr = flp->saddr,
					.tos   = RT_TOS(flp->flowi4_tos) } },
					.mark = flp->flowi4_mark,
					.proto = flp->flowi4_proto };

	if (unlikely(ip_route_output_key(net, &rt, &fl)))
		return ERR_PTR(-EADDRNOTAVAIL);
	flp->saddr = fl.nl_u.ip4_u.saddr;
	return rt;
}
#define ip_route_output_key rpl_ip_route_output_key
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
static inline int ip4_dst_hoplimit(const struct dst_entry *dst)
{
	return dst_metric(dst, RTAX_HOPLIMIT);
}
#endif
#endif
