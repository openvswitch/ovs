#ifndef __LINUX_PKT_CLS_WRAPPER_H
#define __LINUX_PKT_CLS_WRAPPER_H 1

#if defined(__KERNEL__) || defined(HAVE_TCA_FLOWER_KEY_CT_FLAGS_REPLY)
#include_next <linux/pkt_cls.h>
#else

#include <linux/types.h>
#include <linux/pkt_sched.h>

/* Action attributes */
enum {
	TCA_ACT_UNSPEC,
	TCA_ACT_KIND,
	TCA_ACT_OPTIONS,
	TCA_ACT_INDEX,
	TCA_ACT_STATS,
	TCA_ACT_PAD,
	TCA_ACT_COOKIE,
	TCA_ACT_FLAGS,
	__TCA_ACT_MAX
};

#define TCA_ACT_FLAGS_NO_PERCPU_STATS 1 /* Don't use percpu allocator for
                                         * actions stats.
                                         */

#define TCA_ACT_MAX __TCA_ACT_MAX
#define TCA_OLD_COMPAT (TCA_ACT_MAX+1)
#define TCA_ACT_MAX_PRIO 32
#define TCA_ACT_BIND	1
#define TCA_ACT_NOBIND	0
#define TCA_ACT_UNBIND	1
#define TCA_ACT_NOUNBIND	0
#define TCA_ACT_REPLACE		1
#define TCA_ACT_NOREPLACE	0

#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7

/* There is a special kind of actions called "extended actions",
 * which need a value parameter. These have a local opcode located in
 * the highest nibble, starting from 1. The rest of the bits
 * are used to carry the value. These two parts together make
 * a combined opcode.
 */
#define __TC_ACT_EXT_SHIFT 28
#define __TC_ACT_EXT(local) ((local) << __TC_ACT_EXT_SHIFT)
#define TC_ACT_EXT_VAL_MASK ((1 << __TC_ACT_EXT_SHIFT) - 1)
#define TC_ACT_EXT_CMP(combined, opcode) \
	(((combined) & (~TC_ACT_EXT_VAL_MASK)) == opcode)

#define TC_ACT_JUMP __TC_ACT_EXT(1)
#define TC_ACT_GOTO_CHAIN __TC_ACT_EXT(2)

struct tc_police {
	__u32			index;
	int			action;
#define TC_POLICE_UNSPEC	TC_ACT_UNSPEC
#define TC_POLICE_OK		TC_ACT_OK
#define TC_POLICE_RECLASSIFY	TC_ACT_RECLASSIFY
#define TC_POLICE_SHOT		TC_ACT_SHOT
#define TC_POLICE_PIPE		TC_ACT_PIPE

	__u32			limit;
	__u32			burst;
	__u32			mtu;
	struct tc_ratespec	rate;
	struct tc_ratespec	peakrate;
	int			refcnt;
	int			bindcnt;
	__u32			capab;
};

struct tcf_t {
	__u64   install;
	__u64   lastuse;
	__u64   expires;
#ifdef HAVE_STRUCT_TCF_T_FIRSTUSE
	__u64   firstuse;
#endif
};

#define tc_gen \
	__u32                 index; \
	__u32                 capab; \
	int                   action; \
	int                   refcnt; \
	int                   bindcnt

enum {
	TCA_POLICE_UNSPEC,
	TCA_POLICE_TBF,
	TCA_POLICE_RATE,
	TCA_POLICE_PEAKRATE,
	TCA_POLICE_AVRATE,
	TCA_POLICE_RESULT,
	TCA_POLICE_TM,
	TCA_POLICE_PAD,
	__TCA_POLICE_MAX
#define TCA_POLICE_RESULT TCA_POLICE_RESULT
};

/* tca flags definitions */
#define TCA_CLS_FLAGS_SKIP_HW	(1 << 0) /* don't offload filter to HW */
#define TCA_CLS_FLAGS_SKIP_SW	(1 << 1) /* don't use filter in SW */
#define TCA_CLS_FLAGS_IN_HW	(1 << 2) /* filter is offloaded to HW */
#define TCA_CLS_FLAGS_NOT_IN_HW (1 << 3) /* filter isn't offloaded to HW */

/* Basic filter */

enum {
	TCA_BASIC_UNSPEC,
	TCA_BASIC_CLASSID,
	TCA_BASIC_EMATCHES,
	TCA_BASIC_ACT,
	TCA_BASIC_POLICE,
	__TCA_BASIC_MAX
};

/* Flower classifier */

enum {
	TCA_FLOWER_UNSPEC,
	TCA_FLOWER_CLASSID,
	TCA_FLOWER_INDEV,
	TCA_FLOWER_ACT,
	TCA_FLOWER_KEY_ETH_DST,		/* ETH_ALEN */
	TCA_FLOWER_KEY_ETH_DST_MASK,	/* ETH_ALEN */
	TCA_FLOWER_KEY_ETH_SRC,		/* ETH_ALEN */
	TCA_FLOWER_KEY_ETH_SRC_MASK,	/* ETH_ALEN */
	TCA_FLOWER_KEY_ETH_TYPE,	/* be16 */
	TCA_FLOWER_KEY_IP_PROTO,	/* u8 */
	TCA_FLOWER_KEY_IPV4_SRC,	/* be32 */
	TCA_FLOWER_KEY_IPV4_SRC_MASK,	/* be32 */
	TCA_FLOWER_KEY_IPV4_DST,	/* be32 */
	TCA_FLOWER_KEY_IPV4_DST_MASK,	/* be32 */
	TCA_FLOWER_KEY_IPV6_SRC,	/* struct in6_addr */
	TCA_FLOWER_KEY_IPV6_SRC_MASK,	/* struct in6_addr */
	TCA_FLOWER_KEY_IPV6_DST,	/* struct in6_addr */
	TCA_FLOWER_KEY_IPV6_DST_MASK,	/* struct in6_addr */
	TCA_FLOWER_KEY_TCP_SRC,		/* be16 */
	TCA_FLOWER_KEY_TCP_DST,		/* be16 */
	TCA_FLOWER_KEY_UDP_SRC,		/* be16 */
	TCA_FLOWER_KEY_UDP_DST,		/* be16 */

	TCA_FLOWER_FLAGS,
	TCA_FLOWER_KEY_VLAN_ID,		/* be16 */
	TCA_FLOWER_KEY_VLAN_PRIO,	/* u8   */
	TCA_FLOWER_KEY_VLAN_ETH_TYPE,	/* be16 */

	TCA_FLOWER_KEY_ENC_KEY_ID,	/* be32 */
	TCA_FLOWER_KEY_ENC_IPV4_SRC,	/* be32 */
	TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK,/* be32 */
	TCA_FLOWER_KEY_ENC_IPV4_DST,	/* be32 */
	TCA_FLOWER_KEY_ENC_IPV4_DST_MASK,/* be32 */
	TCA_FLOWER_KEY_ENC_IPV6_SRC,	/* struct in6_addr */
	TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK,/* struct in6_addr */
	TCA_FLOWER_KEY_ENC_IPV6_DST,	/* struct in6_addr */
	TCA_FLOWER_KEY_ENC_IPV6_DST_MASK,/* struct in6_addr */

	TCA_FLOWER_KEY_TCP_SRC_MASK,	/* be16 */
	TCA_FLOWER_KEY_TCP_DST_MASK,	/* be16 */
	TCA_FLOWER_KEY_UDP_SRC_MASK,	/* be16 */
	TCA_FLOWER_KEY_UDP_DST_MASK,	/* be16 */
	TCA_FLOWER_KEY_SCTP_SRC_MASK,	/* be16 */
	TCA_FLOWER_KEY_SCTP_DST_MASK,	/* be16 */

	TCA_FLOWER_KEY_SCTP_SRC,	/* be16 */
	TCA_FLOWER_KEY_SCTP_DST,	/* be16 */

	TCA_FLOWER_KEY_ENC_UDP_SRC_PORT,	/* be16 */
	TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK,	/* be16 */
	TCA_FLOWER_KEY_ENC_UDP_DST_PORT,	/* be16 */
	TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK,	/* be16 */

	TCA_FLOWER_KEY_FLAGS,		/* be32 */
	TCA_FLOWER_KEY_FLAGS_MASK,	/* be32 */

	TCA_FLOWER_KEY_ICMPV4_CODE,	/* u8 */
	TCA_FLOWER_KEY_ICMPV4_CODE_MASK,/* u8 */
	TCA_FLOWER_KEY_ICMPV4_TYPE,	/* u8 */
	TCA_FLOWER_KEY_ICMPV4_TYPE_MASK,/* u8 */
	TCA_FLOWER_KEY_ICMPV6_CODE,	/* u8 */
	TCA_FLOWER_KEY_ICMPV6_CODE_MASK,/* u8 */
	TCA_FLOWER_KEY_ICMPV6_TYPE,	/* u8 */
	TCA_FLOWER_KEY_ICMPV6_TYPE_MASK,/* u8 */

	TCA_FLOWER_KEY_ARP_SIP,		/* be32 */
	TCA_FLOWER_KEY_ARP_SIP_MASK,	/* be32 */
	TCA_FLOWER_KEY_ARP_TIP,		/* be32 */
	TCA_FLOWER_KEY_ARP_TIP_MASK,	/* be32 */
	TCA_FLOWER_KEY_ARP_OP,		/* u8 */
	TCA_FLOWER_KEY_ARP_OP_MASK,	/* u8 */
	TCA_FLOWER_KEY_ARP_SHA,		/* ETH_ALEN */
	TCA_FLOWER_KEY_ARP_SHA_MASK,	/* ETH_ALEN */
	TCA_FLOWER_KEY_ARP_THA,		/* ETH_ALEN */
	TCA_FLOWER_KEY_ARP_THA_MASK,	/* ETH_ALEN */

	TCA_FLOWER_KEY_MPLS_TTL,	/* u8 - 8 bits */
	TCA_FLOWER_KEY_MPLS_BOS,	/* u8 - 1 bit */
	TCA_FLOWER_KEY_MPLS_TC,		/* u8 - 3 bits */
	TCA_FLOWER_KEY_MPLS_LABEL,	/* be32 - 20 bits */

	TCA_FLOWER_KEY_TCP_FLAGS,	/* be16 */
	TCA_FLOWER_KEY_TCP_FLAGS_MASK,	/* be16 */

	TCA_FLOWER_KEY_IP_TOS,		/* u8 */
	TCA_FLOWER_KEY_IP_TOS_MASK,	/* u8 */
	TCA_FLOWER_KEY_IP_TTL,		/* u8 */
	TCA_FLOWER_KEY_IP_TTL_MASK,	/* u8 */

	TCA_FLOWER_KEY_CVLAN_ID,	/* be16 */
	TCA_FLOWER_KEY_CVLAN_PRIO,	/* u8   */
	TCA_FLOWER_KEY_CVLAN_ETH_TYPE,	/* be16 */

	TCA_FLOWER_KEY_ENC_IP_TOS,	/* u8 */
	TCA_FLOWER_KEY_ENC_IP_TOS_MASK,	/* u8 */
	TCA_FLOWER_KEY_ENC_IP_TTL,	/* u8 */
	TCA_FLOWER_KEY_ENC_IP_TTL_MASK,	/* u8 */

	TCA_FLOWER_KEY_ENC_OPTS,
	TCA_FLOWER_KEY_ENC_OPTS_MASK,

	TCA_FLOWER_IN_HW_COUNT,

	TCA_FLOWER_KEY_PORT_SRC_MIN,	/* be16 */
	TCA_FLOWER_KEY_PORT_SRC_MAX,	/* be16 */
	TCA_FLOWER_KEY_PORT_DST_MIN,	/* be16 */
	TCA_FLOWER_KEY_PORT_DST_MAX,	/* be16 */

	TCA_FLOWER_KEY_CT_STATE,	/* u16 */
	TCA_FLOWER_KEY_CT_STATE_MASK,	/* u16 */
	TCA_FLOWER_KEY_CT_ZONE,		/* u16 */
	TCA_FLOWER_KEY_CT_ZONE_MASK,	/* u16 */
	TCA_FLOWER_KEY_CT_MARK,		/* u32 */
	TCA_FLOWER_KEY_CT_MARK_MASK,	/* u32 */
	TCA_FLOWER_KEY_CT_LABELS,	/* u128 */
	TCA_FLOWER_KEY_CT_LABELS_MASK,	/* u128 */

	__TCA_FLOWER_MAX,
};

#define TCA_FLOWER_MAX (__TCA_FLOWER_MAX - 1)

enum {
	TCA_FLOWER_KEY_CT_FLAGS_NEW = 1 << 0, /* Beginning of a new connection. */
	TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED = 1 << 1, /* Part of an existing connection. */
	TCA_FLOWER_KEY_CT_FLAGS_RELATED = 1 << 2, /* Related to an established connection. */
	TCA_FLOWER_KEY_CT_FLAGS_TRACKED = 1 << 3, /* Conntrack has occurred. */
	TCA_FLOWER_KEY_CT_FLAGS_INVALID = 1 << 4, /* Conntrack is invalid. */
	TCA_FLOWER_KEY_CT_FLAGS_REPLY = 1 << 5, /* Packet is in the reply direction. */
	__TCA_FLOWER_KEY_CT_FLAGS_MAX,
};

enum {
	TCA_FLOWER_KEY_ENC_OPTS_UNSPEC,
	TCA_FLOWER_KEY_ENC_OPTS_GENEVE, /* Nested
					 * TCA_TUNNEL_KEY_ENC_OPTS_GENEVE
					 * attributes
					 */
	__TCA_FLOWER_KEY_ENC_OPTS_MAX,
};

#define TCA_FLOWER_KEY_ENC_OPTS_MAX (__TCA_FLOWER_KEY_ENC_OPTS_MAX - 1)

enum {
	TCA_FLOWER_KEY_ENC_OPT_GENEVE_UNSPEC,
	TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS,            /* u16 */
	TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE,             /* u8 */
	TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA,             /* 4 to 128 bytes */

	__TCA_FLOWER_KEY_ENC_OPT_GENEVE_MAX,
};

#define TCA_FLOWER_KEY_ENC_OPT_GENEVE_MAX \
		(__TCA_FLOWER_KEY_ENC_OPT_GENEVE_MAX - 1)

enum {
	TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT = (1 << 0),
	TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST = (1 << 1),
};

/* Match-all classifier */

enum {
	TCA_MATCHALL_UNSPEC,
	TCA_MATCHALL_CLASSID,
	TCA_MATCHALL_ACT,
	TCA_MATCHALL_FLAGS,
	__TCA_MATCHALL_MAX,
};

#define TCA_MATCHALL_MAX (__TCA_MATCHALL_MAX - 1)

#endif /* __KERNEL__ || !HAVE_TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST */

#endif /* __LINUX_PKT_CLS_WRAPPER_H */
