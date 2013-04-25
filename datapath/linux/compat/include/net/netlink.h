#ifndef __NET_NETLINK_WRAPPER_H
#define __NET_NETLINK_WRAPPER_H 1

#include <linux/version.h>
#include_next <net/netlink.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
/* Before v2.6.29, a NLA_NESTED attribute, if it was present, was not allowed
 * to be empty.  However, OVS depends on the ability to accept empty
 * attributes.  For example, a present but empty OVS_FLOW_ATTR_ACTIONS on
 * OVS_FLOW_CMD_SET replaces the existing set of actions by an empty "drop"
 * action, whereas a missing OVS_FLOW_ATTR_ACTIONS leaves the existing
 * actions, if any, unchanged.
 *
 * NLA_NESTED is different from NLA_UNSPEC in only two ways:
 *
 * - If the size of the nested attributes is zero, no further size checks
 *   are performed.
 *
 * - If the size of the nested attributes is not zero and no length
 *   parameter is specified the minimum size of nested attributes is
 *   NLA_HDRLEN.
 *
 * nla_parse_nested() validates that there is at least enough space for
 * NLA_HDRLEN, so neither of these conditions are important, and we might
 * as well use NLA_UNSPEC with old kernels.
 */
#undef NLA_NESTED
#define NLA_NESTED NLA_UNSPEC
#endif

#ifndef HAVE_NLA_GET_BE16
/**
 * nla_get_be16 - return payload of __be16 attribute
 * @nla: __be16 netlink attribute
 */
static inline __be16 nla_get_be16(const struct nlattr *nla)
{
	return *(__be16 *) nla_data(nla);
}
#endif  /* !HAVE_NLA_GET_BE16 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
/**
 * nla_get_be32 - return payload of __be32 attribute
 * @nla: __be32 netlink attribute
 */
static inline __be32 nla_get_be32(const struct nlattr *nla)
{
	return *(__be32 *) nla_data(nla);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
/* These functions' nlattr source arguments weren't "const" before 2.6.29, so
 * cast their arguments to the non-"const" versions.  Using macros for this
 * isn't exactly a brilliant idea, but it seems less error-prone than copying
 * the definitions of all umpteen functions. */
#define nla_get_u64(nla)   (nla_get_u64)  ((struct nlattr *) (nla))
#define nla_get_u32(nla)   (nla_get_u32)  ((struct nlattr *) (nla))
#define nla_get_u16(nla)   (nla_get_u16)  ((struct nlattr *) (nla))
#define nla_get_u8(nla)    (nla_get_u8)   ((struct nlattr *) (nla))
/* nla_get_be64 is handled separately below. */
#define nla_get_be32(nla)  (nla_get_be32) ((struct nlattr *) (nla))
#define nla_get_be16(nla)  (nla_get_be16) ((struct nlattr *) (nla))
#define nla_get_be8(nla)   (nla_get_be8)  ((struct nlattr *) (nla))
#define nla_get_flag(nla)  (nla_get_flag) ((struct nlattr *) (nla))
#define nla_get_msecs(nla) (nla_get_msecs)((struct nlattr *) (nla))
#define nla_memcpy(dst, src, count) \
	(nla_memcpy)(dst, (struct nlattr *)(src), count)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
/* This function was introduced in 2.6.31, but initially it performed an
 * unaligned access, so we replace it up to 2.6.34 where it was fixed.  */
#define nla_get_be64 rpl_nla_get_be64
static inline __be64 nla_get_be64(const struct nlattr *nla)
{
	__be64 tmp;

	/* The additional cast is necessary because  */
	nla_memcpy(&tmp, (struct nlattr *) nla, sizeof(tmp));

	return tmp;
}
#endif

#ifndef HAVE_NLA_PUT_BE16
static inline int nla_put_be16(struct sk_buff *skb, int attrtype, __be16 value)
{
	return nla_put(skb, attrtype, sizeof(__be16), &value);
}
#endif

#ifndef HAVE_NLA_PUT_BE32
static inline int nla_put_be32(struct sk_buff *skb, int attrtype, __be32 value)
{
	return nla_put(skb, attrtype, sizeof(__be32), &value);
}
#endif

#ifndef HAVE_NLA_PUT_BE64
static inline int nla_put_be64(struct sk_buff *skb, int attrtype, __be64 value)
{
	return nla_put(skb, attrtype, sizeof(__be64), &value);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
/**
 * nla_type - attribute type
 * @nla: netlink attribute
 */
static inline int nla_type(const struct nlattr *nla)
{
	return nla->nla_type & NLA_TYPE_MASK;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#define nla_parse_nested(tb, maxtype, nla, policy) \
	nla_parse_nested(tb, maxtype, (struct nlattr *)(nla), \
			(struct nla_policy *)(policy))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
#define nla_parse_nested(tb, maxtype, nla, policy) \
	nla_parse_nested(tb, maxtype, (struct nlattr *)(nla), policy)
#endif

#ifndef nla_for_each_nested
#define nla_for_each_nested(pos, nla, rem) \
	nla_for_each_attr(pos, nla_data(nla), nla_len(nla), rem)
#endif

#ifndef HAVE_NLA_FIND_NESTED
static inline struct nlattr *nla_find_nested(struct nlattr *nla, int attrtype)
{
	return nla_find(nla_data(nla), nla_len(nla), attrtype);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
/**
 * nlmsg_report - need to report back to application?
 * @nlh: netlink message header
 *
 * Returns 1 if a report back to the application is requested.
 */
static inline int nlmsg_report(const struct nlmsghdr *nlh)
{
	return !!(nlh->nlmsg_flags & NLM_F_ECHO);
}

extern int		nlmsg_notify(struct sock *sk, struct sk_buff *skb,
				     u32 portid, unsigned int group, int report,
				     gfp_t flags);
#endif	/* linux kernel < 2.6.19 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
/* Before 2.6.19 the 'flags' parameter was missing, so replace it.  We have to
 * #include <net/genetlink.h> first because the 2.6.18 version of that header
 * has an inline call to nlmsg_multicast() without, of course, any 'flags'
 * argument. */
#define nlmsg_multicast rpl_nlmsg_multicast
static inline int nlmsg_multicast(struct sock *sk, struct sk_buff *skb,
				  u32 portid, unsigned int group, gfp_t flags)
{
	int err;

	NETLINK_CB(skb).dst_group = group;

	err = netlink_broadcast(sk, skb, portid, group, flags);
	if (err > 0)
		err = 0;

	return err;
}
#endif	/* linux kernel < 2.6.19 */

#endif /* net/netlink.h */
