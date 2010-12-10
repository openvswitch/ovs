#ifndef __NET_NETLINK_WRAPPER_H
#define __NET_NETLINK_WRAPPER_H 1

#include <linux/version.h>
#include_next <net/netlink.h>

#ifndef HAVE_NLA_NUL_STRING
#define NLA_NUL_STRING NLA_STRING

static inline int VERIFY_NUL_STRING(struct nlattr *attr)
{
	return (!attr || (nla_len(attr)
			  && memchr(nla_data(attr), '\0', nla_len(attr)))
		? 0 : EINVAL);
}
#else
static inline int VERIFY_NUL_STRING(struct nlattr *attr)
{
	return 0;
}
#endif	/* !HAVE_NLA_NUL_STRING */


#ifndef NLA_PUT_BE16
#define NLA_PUT_BE16(skb, attrtype, value) \
        NLA_PUT_TYPE(skb, __be16, attrtype, value)
#endif  /* !NLA_PUT_BE16 */


#ifndef HAVE_NLA_GET_BE16
/**
 * nla_get_be16 - return payload of __be16 attribute
 * @nla: __be16 netlink attribute
 */
static inline __be16 nla_get_be16(struct nlattr *nla)
{
        return *(__be16 *) nla_data(nla);
}
#endif  /* !HAVE_NLA_GET_BE16 */


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

#endif /* net/netlink.h */
