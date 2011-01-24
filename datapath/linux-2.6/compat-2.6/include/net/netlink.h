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
		? 0 : -EINVAL);
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

#ifndef NLA_PUT_BE32
#define NLA_PUT_BE32(skb, attrtype, value) \
        NLA_PUT_TYPE(skb, __be32, attrtype, value)
#endif  /* !NLA_PUT_BE32 */

#ifndef NLA_PUT_BE64
#define NLA_PUT_BE64(skb, attrtype, value) \
        NLA_PUT_TYPE(skb, __be64, attrtype, value)
#endif  /* !NLA_PUT_BE64 */

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

/* The following nla_put_be{16,32,64} functions are not in any version of Linux
 * (although NLA_PUT_BE{16,32,64} are), so we will probably want to add them
 * as part of the patch series when we submit Open vSwitch upstream. */

/**
 * nla_put_be16 - Add a be16 netlink attribute to a socket buffer
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @value: numeric value
 */
static inline int nla_put_be16(struct sk_buff *skb, int attrtype, __be16 value)
{
	return nla_put(skb, attrtype, sizeof(__be16), &value);
}

/**
 * nla_put_be32 - Add a be32 netlink attribute to a socket buffer
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @value: numeric value
 */
static inline int nla_put_be32(struct sk_buff *skb, int attrtype, __be32 value)
{
	return nla_put(skb, attrtype, sizeof(__be32), &value);
}

/**
 * nla_put_64 - Add a be64 netlink attribute to a socket buffer
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @value: numeric value
 */
static inline int nla_put_be64(struct sk_buff *skb, int attrtype, __be64 value)
{
	return nla_put(skb, attrtype, sizeof(__be64), &value);
}

#endif /* net/netlink.h */
