#ifndef __LINUX_NETLINK_WRAPPER_H
#define __LINUX_NETLINK_WRAPPER_H 1

#include <linux/skbuff.h>

#include_next <linux/netlink.h>

#define NETLINK_GENERIC                16

#undef NLMSG_LENGTH
#define NLMSG_HDRLEN    ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len)+NLMSG_ALIGN(NLMSG_HDRLEN))

#define NLMSG_MIN_TYPE         0x10    /* < 0x10: reserved control messages */

enum {
       NETLINK_UNCONNECTED = 0,
       NETLINK_CONNECTED,
};

/*
 *  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 * |        Header       | Pad |     Payload       | Pad |
 * |   (struct nlattr)   | ing |                   | ing |
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 *  <-------------- nlattr->nla_len -------------->
 */

struct nlattr
{
       __u16           nla_len;
       __u16           nla_type;
};

#define NLA_ALIGNTO            4
#define NLA_ALIGN(len)         (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN             ((int) NLA_ALIGN(sizeof(struct nlattr)))

#ifdef __KERNEL__

#include <linux/capability.h>
#include <linux/skbuff.h>

static inline struct nlmsghdr *nlmsg_hdr(const struct sk_buff *skb)
{
       return (struct nlmsghdr *)skb->data;
}

#define __nlmsg_put __rpl_nlmsg_put
static __inline__ struct nlmsghdr *
__nlmsg_put(struct sk_buff *skb, u32 pid, u32 seq, int type, int len, int flags)
{
        struct nlmsghdr *nlh;
        int size = NLMSG_LENGTH(len);

        nlh = (struct nlmsghdr*)skb_put(skb, NLMSG_ALIGN(size));
        nlh->nlmsg_type = type;
        nlh->nlmsg_len = size;
        nlh->nlmsg_flags = flags;
        nlh->nlmsg_pid = pid;
        nlh->nlmsg_seq = seq;
        memset(NLMSG_DATA(nlh) + len, 0, NLMSG_ALIGN(size) - size);
        return nlh;
}

#define NLMSG_DEFAULT_SIZE (NLMSG_GOODSIZE - NLMSG_HDRLEN)

#undef NLMSG_NEW
#define NLMSG_NEW(skb, pid, seq, type, len, flags) \
({      if (skb_tailroom(skb) < (int)NLMSG_SPACE(len)) \
                goto nlmsg_failure; \
        __nlmsg_put(skb, pid, seq, type, len, flags); })
#endif

#undef NLMSG_PUT
#define NLMSG_PUT(skb, pid, seq, type, len) \
        NLMSG_NEW(skb, pid, seq, type, len, 0)

#endif
