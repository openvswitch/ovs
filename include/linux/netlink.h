#ifndef __UAPI_LINUX_NETLINK_WRAPPER_H
#define __UAPI_LINUX_NETLINK_WRAPPER_H 1

#if !defined(__KERNEL__) && !defined(HAVE_NLA_BITFIELD32)

#include <linux/types.h>

/* Generic 32 bitflags attribute content sent to the kernel.
 *
 * The value is a bitmap that defines the values being set
 * The selector is a bitmask that defines which value is legit
 *
 * Examples:
 *  value = 0x0, and selector = 0x1
 *  implies we are selecting bit 1 and we want to set its value to 0.
 *
 *  value = 0x2, and selector = 0x2
 *  implies we are selecting bit 2 and we want to set its value to 1.
 *
 */
struct nla_bitfield32 {
    __u32 value;
    __u32 selector;
};

#endif /* !__KERNEL__ && !HAVE_NLA_BITFIELD32 */

#include_next <linux/netlink.h>

#endif /* __UAPI_LINUX_NETLINK_WRAPPER_H */
