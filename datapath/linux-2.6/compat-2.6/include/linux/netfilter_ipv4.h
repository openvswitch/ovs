#ifndef __LINUX_NETFILTER_IPV4_WRAPPER_H
#define __LINUX_NETFILTER_IPV4_WRAPPER_H 1

#include_next <linux/netfilter_ipv4.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#ifdef __KERNEL__

#define NF_INET_PRE_ROUTING NF_IP_PRE_ROUTING
#define NF_INET_POST_ROUTING NF_IP_POST_ROUTING
#define NF_INET_FORWARD NF_IP_FORWARD

#endif /* __KERNEL__ */

#endif /* linux kernel < 2.6.25 */

#endif
