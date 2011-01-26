#ifndef __NET_NET_NAMESPACE_WRAPPER_H
#define __NET_NET_NAMESPACE_WRAPPER_H 1

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
/* <net/net_namespace.h> exists, go ahead and include it. */
#include_next <net/net_namespace.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#define INIT_NET_GENL_SOCK init_net.genl_sock
#else
#define INIT_NET_GENL_SOCK genl_sock
#endif

#endif /* net/net_namespace.h wrapper */
