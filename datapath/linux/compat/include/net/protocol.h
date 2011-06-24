#ifndef __NET_PROTOCOL_WRAPPER_H
#define __NET_PROTOCOL_WRAPPER_H 1

#include_next <net/protocol.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define inet_add_protocol(prot, num) inet_add_protocol((struct net_protocol *)(prot), num)
#define inet_del_protocol(prot, num) inet_del_protocol((struct net_protocol *)(prot), num)
#endif

#endif
