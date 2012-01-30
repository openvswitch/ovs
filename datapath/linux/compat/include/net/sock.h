#ifndef __NET_SOCK_WRAPPER_H
#define __NET_SOCK_WRAPPER_H 1

#include_next <net/sock.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
struct net;

static inline struct net *sock_net(const struct sock *sk)
{
	return NULL;
}

#endif

#endif /* net/sock.h wrapper */
