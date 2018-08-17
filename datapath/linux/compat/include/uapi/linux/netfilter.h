#ifndef _NETFILTER_WRAPPER_H
#define _NETFILTER_WRAPPER_H

#include_next <uapi/linux/netfilter.h>

/*
 * NFPROTO_INET was introduced in net-next commit 1d49144c0aaa
 * ("netfilter: nf_tables: add "inet" table for IPv4/IPv6") in v3.14.
 * Define this symbol to support back to v3.10 kernel. */
#ifndef HAVE_NFPROTO_INET
#define NFPROTO_INET 1
#endif

#endif /* _NETFILTER_WRAPPER_H */
