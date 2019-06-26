#ifndef __NET_IPV6_FRAG_WRAPPER_H
#define __NET_IPV6_FRAG_WRAPPER_H

#if IS_ENABLED(CONFIG_NF_DEFRAG_IPV6) && defined(HAVE_IPV6_FRAG_H)
#include_next <net/ipv6_frag.h>
#endif

#endif /* __NET_IPV6_FRAG_WRAPPER_H */
