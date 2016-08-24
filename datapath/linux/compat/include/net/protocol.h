#ifndef _NET_PROTOCOL_WRAPPER_H
#define _NET_PROTOCOL_WRAPPER_H

#include_next <net/protocol.h>

#ifdef HAVE_UDP_OFFLOAD

#ifndef HAVE_UDP_ADD_OFFLOAD_TAKES_NET
#define udp_add_offload(net, prot)	udp_add_offload(prot)
#endif

#else

#define udp_add_offload(net, prot)	0
#define udp_del_offload(prot)		do {} while(0)

#endif /* HAVE_UDP_OFFLOAD */

#endif /* _NET_PROTOCOL_WRAPPER_H */
