#ifndef _NET_INETPEER_WRAPPER_H
#define _NET_INETPEER_WRAPPER_H

#include_next <net/inetpeer.h>

#ifndef HAVE_INETPEER_VIF_SUPPORT
static inline struct inet_peer *rpl_inet_getpeer_v4(struct inet_peer_base *base,
						    __be32 v4daddr, int vif,
						    int create)
{
	return inet_getpeer_v4(base, v4daddr, create);
}
#define inet_getpeer_v4 rpl_inet_getpeer_v4
#endif /* HAVE_INETPEER_VIF_SUPPORT */

#endif /* _NET_INETPEER_WRAPPER_H */
