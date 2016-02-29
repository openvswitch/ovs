#ifndef __NET_NET_NAMESPACE_WRAPPER_H
#define __NET_NET_NAMESPACE_WRAPPER_H 1

#include_next <net/net_namespace.h>

#ifndef HAVE_POSSIBLE_NET_T
typedef struct {
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
} possible_net_t;

static inline void rpl_write_pnet(possible_net_t *pnet, struct net *net)
{
#ifdef CONFIG_NET_NS
	pnet->net = net;
#endif
}

static inline struct net *rpl_read_pnet(const possible_net_t *pnet)
{
#ifdef CONFIG_NET_NS
	return pnet->net;
#else
	return &init_net;
#endif
}
#else /* Linux >= 4.1 */
#define rpl_read_pnet read_pnet
#define rpl_write_pnet write_pnet
#endif /* Linux >= 4.1 */

#endif /* net/net_namespace.h wrapper */
