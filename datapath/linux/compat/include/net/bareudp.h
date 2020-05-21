#ifndef __NET_BAREUDP_WRAPPER_H
#define __NET_BAREUDP_WRAPPER_H  1

#ifdef CONFIG_INET
#include <net/udp_tunnel.h>
#endif


#ifdef USE_UPSTREAM_TUNNEL
#include_next <net/bareudp.h>

static inline int rpl_bareudp_init_module(void)
{
	return 0;
}
static inline void rpl_bareudp_cleanup_module(void)
{}

#define bareudp_xmit dev_queue_xmit

#ifdef CONFIG_INET
#ifdef HAVE_NAME_ASSIGN_TYPE
static inline struct net_device *rpl_bareudp_dev_create(
	struct net *net, const char *name, u8 name_assign_type, struct bareudp_conf *conf) {
	return bareudp_dev_create(net, name,name_assign_type, conf);
}
#define bareudp_dev_create rpl_bareudp_dev_create
#endif
#endif

#else

struct bareudp_conf {
        __be16 ethertype;
        __be16 port;
        u16 sport_min;
        bool multi_proto_mode;
};

#ifdef CONFIG_INET
#define bareudp_dev_create rpl_bareudp_dev_create
struct net_device *rpl_bareudp_dev_create(struct net *net, const char *name,
					  u8 name_assign_type, struct bareudp_conf *conf);
#endif /*ifdef CONFIG_INET */

int rpl_bareudp_init_module(void);
void rpl_bareudp_cleanup_module(void);

#define bareudp_xmit rpl_bareudp_xmit
netdev_tx_t rpl_bareudp_xmit(struct sk_buff *skb);

#endif
#define bareudp_init_module rpl_bareudp_init_module
#define bareudp_cleanup_module rpl_bareudp_cleanup_module

#define bareudp_fill_metadata_dst ovs_bareudp_fill_metadata_dst
int ovs_bareudp_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb);

#endif /*ifdef__NET_BAREUDP_H */
