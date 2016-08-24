#ifndef __NET_LISP_WRAPPER_H
#define __NET_LISP_WRAPPER_H  1

#ifdef CONFIG_INET
#include <net/udp_tunnel.h>
#endif


#ifdef CONFIG_INET
#define lisp_dev_create_fb rpl_lisp_dev_create_fb
struct net_device *rpl_lisp_dev_create_fb(struct net *net, const char *name,
					u8 name_assign_type, u16 dst_port);
#endif /*ifdef CONFIG_INET */

#define lisp_init_module rpl_lisp_init_module
int rpl_lisp_init_module(void);

#define lisp_cleanup_module rpl_lisp_cleanup_module
void rpl_lisp_cleanup_module(void);

#define lisp_xmit rpl_lisp_xmit
netdev_tx_t rpl_lisp_xmit(struct sk_buff *skb);

#define lisp_fill_metadata_dst ovs_lisp_fill_metadata_dst
int ovs_lisp_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb);

#endif /*ifdef__NET_LISP_H */
