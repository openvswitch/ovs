#ifndef __NET_NET_NAMESPACE_WRAPPER_H
#define __NET_NET_NAMESPACE_WRAPPER_H 1

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
/* <net/net_namespace.h> exists, go ahead and include it. */
#include_next <net/net_namespace.h>
#else
/* No network namespace support. */
struct net;

static inline struct net *hold_net(struct net *net)
{
	return net;
}

static inline void release_net(struct net *net)
{
}

#define __net_init      __init
#define __net_exit      __exit
#endif /* 2.6.24 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#ifdef CONFIG_NET_NS
static inline
int net_eq(const struct net *net1, const struct net *net2)
{
	return net1 == net2;
}
#else
static inline
int net_eq(const struct net *net1, const struct net *net2)
{
	return 1;
}
#endif /* CONFIG_NET_NS */
#endif /* 2.6.26 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
#ifdef CONFIG_NET_NS

static inline void write_pnet(struct net **pnet, struct net *net)
{
	*pnet = net;
}

static inline struct net *read_pnet(struct net * const *pnet)
{
	return *pnet;
}

#else

#define write_pnet(pnet, net)   do { (void)(net); } while (0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#define read_pnet(pnet)         (&init_net)
#else
#define read_pnet(pnet)         (NULL)
#endif /* 2.6.24 */

#endif /* CONFIG_NET_NS */
#endif /* 2.6.29 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
#define pernet_operations rpl_pernet_operations
struct pernet_operations {
	int (*init)(struct net *net);
	void (*exit)(struct net *net);
	int *id;
	size_t size;
};

extern int rpl_register_pernet_gen_device(struct rpl_pernet_operations *ops);
extern void rpl_unregister_pernet_gen_device(struct rpl_pernet_operations *ops);

#define register_pernet_device rpl_register_pernet_gen_device
#define unregister_pernet_device rpl_unregister_pernet_gen_device

#endif /* 2.6.33 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#undef for_each_net
#define for_each_net(net)   { net = NULL; }

#endif /* 2.6.32 */

#endif /* net/net_namespace.h wrapper */
