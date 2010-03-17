#ifndef __NET_NAMESPACE_WRAPPER_H
#define __NET_NAMESPACE_WRAPPER_H 1

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include_next <net/net_namespace.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
struct net;

struct extended_pernet_operations {
	struct list_head list;
	int (*init)(struct net *net);
	void (*exit)(struct net *net);
	int *id;
	size_t size;
};
#define pernet_operations extended_pernet_operations

#define register_pernet_device rpl_register_pernet_device
int rpl_register_pernet_device(struct extended_pernet_operations *ops);

#define unregister_pernet_device rpl_unregister_pernet_device
void rpl_unregister_pernet_device(struct extended_pernet_operations *ops);

#endif /* linux kernel < 2.6.33 */

#endif
