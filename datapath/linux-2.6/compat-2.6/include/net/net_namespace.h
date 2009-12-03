#ifndef __NET_NAMESPACE_WRAPPER_H
#define __NET_NAMESPACE_WRAPPER_H 1

#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24)
#include_next <net/net_namespace.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
struct net;

struct pernet_operations {
	struct list_head list;
	int (*init)(struct net *net);
	void (*exit)(struct net *net);
};
#endif /* linux kernel < 2.6.24 */

extern int register_pernet_gen_device(int *id, struct pernet_operations *);
extern void unregister_pernet_gen_device(int id, struct pernet_operations *);

#endif /* linux kernel < 2.6.26 */

#endif
