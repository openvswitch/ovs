#include <linux/if_vlan.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
static int net_assign_generic(struct net *net, int id, void *data);
#endif

int __net_init compat_init_net(struct net *net, struct rpl_pernet_operations *pnet)
{
	int err;
	void *ovs_net = kzalloc(pnet->size, GFP_KERNEL);

	if (!ovs_net)
		return -ENOMEM;

	err = net_assign_generic(net, *pnet->id, ovs_net);
	if (err)
		goto err;

	if (pnet->init) {
		err = pnet->init(net);
		if (err)
			goto err;
	}

	return 0;
err:
	kfree(ovs_net);
	return err;
}

void __net_exit compat_exit_net(struct net *net, struct rpl_pernet_operations *pnet)
{
	void *ovs_net = net_generic(net, *pnet->id);

	if (pnet->exit)
		pnet->exit(net);
	kfree(ovs_net);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define MAX_DATA_COUNT 2
static struct net *net;

static void *__ovs_net_data[MAX_DATA_COUNT];
static int count;

static int net_assign_generic(struct net *net, int id, void *data)
{
	BUG_ON(id >= MAX_DATA_COUNT);
	__ovs_net_data[id] = data;
	return 0;
}

void *net_generic(const struct net *net, int id)
{
	return __ovs_net_data[id];
}

int rpl_register_pernet_gen_device(struct rpl_pernet_operations *rpl_pnet)
{
	*rpl_pnet->id = count++;
	return compat_init_net(net, rpl_pnet);
}

void rpl_unregister_pernet_gen_device(struct rpl_pernet_operations *rpl_pnet)
{
	compat_exit_net(net, rpl_pnet);
}

#endif
