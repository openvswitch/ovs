#include <linux/if_vlan.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)

int ovs_compat_init_net(struct net *net, struct rpl_pernet_operations *pnet)
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
EXPORT_SYMBOL_GPL(ovs_compat_init_net);

void ovs_compat_exit_net(struct net *net, struct rpl_pernet_operations *pnet)
{
	void *ovs_net = net_generic(net, *pnet->id);

	if (pnet->exit)
		pnet->exit(net);
	kfree(ovs_net);
}
EXPORT_SYMBOL_GPL(ovs_compat_exit_net);

#endif
