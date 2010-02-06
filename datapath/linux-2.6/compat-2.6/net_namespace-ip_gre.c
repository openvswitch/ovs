#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)

#include <linux/sched.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#undef pernet_operations
#undef register_pernet_device
#undef unregister_pernet_device
#undef net_assign_generic
#undef net_generic

/* This trivial implementation assumes that there is only a single pernet
 * device registered and that the caller is well behaved.  It only weakly
 * attempts to check that these conditions are true. */

static struct extended_pernet_operations *dev_ops;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static void *ng_data;
#else
static struct pernet_operations new_ops;
#endif

static int device_init_net(struct net *net)
{
	int err;
	if (dev_ops->id && dev_ops->size) {
		void *data = kzalloc(dev_ops->size, GFP_KERNEL);
		if (!data)
			return -ENOMEM;

		err = rpl_net_assign_generic(net, *dev_ops->id, data);
		if (err) {
			kfree(data);
			return err;
		}
	}
	if (dev_ops->init)
		return dev_ops->init(net);
	return 0;
}

static void device_exit_net(struct net *net)
{
	if (dev_ops->id && dev_ops->size) {
		int id = *dev_ops->id;
		kfree(rpl_net_generic(net, id));
	}

	if (dev_ops->exit)
		return dev_ops->exit(net);
}

int rpl_register_pernet_device(struct extended_pernet_operations *ops)
{
	BUG_ON(dev_ops);
	dev_ops = ops;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	if (dev_ops->id)
		*dev_ops->id = 1;

	return device_init_net(NULL);
#else
	memcpy(&new_ops, dev_ops, sizeof new_ops);
	new_ops.init = device_init_net;
	new_ops.exit = device_exit_net;

	if (ops->id)
		return register_pernet_gen_device(dev_ops->id, &new_ops);
	else
		return register_pernet_device(&new_ops);
#endif
}

void rpl_unregister_pernet_device(struct extended_pernet_operations *ops)
{
	BUG_ON(!dev_ops);
	BUG_ON(dev_ops != ops);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	device_exit_net(NULL);
#else
	if (ops->id)
		unregister_pernet_gen_device(*dev_ops->id, &new_ops);
	else
		unregister_pernet_device(&new_ops);
#endif

	dev_ops = NULL;
}

int rpl_net_assign_generic(struct net *net, int id, void *data)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	BUG_ON(id != 1);

	ng_data = data;
	return 0;
#else
	return net_assign_generic(net, id, data);
#endif
}

void *rpl_net_generic(struct net *net, int id)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	BUG_ON(id != 1);

	return ng_data;
#else
	return net_generic(net, id);
#endif
}

#endif /* kernel < 2.6.33 */
