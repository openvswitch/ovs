#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)

#include <linux/sched.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

/* This trivial implementation assumes that there is only a single pernet
 * generic device registered and that the caller is well behaved.  It only
 * weakly attempts to check that these conditions are true. */

static bool device_registered;
static void *ng_data;

int register_pernet_gen_device(int *id, struct pernet_operations *ops)
{
	BUG_ON(device_registered);

	*id = 1;
	device_registered = true;

	if (ops->init == NULL)
		return 0;
	return ops->init(NULL);
}

void unregister_pernet_gen_device(int id, struct pernet_operations *ops)
{
	device_registered = false;
	if (ops->exit)
		ops->exit(NULL);
}

int net_assign_generic(struct net *net, int id, void *data)
{
	BUG_ON(id != 1);

	ng_data = data;
	return 0;
}

void *net_generic(struct net *net, int id)
{
	BUG_ON(id != 1);

	return ng_data;
}

#endif /* kernel < 2.6.26 */
