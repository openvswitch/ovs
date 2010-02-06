#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)

#include <linux/netdevice.h>
#include <linux/rtnetlink.h>

struct netdev_list {
	struct list_head unreg_list;
	struct net_device *dev;
};

/**
 *	unregister_netdevice_queue - remove device from the kernel
 *	@dev: device
 *	@head: list

 *	This function shuts down a device interface and removes it
 *	from the kernel tables.
 *	If head not NULL, device is queued to be unregistered later.
 *
 *	Callers must hold the rtnl semaphore.  You may want
 *	unregister_netdev() instead of this.
 */

void unregister_netdevice_queue(struct net_device *dev, struct list_head *head)
{
	ASSERT_RTNL();

	if (head) {
		struct netdev_list *list_item = kmalloc(sizeof *list_item,
							GFP_KERNEL);
		/* If we can't queue it, probably better to try to destroy it
		 * now.  Either could potentially be bad but this is probably
		 * less likely to cause problems. */
		if (!list_item) {
			unregister_netdevice(dev);
			return;
		}

		list_item->dev = dev;
		list_add_tail(&list_item->unreg_list, head);
	} else
		unregister_netdevice(dev);
}

/**
 *	unregister_netdevice_many - unregister many devices
 *	@head: list of devices
 *
 */
void unregister_netdevice_many(struct list_head *head)
{
	if (!list_empty(head)) {
		struct netdev_list *list_item, *next;

		list_for_each_entry_safe(list_item, next, head, unreg_list) {
			unregister_netdevice(list_item->dev);
			kfree(list_item);
		}
	}
}

#endif /* kernel < 2.6.33 */
