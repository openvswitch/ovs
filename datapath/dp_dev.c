#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rcupdate.h>

#include "datapath.h"
#include "forward.h"

static int dp_dev_do_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	printk("xxx_do_ioctl called\n");
	return 0;
}

static struct net_device_stats *dp_dev_get_stats(struct net_device *dev)
{
	struct datapath *dp = netdev_priv(dev);
	return &dp->stats;
}

int dp_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct datapath *dp = netdev_priv(dev);

	printk("xxx dp_dev_xmit not implemented yet!\n");
	return 0;

	printk("xxx_xmit called send to dp_frame_hook\n");

	rcu_read_lock();    /* xxx Only for 2.4 kernels? */
	fwd_port_input(dp->chain, skb, OFPP_LOCAL);
	rcu_read_unlock();  /* xxx Only for 2.4 kernels? */
	
	return 0;
}

static int dp_dev_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static void dp_dev_set_multicast_list(struct net_device *dev)
{
	printk("xxx_set_multi called\n");
}

static int dp_dev_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

int dp_dev_setup(struct net_device *dev)
{
	int err;

	strncpy(dev->name, "of%d", IFNAMSIZ);
	err = dev_alloc_name(dev, dev->name);
	if (err < 0) 
		return err;

	dev->do_ioctl = dp_dev_do_ioctl;
	dev->get_stats = dp_dev_get_stats;
	dev->hard_start_xmit = dp_dev_xmit;
	dev->open = dp_dev_open;
	dev->set_multicast_list = dp_dev_set_multicast_list;
	dev->stop = dp_dev_stop;
	dev->tx_queue_len = 0;
	dev->set_mac_address = NULL;

	dev->flags = IFF_BROADCAST | IFF_NOARP | IFF_MULTICAST;

	random_ether_addr(dev->dev_addr);

	ether_setup(dev);
	return register_netdevice(dev);
}
