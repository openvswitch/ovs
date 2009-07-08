/* veth driver port to Linux 2.6.18 */

/*
 *  drivers/net/veth.c
 *
 *  Copyright (C) 2007, 2009 OpenVZ http://openvz.org, SWsoft Inc
 *
 * Author: Pavel Emelianov <xemul@openvz.org>
 * Ethtool interface from: Eric W. Biederman <ebiederm@xmission.com>
 *
 */

#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>

#include <net/dst.h>
#include <net/xfrm.h>

#define DRV_NAME	"veth"
#define DRV_VERSION	"1.0"

struct veth_net_stats {
	unsigned long	rx_packets;
	unsigned long	tx_packets;
	unsigned long	rx_bytes;
	unsigned long	tx_bytes;
	unsigned long	tx_dropped;
};

struct veth_priv {
	struct net_device *peer;
	struct net_device *dev;
	struct list_head list;
	struct veth_net_stats *stats;
	unsigned ip_summed;
	struct net_device_stats dev_stats;
};

static LIST_HEAD(veth_list);

/*
 * ethtool interface
 */

static struct {
	const char string[ETH_GSTRING_LEN];
} ethtool_stats_keys[] = {
	{ "peer_ifindex" },
};

static int veth_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	cmd->supported		= 0;
	cmd->advertising	= 0;
	cmd->speed		= SPEED_10000;
	cmd->duplex		= DUPLEX_FULL;
	cmd->port		= PORT_TP;
	cmd->phy_address	= 0;
	cmd->transceiver	= XCVR_INTERNAL;
	cmd->autoneg		= AUTONEG_DISABLE;
	cmd->maxtxpkt		= 0;
	cmd->maxrxpkt		= 0;
	return 0;
}

static void veth_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strcpy(info->driver, DRV_NAME);
	strcpy(info->version, DRV_VERSION);
	strcpy(info->fw_version, "N/A");
}

static void veth_get_strings(struct net_device *dev, u32 stringset, u8 *buf)
{
	switch(stringset) {
	case ETH_SS_STATS:
		memcpy(buf, &ethtool_stats_keys, sizeof(ethtool_stats_keys));
		break;
	}
}

static void veth_get_ethtool_stats(struct net_device *dev,
		struct ethtool_stats *stats, u64 *data)
{
	struct veth_priv *priv;

	priv = netdev_priv(dev);
	data[0] = priv->peer->ifindex;
}

static u32 veth_get_rx_csum(struct net_device *dev)
{
	struct veth_priv *priv;

	priv = netdev_priv(dev);
	return priv->ip_summed == CHECKSUM_UNNECESSARY;
}

static int veth_set_rx_csum(struct net_device *dev, u32 data)
{
	struct veth_priv *priv;

	priv = netdev_priv(dev);
	priv->ip_summed = data ? CHECKSUM_UNNECESSARY : CHECKSUM_NONE;
	return 0;
}

static u32 veth_get_tx_csum(struct net_device *dev)
{
	return (dev->features & NETIF_F_NO_CSUM) != 0;
}

static int veth_set_tx_csum(struct net_device *dev, u32 data)
{
	if (data)
		dev->features |= NETIF_F_NO_CSUM;
	else
		dev->features &= ~NETIF_F_NO_CSUM;
	return 0;
}

static struct ethtool_ops veth_ethtool_ops = {
	.get_settings		= veth_get_settings,
	.get_drvinfo		= veth_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_rx_csum		= veth_get_rx_csum,
	.set_rx_csum		= veth_set_rx_csum,
	.get_tx_csum		= veth_get_tx_csum,
	.set_tx_csum		= veth_set_tx_csum,
	.get_sg			= ethtool_op_get_sg,
	.set_sg			= ethtool_op_set_sg,
	.get_strings		= veth_get_strings,
	.get_ethtool_stats	= veth_get_ethtool_stats,
};

/*
 * xmit
 */

static int veth_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device *rcv = NULL;
	struct veth_priv *priv, *rcv_priv;
	struct veth_net_stats *stats;
	int length, cpu;

	skb_orphan(skb);

	priv = netdev_priv(dev);
	rcv = priv->peer;
	rcv_priv = netdev_priv(rcv);

	cpu = smp_processor_id();
	stats = per_cpu_ptr(priv->stats, cpu);

	if (!(rcv->flags & IFF_UP))
		goto outf;

	skb->dev = rcv;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, rcv);
	if (dev->features & NETIF_F_NO_CSUM)
		skb->ip_summed = rcv_priv->ip_summed;

	dst_release(skb->dst);
	skb->dst = NULL;
	secpath_reset(skb);
	nf_reset(skb);

	length = skb->len;

	stats->tx_bytes += length;
	stats->tx_packets++;

	stats = per_cpu_ptr(rcv_priv->stats, cpu);
	stats->rx_bytes += length;
	stats->rx_packets++;

	netif_rx(skb);
	return 0;

outf:
	kfree_skb(skb);
	stats->tx_dropped++;
	return 0;
}

/*
 * general routines
 */

static struct net_device_stats *veth_get_stats(struct net_device *dev)
{
	struct veth_priv *priv;
	struct net_device_stats *dev_stats;
	int cpu;
	struct veth_net_stats *stats;

	priv = netdev_priv(dev);
	dev_stats = &priv->dev_stats;

	dev_stats->rx_packets = 0;
	dev_stats->tx_packets = 0;
	dev_stats->rx_bytes = 0;
	dev_stats->tx_bytes = 0;
	dev_stats->tx_dropped = 0;

	for_each_online_cpu(cpu) {
		stats = per_cpu_ptr(priv->stats, cpu);

		dev_stats->rx_packets += stats->rx_packets;
		dev_stats->tx_packets += stats->tx_packets;
		dev_stats->rx_bytes += stats->rx_bytes;
		dev_stats->tx_bytes += stats->tx_bytes;
		dev_stats->tx_dropped += stats->tx_dropped;
	}

	return dev_stats;
}

static int veth_open(struct net_device *dev)
{
	struct veth_priv *priv;

	priv = netdev_priv(dev);
	if (priv->peer == NULL)
		return -ENOTCONN;

	if (priv->peer->flags & IFF_UP) {
		netif_carrier_on(dev);
		netif_carrier_on(priv->peer);
	}
	return 0;
}

static int veth_dev_init(struct net_device *dev)
{
	struct veth_net_stats *stats;
	struct veth_priv *priv;

	stats = alloc_percpu(struct veth_net_stats);
	if (stats == NULL)
		return -ENOMEM;

	priv = netdev_priv(dev);
	priv->stats = stats;
	return 0;
}

static void veth_dev_free(struct net_device *dev)
{
	struct veth_priv *priv;

	priv = netdev_priv(dev);
	free_percpu(priv->stats);
	free_netdev(dev);
}

static void veth_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->hard_start_xmit = veth_xmit;
	dev->get_stats = veth_get_stats;
	dev->open = veth_open;
	dev->ethtool_ops = &veth_ethtool_ops;
	dev->features |= NETIF_F_LLTX;
	dev->init = veth_dev_init;
	dev->destructor = veth_dev_free;
}

static void veth_change_state(struct net_device *dev)
{
	struct net_device *peer;
	struct veth_priv *priv;

	priv = netdev_priv(dev);
	peer = priv->peer;

	if (netif_carrier_ok(peer)) {
		if (!netif_carrier_ok(dev))
			netif_carrier_on(dev);
	} else {
		if (netif_carrier_ok(dev))
			netif_carrier_off(dev);
	}
}

static int veth_device_event(struct notifier_block *unused,
			     unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;

	if (dev->open != veth_open)
		goto out;

	switch (event) {
	case NETDEV_CHANGE:
		veth_change_state(dev);
		break;
	}
out:
	return NOTIFY_DONE;
}

static struct notifier_block veth_notifier_block __read_mostly = {
	.notifier_call	= veth_device_event,
};

/*
 * netlink interface
 */

static int veth_newlink(const char *devname, const char *peername)
{
	int err;
	const char *names[2];
	struct net_device *devs[2];
	int i;

	names[0] = devname;
	names[1] = peername;
	devs[0] = devs[1] = NULL;

	for (i = 0; i < 2; i++) {
		struct net_device *dev;

		err = -ENOMEM;
		devs[i] = alloc_netdev(sizeof(struct veth_priv),
				       names[i], veth_setup);
		if (!devs[i]) {
			goto err;
		}

		dev = devs[i];

		if (strchr(dev->name, '%')) {
			err = dev_alloc_name(dev, dev->name);
			if (err < 0)
				goto err;
		}
		random_ether_addr(dev->dev_addr);

		err = register_netdevice(dev);
		if (err < 0)
			goto err;

		netif_carrier_off(dev);
	}

	/*
	 * tie the devices together
	 */

	for (i = 0; i < 2; i++) {
		struct veth_priv *priv = netdev_priv(devs[i]);
		priv->dev = devs[i];
		priv->peer = devs[!i];
		if (!i)
			list_add(&priv->list, &veth_list);
		else
			INIT_LIST_HEAD(&priv->list);
	}
	return 0;

err:
	for (i = 0; i < 2; i++) {
		if (devs[i]) {
			if (devs[i]->reg_state != NETREG_UNINITIALIZED)
				unregister_netdevice(devs[i]);
			else
				free_netdev(devs[i]);
		}
	}
	return err;
}

static void veth_dellink(struct net_device *dev)
{
	struct veth_priv *priv;
	struct net_device *peer;

	priv = netdev_priv(dev);
	peer = priv->peer;

	if (!list_empty(&priv->list))
		list_del(&priv->list);

	priv = netdev_priv(peer);
	if (!list_empty(&priv->list))
		list_del(&priv->list);

	unregister_netdevice(dev);
	unregister_netdevice(peer);
}

/*
 * sysfs 
 */

/*
 * "show" function for the veth_pairs attribute.
 * The class parameter is ignored.
 */
static ssize_t veth_show_veth_pairs(struct class *cls, char *buffer)
{
	int res = 0;
	struct veth_priv *priv;

	list_for_each_entry(priv, &veth_list, list) {
		if (res > (PAGE_SIZE - (IFNAMSIZ * 2 + 1))) {
			/* not enough space for another interface name */
			if ((PAGE_SIZE - res) > 10)
				res = PAGE_SIZE - 10;
			res += sprintf(buffer + res, "++more++");
			break;
		}
		res += sprintf(buffer + res, "%s,%s ",
			       priv->dev->name, priv->peer->name);
	}
	res += sprintf(buffer + res, "\n");
	res++;
	return res;
}

/*
 * "store" function for the veth_pairs attribute.  This is what
 * creates and deletes veth pairs.
 *
 * The class parameter is ignored.
 *
 */
static ssize_t veth_store_veth_pairs(struct class *cls, const char *buffer,
				     size_t count)
{
	int c = *buffer++;
	int retval;
	printk("1\n");
	if (c == '+') {
		char devname[IFNAMSIZ + 1] = "";
		char peername[IFNAMSIZ + 1] = "";
		char *comma = strchr(buffer, ',');
		printk("2\n");
		if (!comma)
			goto err_no_cmd;
		strncat(devname, buffer,
			min_t(int, sizeof devname, comma - buffer));
		strncat(peername, comma + 1,
			min_t(int, sizeof peername, strcspn(comma + 1, "\n")));
		printk("3 '%s' '%s'\n", devname, peername);
		if (!dev_valid_name(devname) || !dev_valid_name(peername))
			goto err_no_cmd;
		printk("4\n");
		rtnl_lock();
		retval = veth_newlink(devname, peername);
		rtnl_unlock();
		return retval ? retval : count;
	} else if (c == '-') {
		struct net_device *dev;

		rtnl_lock();
		dev = dev_get_by_name(buffer);
		if (!dev)
			retval = -ENODEV;
		else if (dev->init != veth_dev_init)
			retval = -EINVAL;
		else {
			veth_dellink(dev);
			retval = count;
		}
		rtnl_unlock();

		return retval;
	}

err_no_cmd:
	printk(KERN_ERR DRV_NAME ": no command found in veth_pairs.  Use +ifname,peername or -ifname.\n");
	return -EPERM;
}

/* class attribute for veth_pairs file.  This ends up in /sys/class/net */
static CLASS_ATTR(veth_pairs,  S_IWUSR | S_IRUGO,
		  veth_show_veth_pairs, veth_store_veth_pairs);

static struct class *netdev_class;

/*
 * Initialize sysfs.  This sets up the veth_pairs file in
 * /sys/class/net.
 */
int veth_create_sysfs(void)
{
	struct net_device *dev = dev_get_by_name("lo");
	if (!dev)
		return -ESRCH;
	netdev_class = dev->class_dev.class;
	if (!netdev_class)
		return -ENODEV;
	
	return class_create_file(netdev_class, &class_attr_veth_pairs);
}

/*
 * Remove /sys/class/net/veth_pairs.
 */
void veth_destroy_sysfs(void)
{
	class_remove_file(netdev_class, &class_attr_veth_pairs);
}



/*
 * init/fini
 */

static __init int veth_init(void)
{
	int retval = veth_create_sysfs();
	if (retval)
		return retval;
	register_netdevice_notifier(&veth_notifier_block);
	return 0;
}

static __exit void veth_exit(void)
{
	unregister_netdevice_notifier(&veth_notifier_block);
}

module_init(veth_init);
module_exit(veth_exit);

MODULE_DESCRIPTION("Virtual Ethernet Tunnel");
MODULE_LICENSE("GPL v2");
