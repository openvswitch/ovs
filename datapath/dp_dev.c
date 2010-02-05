/*
 * Copyright (c) 2009, 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>

#include "datapath.h"
#include "dp_dev.h"

struct pcpu_lstats {
	unsigned long rx_packets;
	unsigned long rx_bytes;
	unsigned long tx_packets;
	unsigned long tx_bytes;
};

struct datapath *dp_dev_get_dp(struct net_device *netdev)
{
	return dp_dev_priv(netdev)->dp;
}

static struct net_device_stats *dp_dev_get_stats(struct net_device *netdev)
{
	struct dp_dev *dp_dev = dp_dev_priv(netdev);
	struct net_device_stats *stats;
	int i;

	stats = &dp_dev->stats;
	memset(stats, 0, sizeof *stats);
	for_each_possible_cpu(i) {
		const struct pcpu_lstats *lb_stats;

		lb_stats = per_cpu_ptr(dp_dev->lstats, i);
		stats->rx_bytes   += lb_stats->rx_bytes;
		stats->rx_packets += lb_stats->rx_packets;
		stats->tx_bytes   += lb_stats->tx_bytes;
		stats->tx_packets += lb_stats->tx_packets;
	}
	return stats;
}

int dp_dev_recv(struct net_device *netdev, struct sk_buff *skb) 
{
	struct dp_dev *dp_dev = dp_dev_priv(netdev);
	struct pcpu_lstats *lb_stats;
	int len;
	len = skb->len;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, netdev);
	if (in_interrupt())
		netif_rx(skb);
	else
		netif_rx_ni(skb);
	netdev->last_rx = jiffies;

	preempt_disable();
	lb_stats = per_cpu_ptr(dp_dev->lstats, smp_processor_id());
	lb_stats->rx_packets++;
	lb_stats->rx_bytes += len;
	preempt_enable();

	return len;
}

static int dp_dev_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	return 0;
}

/* Not reentrant (because it is called with BHs disabled), but may be called
 * simultaneously on different CPUs. */
static int dp_dev_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct dp_dev *dp_dev = dp_dev_priv(netdev);
	struct pcpu_lstats *lb_stats;

	/* dp_process_received_packet() needs its own clone. */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return 0;

	lb_stats = per_cpu_ptr(dp_dev->lstats, smp_processor_id());
	lb_stats->tx_packets++;
	lb_stats->tx_bytes += skb->len;

	skb_reset_mac_header(skb);
	rcu_read_lock_bh();
	dp_process_received_packet(skb, dp_dev->dp->ports[dp_dev->port_no]);
	rcu_read_unlock_bh();

	return 0;
}

static int dp_dev_open(struct net_device *netdev)
{
	netif_start_queue(netdev);
	return 0;
}

static int dp_dev_stop(struct net_device *netdev)
{
	netif_stop_queue(netdev);
	return 0;
}

static void dp_getinfo(struct net_device *netdev, struct ethtool_drvinfo *info)
{
	struct dp_dev *dp_dev = dp_dev_priv(netdev);
	strcpy(info->driver, "openvswitch");
	sprintf(info->bus_info, "%d.%d", dp_dev->dp->dp_idx, dp_dev->port_no);
}

static struct ethtool_ops dp_ethtool_ops = {
	.get_drvinfo = dp_getinfo,
	.get_link = ethtool_op_get_link,
	.get_sg = ethtool_op_get_sg,
	.get_tx_csum = ethtool_op_get_tx_csum,
	.get_tso = ethtool_op_get_tso,
};

static int dp_dev_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < 68 || new_mtu > dp_min_mtu(dp_dev_get_dp(dev)))
		return -EINVAL;

	dev->mtu = new_mtu;
	return 0;
}

static int dp_dev_init(struct net_device *netdev)
{
	struct dp_dev *dp_dev = dp_dev_priv(netdev);

	dp_dev->lstats = alloc_percpu(struct pcpu_lstats);
	if (!dp_dev->lstats)
		return -ENOMEM;

	return 0;
}

static void dp_dev_free(struct net_device *netdev)
{
	struct dp_dev *dp_dev = dp_dev_priv(netdev);

	free_percpu(dp_dev->lstats);
	free_netdev(netdev);
}

static int dp_dev_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	if (dp_ioctl_hook)
		return dp_ioctl_hook(dev, ifr, cmd);
	return -EOPNOTSUPP;
}

#ifdef HAVE_NET_DEVICE_OPS
static const struct net_device_ops dp_dev_netdev_ops = {
	.ndo_init = dp_dev_init,
	.ndo_open = dp_dev_open,
	.ndo_stop = dp_dev_stop,
	.ndo_start_xmit = dp_dev_xmit,
	.ndo_set_mac_address = dp_dev_mac_addr,
	.ndo_do_ioctl = dp_dev_do_ioctl,
	.ndo_change_mtu = dp_dev_change_mtu,
	.ndo_get_stats = dp_dev_get_stats,
};
#endif

static void
do_setup(struct net_device *netdev)
{
	ether_setup(netdev);

#ifdef HAVE_NET_DEVICE_OPS
	netdev->netdev_ops = &dp_dev_netdev_ops;
#else
	netdev->do_ioctl = dp_dev_do_ioctl;
	netdev->get_stats = dp_dev_get_stats;
	netdev->hard_start_xmit = dp_dev_xmit;
	netdev->open = dp_dev_open;
	netdev->stop = dp_dev_stop;
	netdev->set_mac_address = dp_dev_mac_addr;
	netdev->change_mtu = dp_dev_change_mtu;
	netdev->init = dp_dev_init;
#endif

	netdev->destructor = dp_dev_free;
	SET_ETHTOOL_OPS(netdev, &dp_ethtool_ops);
	netdev->tx_queue_len = 0;

	netdev->flags = IFF_BROADCAST | IFF_MULTICAST;
	netdev->features = NETIF_F_LLTX; /* XXX other features? */

	random_ether_addr(netdev->dev_addr);

	/* Set the OUI to the Nicira one. */
	netdev->dev_addr[0] = 0x00;
	netdev->dev_addr[1] = 0x23;
	netdev->dev_addr[2] = 0x20;

	/* Set the top bits to indicate random Nicira address. */
	netdev->dev_addr[3] |= 0xc0;
}

/* Create a datapath device associated with 'dp'.  If 'dp_name' is null,
 * the device name will be of the form 'of<dp_idx>'.  Returns the new device or
 * an error code.
 *
 * Called with RTNL lock and dp_mutex. */
struct net_device *dp_dev_create(struct datapath *dp, const char *dp_name, int port_no)
{
	struct dp_dev *dp_dev;
	struct net_device *netdev;
	char dev_name[IFNAMSIZ];
	int err;

	if (dp_name) {
		if (strlen(dp_name) >= IFNAMSIZ)
			return ERR_PTR(-EINVAL);
		strncpy(dev_name, dp_name, sizeof(dev_name));
	} else
		snprintf(dev_name, sizeof dev_name, "of%d", dp->dp_idx);

	netdev = alloc_netdev(sizeof(struct dp_dev), dev_name, do_setup);
	if (!netdev)
		return ERR_PTR(-ENOMEM);

	dp_dev = dp_dev_priv(netdev);
	dp_dev->dp = dp;
	dp_dev->port_no = port_no;
	dp_dev->dev = netdev;

	err = register_netdevice(netdev);
	if (err) {
		free_netdev(netdev);
		return ERR_PTR(err);
	}

	return netdev;
}

/* Called with RTNL lock and dp_mutex.*/
void dp_dev_destroy(struct net_device *netdev)
{
	unregister_netdevice(netdev);
}

int is_dp_dev(struct net_device *netdev) 
{
#ifdef HAVE_NET_DEVICE_OPS
	return netdev->netdev_ops == &dp_dev_netdev_ops;
#else
	return netdev->open == dp_dev_open;
#endif
}
