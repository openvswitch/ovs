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
#include <linux/rcupdate.h>
#include <linux/skbuff.h>

#include "datapath.h"
#include "vport-generic.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

struct internal_dev {
	struct vport *attached_vport, *vport;
	struct net_device_stats stats;
};

static inline struct internal_dev *internal_dev_priv(struct net_device *netdev)
{
	return netdev_priv(netdev);
}

/* This function is only called by the kernel network layer.  It is not a vport
 * get_stats() function.  If a vport get_stats() function is defined that
 * results in this being called it will cause infinite recursion. */
static struct net_device_stats *internal_dev_sys_stats(struct net_device *netdev)
{
	struct vport *vport = internal_dev_get_vport(netdev);
	struct net_device_stats *stats = &internal_dev_priv(netdev)->stats;

	if (vport) {
		struct odp_vport_stats vport_stats;

		vport_get_stats(vport, &vport_stats);

		/* The tx and rx stats need to be swapped because the switch
		 * and host OS have opposite perspectives. */
		stats->rx_packets	= vport_stats.tx_packets;
		stats->tx_packets	= vport_stats.rx_packets;
		stats->rx_bytes		= vport_stats.tx_bytes;
		stats->tx_bytes		= vport_stats.rx_bytes;
		stats->rx_errors	= vport_stats.tx_errors;
		stats->tx_errors	= vport_stats.rx_errors;
		stats->rx_dropped	= vport_stats.tx_dropped;
		stats->tx_dropped	= vport_stats.rx_dropped;
		stats->collisions	= vport_stats.collisions;
	}

	return stats;
}

static int internal_dev_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	return 0;
}

/* Called with rcu_read_lock and bottom-halves disabled. */
static int internal_dev_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct internal_dev *internal_dev = internal_dev_priv(netdev);
	struct vport *vport = rcu_dereference(internal_dev->vport);

	/* We need our own clone. */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb)) {
		vport_record_error(vport, VPORT_E_RX_DROPPED);
		return 0;
	}

	skb_reset_mac_header(skb);
	compute_ip_summed(skb, true);

	vport_receive(vport, skb);

	return 0;
}

static int internal_dev_open(struct net_device *netdev)
{
	netif_start_queue(netdev);
	return 0;
}

static int internal_dev_stop(struct net_device *netdev)
{
	netif_stop_queue(netdev);
	return 0;
}

static void internal_dev_getinfo(struct net_device *netdev,
				 struct ethtool_drvinfo *info)
{
	struct vport *vport = internal_dev_get_vport(netdev);
	struct dp_port *dp_port;

	strcpy(info->driver, "openvswitch");

	if (!vport)
		return;

	dp_port = vport_get_dp_port(vport);
	if (dp_port)
		sprintf(info->bus_info, "%d.%d", dp_port->dp->dp_idx, dp_port->port_no);
}

static struct ethtool_ops internal_dev_ethtool_ops = {
	.get_drvinfo	= internal_dev_getinfo,
	.get_link	= ethtool_op_get_link,
	.get_sg		= ethtool_op_get_sg,
	.set_sg		= ethtool_op_set_sg,
	.get_tx_csum	= ethtool_op_get_tx_csum,
	.set_tx_csum	= ethtool_op_set_tx_hw_csum,
	.get_tso	= ethtool_op_get_tso,
	.set_tso	= ethtool_op_set_tso,
};

static int internal_dev_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct vport *vport = internal_dev_get_vport(netdev);

	if (new_mtu < 68)
		return -EINVAL;

	if (vport) {
		struct dp_port *dp_port = vport_get_dp_port(vport);

		if (dp_port) {
			if (new_mtu > dp_min_mtu(dp_port->dp))
				return -EINVAL;
		}
	}

	netdev->mtu = new_mtu;
	return 0;
}

static void internal_dev_free(struct net_device *netdev)
{
	free_netdev(netdev);
}

static int internal_dev_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	if (dp_ioctl_hook)
		return dp_ioctl_hook(dev, ifr, cmd);

	return -EOPNOTSUPP;
}

#ifdef HAVE_NET_DEVICE_OPS
static const struct net_device_ops internal_dev_netdev_ops = {
	.ndo_open = internal_dev_open,
	.ndo_stop = internal_dev_stop,
	.ndo_start_xmit = internal_dev_xmit,
	.ndo_set_mac_address = internal_dev_mac_addr,
	.ndo_do_ioctl = internal_dev_do_ioctl,
	.ndo_change_mtu = internal_dev_change_mtu,
	.ndo_get_stats = internal_dev_sys_stats,
};
#endif

static void do_setup(struct net_device *netdev)
{
	ether_setup(netdev);

#ifdef HAVE_NET_DEVICE_OPS
	netdev->netdev_ops = &internal_dev_netdev_ops;
#else
	netdev->do_ioctl = internal_dev_do_ioctl;
	netdev->get_stats = internal_dev_sys_stats;
	netdev->hard_start_xmit = internal_dev_xmit;
	netdev->open = internal_dev_open;
	netdev->stop = internal_dev_stop;
	netdev->set_mac_address = internal_dev_mac_addr;
	netdev->change_mtu = internal_dev_change_mtu;
#endif

	netdev->destructor = internal_dev_free;
	SET_ETHTOOL_OPS(netdev, &internal_dev_ethtool_ops);
	netdev->tx_queue_len = 0;

	netdev->flags = IFF_BROADCAST | IFF_MULTICAST;
	netdev->features = NETIF_F_LLTX | NETIF_F_SG | NETIF_F_HIGHDMA
				| NETIF_F_HW_CSUM | NETIF_F_TSO;

	vport_gen_rand_ether_addr(netdev->dev_addr);
}

static struct vport *internal_dev_create(const char *name,
					 const void __user *config)
{
	struct vport *vport;
	struct netdev_vport *netdev_vport;
	struct internal_dev *internal_dev;
	int err;

	vport = vport_alloc(sizeof(struct netdev_vport), &internal_vport_ops);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	netdev_vport = netdev_vport_priv(vport);

	netdev_vport->dev = alloc_netdev(sizeof(struct internal_dev), name, do_setup);
	if (!netdev_vport->dev) {
		err = -ENOMEM;
		goto error_free_vport;
	}

	internal_dev = internal_dev_priv(netdev_vport->dev);
	rcu_assign_pointer(internal_dev->vport, vport);

	err = register_netdevice(netdev_vport->dev);
	if (err)
		goto error_free_netdev;

	return vport;

error_free_netdev:
	free_netdev(netdev_vport->dev);
error_free_vport:
	vport_free(vport);
error:
	return ERR_PTR(err);
}

static int internal_dev_destroy(struct vport *vport)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);

	unregister_netdevice(netdev_vport->dev);
	vport_free(vport);

	return 0;
}

static int internal_dev_attach(struct vport *vport)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	struct internal_dev *internal_dev = internal_dev_priv(netdev_vport->dev);

	rcu_assign_pointer(internal_dev->attached_vport, internal_dev->vport);
	dev_set_promiscuity(netdev_vport->dev, 1);
	netif_start_queue(netdev_vport->dev);

	return 0;
}

static int internal_dev_detach(struct vport *vport)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	struct internal_dev *internal_dev = internal_dev_priv(netdev_vport->dev);

	netif_stop_queue(netdev_vport->dev);
	dev_set_promiscuity(netdev_vport->dev, -1);
	rcu_assign_pointer(internal_dev->attached_vport, NULL);

	return 0;
}

static int internal_dev_recv(struct vport *vport, struct sk_buff *skb)
{
	struct net_device *netdev = netdev_vport_priv(vport)->dev;
	int len;

	skb->dev = netdev;
	len = skb->len;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, netdev);

	if (in_interrupt())
		netif_rx(skb);
	else
		netif_rx_ni(skb);
	netdev->last_rx = jiffies;

	return len;
}

struct vport_ops internal_vport_ops = {
	.type		= "internal",
	.flags		= VPORT_F_REQUIRED | VPORT_F_GEN_STATS,
	.create		= internal_dev_create,
	.destroy	= internal_dev_destroy,
	.attach		= internal_dev_attach,
	.detach		= internal_dev_detach,
	.set_mtu	= netdev_set_mtu,
	.set_addr	= netdev_set_addr,
	.get_name	= netdev_get_name,
	.get_addr	= netdev_get_addr,
	.get_kobj	= netdev_get_kobj,
	.get_dev_flags	= netdev_get_dev_flags,
	.is_running	= netdev_is_running,
	.get_operstate	= netdev_get_operstate,
	.get_ifindex	= netdev_get_ifindex,
	.get_iflink	= netdev_get_iflink,
	.get_mtu	= netdev_get_mtu,
	.send		= internal_dev_recv,
};

int is_internal_dev(const struct net_device *netdev)
{
#ifdef HAVE_NET_DEVICE_OPS
	return netdev->netdev_ops == &internal_dev_netdev_ops;
#else
	return netdev->open == internal_dev_open;
#endif
}

int is_internal_vport(const struct vport *vport)
{
	return vport->ops == &internal_vport_ops;
}

struct vport *internal_dev_get_vport(struct net_device *netdev)
{
	struct internal_dev *internal_dev = internal_dev_priv(netdev);
	return rcu_dereference(internal_dev->attached_vport);
}
