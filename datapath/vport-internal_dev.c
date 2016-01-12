/*
 * Copyright (c) 2007-2015 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <linux/hardirq.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <linux/u64_stats_sync.h>
#include <linux/netdev_features.h>

#include <net/dst.h>
#include <net/xfrm.h>
#include <net/rtnetlink.h>

#include "datapath.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

struct internal_dev {
	struct vport *vport;
};

static struct vport_ops ovs_internal_vport_ops;

static struct internal_dev *internal_dev_priv(struct net_device *netdev)
{
	return netdev_priv(netdev);
}

/* Called with rcu_read_lock_bh. */
static int internal_dev_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	int len, err;

	len = skb->len;
	rcu_read_lock();
	err = ovs_vport_receive(internal_dev_priv(netdev)->vport, skb, NULL);
	rcu_read_unlock();

	if (likely(!err)) {
#ifdef HAVE_DEV_TSTATS
		struct pcpu_sw_netstats *tstats;

		tstats = this_cpu_ptr((struct pcpu_sw_netstats __percpu *)netdev->tstats);

		u64_stats_update_begin(&tstats->syncp);
		tstats->tx_bytes += len;
		tstats->tx_packets++;
		u64_stats_update_end(&tstats->syncp);
#endif
	} else {
		netdev->stats.tx_errors++;
	}
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
	strlcpy(info->driver, "openvswitch", sizeof(info->driver));
}

static const struct ethtool_ops internal_dev_ethtool_ops = {
	.get_drvinfo	= internal_dev_getinfo,
	.get_link	= ethtool_op_get_link,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
	.get_sg		= ethtool_op_get_sg,
	.set_sg		= ethtool_op_set_sg,
	.get_tx_csum	= ethtool_op_get_tx_csum,
	.set_tx_csum	= ethtool_op_set_tx_hw_csum,
	.get_tso	= ethtool_op_get_tso,
	.set_tso	= ethtool_op_set_tso,
#endif
};

static int internal_dev_change_mtu(struct net_device *netdev, int new_mtu)
{
	if (new_mtu < 68)
		return -EINVAL;

	netdev->mtu = new_mtu;
	return 0;
}

static void internal_dev_destructor(struct net_device *dev)
{
	struct vport *vport = ovs_internal_dev_get_vport(dev);

	ovs_vport_free(vport);
	free_netdev(dev);
}

#ifdef HAVE_DEV_TSTATS
static int internal_dev_init(struct net_device *dev)
{
	dev->tstats = (typeof(dev->tstats)) netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;
	return 0;
}

static void internal_dev_uninit(struct net_device *dev)
{
	free_percpu(dev->tstats);
}
#endif

static const struct net_device_ops internal_dev_netdev_ops = {
#ifdef HAVE_DEV_TSTATS
	.ndo_init = internal_dev_init,
	.ndo_uninit = internal_dev_uninit,
	.ndo_get_stats64 = ip_tunnel_get_stats64,
#endif
	.ndo_open = internal_dev_open,
	.ndo_stop = internal_dev_stop,
	.ndo_start_xmit = internal_dev_xmit,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_change_mtu = internal_dev_change_mtu,
};

static struct rtnl_link_ops internal_dev_link_ops __read_mostly = {
	.kind = "openvswitch",
};

static void do_setup(struct net_device *netdev)
{
	ether_setup(netdev);

	netdev->netdev_ops = &internal_dev_netdev_ops;

	netdev->priv_flags &= ~IFF_TX_SKB_SHARING;
	netdev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_OPENVSWITCH;
	netdev->destructor = internal_dev_destructor;
	netdev->ethtool_ops = &internal_dev_ethtool_ops;
	netdev->rtnl_link_ops = &internal_dev_link_ops;
	netdev->tx_queue_len = 0;

	netdev->features = NETIF_F_LLTX | NETIF_F_SG | NETIF_F_FRAGLIST |
			   NETIF_F_HIGHDMA | NETIF_F_HW_CSUM |
			   NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ENCAP_ALL;

	netdev->vlan_features = netdev->features;
	netdev->features |= NETIF_F_HW_VLAN_CTAG_TX;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
	netdev->hw_enc_features = netdev->features;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
	netdev->hw_features = netdev->features & ~NETIF_F_LLTX;
#endif
	eth_hw_addr_random(netdev);
}

static struct vport *internal_dev_create(const struct vport_parms *parms)
{
	struct vport *vport;
	struct internal_dev *internal_dev;
	int err;

	vport = ovs_vport_alloc(0, &ovs_internal_vport_ops, parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	vport->dev = alloc_netdev(sizeof(struct internal_dev),
				  parms->name, NET_NAME_UNKNOWN, do_setup);
	if (!vport->dev) {
		err = -ENOMEM;
		goto error_free_vport;
	}

	dev_net_set(vport->dev, ovs_dp_get_net(vport->dp));
	internal_dev = internal_dev_priv(vport->dev);
	internal_dev->vport = vport;

	/* Restrict bridge port to current netns. */
	if (vport->port_no == OVSP_LOCAL)
		vport->dev->features |= NETIF_F_NETNS_LOCAL;

	rtnl_lock();
	err = register_netdevice(vport->dev);
	if (err)
		goto error_free_netdev;

	dev_set_promiscuity(vport->dev, 1);
	rtnl_unlock();
	netif_start_queue(vport->dev);

	return vport;

error_free_netdev:
	rtnl_unlock();
	free_netdev(vport->dev);
error_free_vport:
	ovs_vport_free(vport);
error:
	return ERR_PTR(err);
}

static void internal_dev_destroy(struct vport *vport)
{
	netif_stop_queue(vport->dev);
	rtnl_lock();
	dev_set_promiscuity(vport->dev, -1);

	/* unregister_netdevice() waits for an RCU grace period. */
	unregister_netdevice(vport->dev);

	rtnl_unlock();
}

static netdev_tx_t internal_dev_recv(struct sk_buff *skb)
{
	struct net_device *netdev = skb->dev;
#ifdef HAVE_DEV_TSTATS
	struct pcpu_sw_netstats *stats;
#endif

	if (unlikely(!(netdev->flags & IFF_UP))) {
		kfree_skb(skb);
		netdev->stats.rx_dropped++;
		return NETDEV_TX_OK;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
	if (skb_vlan_tag_present(skb)) {
		if (unlikely(!vlan_insert_tag_set_proto(skb,
							skb->vlan_proto,
							skb_vlan_tag_get(skb))))
			return NETDEV_TX_OK;

		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->csum = csum_add(skb->csum,
					     csum_partial(skb->data + (2 * ETH_ALEN),
							  VLAN_HLEN, 0));

		vlan_set_tci(skb, 0);
	}
#endif

	skb_dst_drop(skb);
	nf_reset(skb);
	secpath_reset(skb);

	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, netdev);
	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);

#ifdef HAVE_DEV_TSTATS
	stats = this_cpu_ptr((struct pcpu_sw_netstats __percpu *)netdev->tstats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);
#endif

	netif_rx(skb);
	return NETDEV_TX_OK;
}

static struct vport_ops ovs_internal_vport_ops = {
	.type		= OVS_VPORT_TYPE_INTERNAL,
	.create		= internal_dev_create,
	.destroy	= internal_dev_destroy,
	.send		= internal_dev_recv,
};

int ovs_is_internal_dev(const struct net_device *netdev)
{
	return netdev->netdev_ops == &internal_dev_netdev_ops;
}

struct vport *ovs_internal_dev_get_vport(struct net_device *netdev)
{
	if (!ovs_is_internal_dev(netdev))
		return NULL;

	return internal_dev_priv(netdev)->vport;
}

int ovs_internal_dev_rtnl_link_register(void)
{
	int err;

	err = rtnl_link_register(&internal_dev_link_ops);
	if (err < 0)
		return err;

	err = ovs_vport_ops_register(&ovs_internal_vport_ops);
	if (err < 0)
		rtnl_link_unregister(&internal_dev_link_ops);

	return err;
}

void ovs_internal_dev_rtnl_link_unregister(void)
{
	ovs_vport_ops_unregister(&ovs_internal_vport_ops);
	rtnl_link_unregister(&internal_dev_link_ops);
}
