/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/llc.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>

#include <net/llc.h>

#include "datapath.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

#include "compat.h"

struct vport_ops netdev_vport_ops;

static void netdev_port_receive(struct net_bridge_port *, struct sk_buff *);

/*
 * Used as br_handle_frame_hook.  (Cannot run bridge at the same time, even on
 * different set of devices!)
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
/* Called with rcu_read_lock and bottom-halves disabled. */
static struct sk_buff *
netdev_frame_hook(struct net_bridge_port *p, struct sk_buff *skb)
{
	netdev_port_receive(p, skb);
	return NULL;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
/* Called with rcu_read_lock and bottom-halves disabled. */
static int
netdev_frame_hook(struct net_bridge_port *p, struct sk_buff **pskb)
{
	netdev_port_receive(p, *pskb);
	return 1;
}
#else
#error
#endif

static int
netdev_init(void)
{
	/* Hook into callback used by the bridge to intercept packets.
	 * Parasites we are. */
	br_handle_frame_hook = netdev_frame_hook;

	return 0;
}

static void
netdev_exit(void)
{
	br_handle_frame_hook = NULL;
}

static struct vport *
netdev_create(const char *name, const void __user *config)
{
	struct vport *vport;
	struct netdev_vport *netdev_vport;
	int err;

	vport = vport_alloc(sizeof(struct netdev_vport), &netdev_vport_ops);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	netdev_vport = netdev_vport_priv(vport);

	netdev_vport->dev = dev_get_by_name(&init_net, name);
	if (!netdev_vport->dev) {
		err = -ENODEV;
		goto error_free_vport;
	}

	if (netdev_vport->dev->flags & IFF_LOOPBACK ||
	    netdev_vport->dev->type != ARPHRD_ETHER ||
	    is_internal_dev(netdev_vport->dev)) {
		err = -EINVAL;
		goto error_put;
	}

	if (netdev_vport->dev->br_port) {
		err = -EBUSY;
		goto error_put;
	}

	return vport;

error_put:
	dev_put(netdev_vport->dev);
error_free_vport:
	vport_free(vport);
error:
	return ERR_PTR(err);
}

static int
netdev_destroy(struct vport *vport)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);

	dev_put(netdev_vport->dev);
	vport_free(vport);

	return 0;
}

static int
netdev_attach(struct vport *vport)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);

	dev_set_promiscuity(netdev_vport->dev, 1);
	dev_disable_lro(netdev_vport->dev);
	rcu_assign_pointer(netdev_vport->dev->br_port, (struct net_bridge_port *)vport);

	return 0;
}

static int
netdev_detach(struct vport *vport)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);

	rcu_assign_pointer(netdev_vport->dev->br_port, NULL);
	dev_set_promiscuity(netdev_vport->dev, -1);

	return 0;
}

int
netdev_set_mtu(struct vport *vport, int mtu)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return dev_set_mtu(netdev_vport->dev, mtu);
}

int
netdev_set_addr(struct vport *vport, const unsigned char *addr)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	struct sockaddr sa;

	sa.sa_family = ARPHRD_ETHER;
	memcpy(sa.sa_data, addr, ETH_ALEN);

	return dev_set_mac_address(netdev_vport->dev, &sa);
}

const char *
netdev_get_name(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->name;
}

const unsigned char *
netdev_get_addr(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->dev_addr;
}

struct kobject *
netdev_get_kobj(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return &netdev_vport->dev->NETDEV_DEV_MEMBER.kobj;
}

int
netdev_get_stats(const struct vport *vport, struct xflow_vport_stats *stats)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	const struct net_device_stats *netdev_stats;

	netdev_stats = dev_get_stats(netdev_vport->dev);

	stats->rx_bytes		= netdev_stats->rx_bytes;
	stats->rx_packets	= netdev_stats->rx_packets;
	stats->tx_bytes		= netdev_stats->tx_bytes;
	stats->tx_packets	= netdev_stats->tx_packets;
	stats->rx_dropped	= netdev_stats->rx_dropped;
	stats->rx_errors	= netdev_stats->rx_errors;
	stats->rx_frame_err	= netdev_stats->rx_frame_errors;
	stats->rx_over_err	= netdev_stats->rx_over_errors;
	stats->rx_crc_err	= netdev_stats->rx_crc_errors;
	stats->tx_dropped	= netdev_stats->tx_dropped;
	stats->tx_errors	= netdev_stats->tx_errors;
	stats->collisions	= netdev_stats->collisions;

	return 0;
}

unsigned
netdev_get_dev_flags(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return dev_get_flags(netdev_vport->dev);
}

int
netdev_is_running(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netif_running(netdev_vport->dev);
}

unsigned char
netdev_get_operstate(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->operstate;
}

int
netdev_get_ifindex(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->ifindex;
}

int
netdev_get_iflink(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->iflink;
}

int
netdev_get_mtu(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->mtu;
}

/* Must be called with rcu_read_lock. */
static void
netdev_port_receive(struct net_bridge_port *p, struct sk_buff *skb)
{
	struct vport *vport = (struct vport *)p;

	/* Make our own copy of the packet.  Otherwise we will mangle the
	 * packet for anyone who came before us (e.g. tcpdump via AF_PACKET).
	 * (No one comes after us, since we tell handle_bridge() that we took
	 * the packet.) */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return;

	/* Push the Ethernet header back on. */
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	compute_ip_summed(skb, false);

	vport_receive(vport, skb);
}

static int
netdev_send(struct vport *vport, struct sk_buff *skb)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	int len = skb->len;

	skb->dev = netdev_vport->dev;
	forward_ip_summed(skb);
	dev_queue_xmit(skb);

	return len;
}

/* Returns null if this device is not attached to a datapath. */
struct vport *
netdev_get_vport(struct net_device *dev)
{
	return (struct vport *)dev->br_port;
}

struct vport_ops netdev_vport_ops = {
	.type		= "netdev",
	.flags		= VPORT_F_REQUIRED,
	.init		= netdev_init,
	.exit		= netdev_exit,
	.create		= netdev_create,
	.destroy	= netdev_destroy,
	.attach		= netdev_attach,
	.detach		= netdev_detach,
	.set_mtu	= netdev_set_mtu,
	.set_addr	= netdev_set_addr,
	.get_name	= netdev_get_name,
	.get_addr	= netdev_get_addr,
	.get_kobj	= netdev_get_kobj,
	.get_stats	= netdev_get_stats,
	.get_dev_flags	= netdev_get_dev_flags,
	.is_running	= netdev_is_running,
	.get_operstate	= netdev_get_operstate,
	.get_ifindex	= netdev_get_ifindex,
	.get_iflink	= netdev_get_iflink,
	.get_mtu	= netdev_get_mtu,
	.send		= netdev_send,
};

/*
 * Open vSwitch cannot safely coexist with the Linux bridge module on any
 * released version of Linux, because there is only a single bridge hook
 * function and only a single br_port member in struct net_device.
 *
 * Declaring and exporting this symbol enforces mutual exclusion.  The bridge
 * module also exports the same symbol, so the module loader will refuse to
 * load both modules at the same time (e.g. "bridge: exports duplicate symbol
 * br_should_route_hook (owned by openvswitch_mod)").
 *
 * The use of "typeof" here avoids the need to track changes in the type of
 * br_should_route_hook over various kernel versions.
 */
typeof(br_should_route_hook) br_should_route_hook;
EXPORT_SYMBOL(br_should_route_hook);
