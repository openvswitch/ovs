/*
 * Copyright (c) 2010, 2011 Nicira Networks.
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

#include "checksum.h"
#include "datapath.h"
#include "vlan.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37) && \
    !defined(HAVE_VLAN_BUG_WORKAROUND)
#include <linux/module.h>

static int vlan_tso __read_mostly = 0;
module_param(vlan_tso, int, 0644);
MODULE_PARM_DESC(vlan_tso, "Enable TSO for VLAN packets");
#else
#define vlan_tso true
#endif

/* If the native device stats aren't 64 bit use the vport stats tracking instead. */
#define USE_VPORT_STATS (sizeof(((struct net_device_stats *)0)->rx_bytes) < sizeof(u64))

static void netdev_port_receive(struct vport *vport, struct sk_buff *skb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
/* Called with rcu_read_lock and bottom-halves disabled. */
static rx_handler_result_t netdev_frame_hook(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct vport *vport;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	vport = netdev_get_vport(skb->dev);

	netdev_port_receive(vport, skb);

	return RX_HANDLER_CONSUMED;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
/* Called with rcu_read_lock and bottom-halves disabled. */
static struct sk_buff *netdev_frame_hook(struct sk_buff *skb)
{
	struct vport *vport;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return skb;

	vport = netdev_get_vport(skb->dev);

	netdev_port_receive(vport, skb);

	return NULL;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
/*
 * Used as br_handle_frame_hook.  (Cannot run bridge at the same time, even on
 * different set of devices!)
 */
/* Called with rcu_read_lock and bottom-halves disabled. */
static struct sk_buff *netdev_frame_hook(struct net_bridge_port *p,
					 struct sk_buff *skb)
{
	netdev_port_receive((struct vport *)p, skb);
	return NULL;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
/*
 * Used as br_handle_frame_hook.  (Cannot run bridge at the same time, even on
 * different set of devices!)
 */
/* Called with rcu_read_lock and bottom-halves disabled. */
static int netdev_frame_hook(struct net_bridge_port *p, struct sk_buff **pskb)
{
	netdev_port_receive((struct vport *)p, *pskb);
	return 1;
}
#else
#error
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
static int netdev_init(void) { return 0; }
static void netdev_exit(void) { }
#else
static int netdev_init(void)
{
	/* Hook into callback used by the bridge to intercept packets.
	 * Parasites we are. */
	br_handle_frame_hook = netdev_frame_hook;

	return 0;
}

static void netdev_exit(void)
{
	br_handle_frame_hook = NULL;
}
#endif

static struct vport *netdev_create(const struct vport_parms *parms)
{
	struct vport *vport;
	struct netdev_vport *netdev_vport;
	int err;

	vport = vport_alloc(sizeof(struct netdev_vport), &netdev_vport_ops, parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	netdev_vport = netdev_vport_priv(vport);

	netdev_vport->dev = dev_get_by_name(&init_net, parms->name);
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

	/* If we are using the vport stats layer initialize it to the current
	 * values so we are roughly consistent with the device stats. */
	if (USE_VPORT_STATS) {
		struct rtnl_link_stats64 stats;

		err = netdev_get_stats(vport, &stats);
		if (!err)
			vport_set_stats(vport, &stats);
	}

	err = netdev_rx_handler_register(netdev_vport->dev, netdev_frame_hook,
					 vport);
	if (err)
		goto error_put;

	dev_set_promiscuity(netdev_vport->dev, 1);
	dev_disable_lro(netdev_vport->dev);
	netdev_vport->dev->priv_flags |= IFF_OVS_DATAPATH;

	return vport;

error_put:
	dev_put(netdev_vport->dev);
error_free_vport:
	vport_free(vport);
error:
	return ERR_PTR(err);
}

static int netdev_destroy(struct vport *vport)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);

	netdev_vport->dev->priv_flags &= ~IFF_OVS_DATAPATH;
	netdev_rx_handler_unregister(netdev_vport->dev);
	dev_set_promiscuity(netdev_vport->dev, -1);

	synchronize_rcu();

	dev_put(netdev_vport->dev);
	vport_free(vport);

	return 0;
}

int netdev_set_mtu(struct vport *vport, int mtu)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return dev_set_mtu(netdev_vport->dev, mtu);
}

int netdev_set_addr(struct vport *vport, const unsigned char *addr)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	struct sockaddr sa;

	sa.sa_family = ARPHRD_ETHER;
	memcpy(sa.sa_data, addr, ETH_ALEN);

	return dev_set_mac_address(netdev_vport->dev, &sa);
}

const char *netdev_get_name(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->name;
}

const unsigned char *netdev_get_addr(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->dev_addr;
}

struct kobject *netdev_get_kobj(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return &netdev_vport->dev->NETDEV_DEV_MEMBER.kobj;
}

int netdev_get_stats(const struct vport *vport, struct rtnl_link_stats64 *stats)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	dev_get_stats(netdev_vport->dev, stats);
	return 0;
}

unsigned netdev_get_dev_flags(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return dev_get_flags(netdev_vport->dev);
}

int netdev_is_running(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netif_running(netdev_vport->dev);
}

unsigned char netdev_get_operstate(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->operstate;
}

int netdev_get_ifindex(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->ifindex;
}

int netdev_get_iflink(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->iflink;
}

int netdev_get_mtu(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->mtu;
}

/* Must be called with rcu_read_lock. */
static void netdev_port_receive(struct vport *vport, struct sk_buff *skb)
{
	if (unlikely(!vport)) {
		kfree_skb(skb);
		return;
	}

	/* Make our own copy of the packet.  Otherwise we will mangle the
	 * packet for anyone who came before us (e.g. tcpdump via AF_PACKET).
	 * (No one comes after us, since we tell handle_bridge() that we took
	 * the packet.) */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		return;

	skb_warn_if_lro(skb);

	skb_push(skb, ETH_HLEN);

	if (unlikely(compute_ip_summed(skb, false))) {
		kfree_skb(skb);
		return;
	}
	vlan_copy_skb_tci(skb);

	vport_receive(vport, skb);
}

static bool dev_supports_vlan_tx(struct net_device *dev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
	/* Software fallback means every device supports vlan_tci on TX. */
	return true;
#elif defined(HAVE_VLAN_BUG_WORKAROUND)
	return dev->features & NETIF_F_HW_VLAN_TX;
#else
	/* Assume that the driver is buggy. */
	return false;
#endif
}

static int netdev_send(struct vport *vport, struct sk_buff *skb)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	int len;

	skb->dev = netdev_vport->dev;
	forward_ip_summed(skb, true);

	if (vlan_tx_tag_present(skb) && !dev_supports_vlan_tx(skb->dev)) {
		int features = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
		features = skb->dev->features & skb->dev->vlan_features;
#endif

		if (!vlan_tso)
			features &= ~(NETIF_F_TSO | NETIF_F_TSO6 |
				      NETIF_F_UFO | NETIF_F_FSO);

		if (skb_is_gso(skb) &&
		    (!skb_gso_ok(skb, features) ||
		     unlikely(skb->ip_summed != CHECKSUM_PARTIAL))) {
			struct sk_buff *nskb;

			nskb = skb_gso_segment(skb, features);
			if (!nskb) {
				if (unlikely(skb_cloned(skb) &&
				    pskb_expand_head(skb, 0, 0, GFP_ATOMIC))) {
					kfree_skb(skb);
					return 0;
				}

				skb_shinfo(skb)->gso_type &= ~SKB_GSO_DODGY;
				goto tag;
			}

			if (IS_ERR(nskb)) {
				kfree_skb(skb);
				return 0;
			}
			consume_skb(skb);
			skb = nskb;

			len = 0;
			do {
				nskb = skb->next;
				skb->next = NULL;

				skb = __vlan_put_tag(skb, vlan_tx_tag_get(skb));
				if (likely(skb)) {
					len += skb->len;
					vlan_set_tci(skb, 0);
					dev_queue_xmit(skb);
				}

				skb = nskb;
			} while (skb);

			return len;
		}

tag:
		skb = __vlan_put_tag(skb, vlan_tx_tag_get(skb));
		if (unlikely(!skb))
			return 0;
		vlan_set_tci(skb, 0);
	}

	len = skb->len;
	dev_queue_xmit(skb);

	return len;
}

/* Returns null if this device is not attached to a datapath. */
struct vport *netdev_get_vport(struct net_device *dev)
{
#ifdef IFF_BRIDGE_PORT
#if IFF_BRIDGE_PORT != IFF_OVS_DATAPATH
	if (likely(dev->priv_flags & IFF_OVS_DATAPATH))
#else
	if (likely(rcu_access_pointer(dev->rx_handler) == netdev_frame_hook))	
#endif
		return (struct vport *)rcu_dereference_rtnl(dev->rx_handler_data);
	else
		return NULL;
#else
	return (struct vport *)rcu_dereference_rtnl(dev->br_port);
#endif
}

const struct vport_ops netdev_vport_ops = {
	.type		= ODP_VPORT_TYPE_NETDEV,
	.flags          = (VPORT_F_REQUIRED |
			  (USE_VPORT_STATS ? VPORT_F_GEN_STATS : 0)),
	.init		= netdev_init,
	.exit		= netdev_exit,
	.create		= netdev_create,
	.destroy	= netdev_destroy,
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
/*
 * In kernels earlier than 2.6.36, Open vSwitch cannot safely coexist with
 * the Linux bridge module on any released version of Linux, because there
 * is only a single bridge hook function and only a single br_port member
 * in struct net_device.
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
#endif
