/*
 * Copyright (c) 2007-2012 Nicira, Inc.
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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

static int vlan_tso __read_mostly;
module_param(vlan_tso, int, 0644);
MODULE_PARM_DESC(vlan_tso, "Enable TSO for VLAN packets");
#else
#define vlan_tso true
#endif

#ifdef HAVE_RHEL_OVS_HOOK
static atomic_t nr_bridges = ATOMIC_INIT(0);

extern struct sk_buff *(*openvswitch_handle_frame_hook)(struct sk_buff *skb);
#endif

static void netdev_port_receive(struct vport *vport, struct sk_buff *skb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
/* Called with rcu_read_lock and bottom-halves disabled. */
static rx_handler_result_t netdev_frame_hook(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct vport *vport;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	vport = ovs_netdev_get_vport(skb->dev);

	netdev_port_receive(vport, skb);

	return RX_HANDLER_CONSUMED;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) || \
      defined HAVE_RHEL_OVS_HOOK
/* Called with rcu_read_lock and bottom-halves disabled. */
static struct sk_buff *netdev_frame_hook(struct sk_buff *skb)
{
	struct vport *vport;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return skb;

	vport = ovs_netdev_get_vport(skb->dev);

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) || \
    defined HAVE_RHEL_OVS_HOOK
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

	vport = ovs_vport_alloc(sizeof(struct netdev_vport),
				&ovs_netdev_vport_ops, parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	netdev_vport = netdev_vport_priv(vport);

	netdev_vport->dev = dev_get_by_name(ovs_dp_get_net(vport->dp), parms->name);
	if (!netdev_vport->dev) {
		err = -ENODEV;
		goto error_free_vport;
	}

	if (netdev_vport->dev->flags & IFF_LOOPBACK ||
	    netdev_vport->dev->type != ARPHRD_ETHER ||
	    ovs_is_internal_dev(netdev_vport->dev)) {
		err = -EINVAL;
		goto error_put;
	}

#ifdef HAVE_RHEL_OVS_HOOK
	rcu_assign_pointer(netdev_vport->dev->ax25_ptr, vport);
	atomic_inc(&nr_bridges);
	rcu_assign_pointer(openvswitch_handle_frame_hook, netdev_frame_hook);
#else
	err = netdev_rx_handler_register(netdev_vport->dev, netdev_frame_hook,
					 vport);
	if (err)
		goto error_put;
#endif

	dev_set_promiscuity(netdev_vport->dev, 1);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	dev_disable_lro(netdev_vport->dev);
#endif
	netdev_vport->dev->priv_flags |= IFF_OVS_DATAPATH;

	return vport;

error_put:
	dev_put(netdev_vport->dev);
error_free_vport:
	ovs_vport_free(vport);
error:
	return ERR_PTR(err);
}

static void free_port_rcu(struct rcu_head *rcu)
{
	struct netdev_vport *netdev_vport = container_of(rcu,
					struct netdev_vport, rcu);

#ifdef HAVE_RHEL_OVS_HOOK
	rcu_assign_pointer(netdev_vport->dev->ax25_ptr, NULL);

	if (atomic_dec_and_test(&nr_bridges))
		rcu_assign_pointer(openvswitch_handle_frame_hook, NULL);
#endif
	dev_put(netdev_vport->dev);
	ovs_vport_free(vport_from_priv(netdev_vport));
}

static void netdev_destroy(struct vport *vport)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);

	netdev_vport->dev->priv_flags &= ~IFF_OVS_DATAPATH;
	netdev_rx_handler_unregister(netdev_vport->dev);
	dev_set_promiscuity(netdev_vport->dev, -1);

	call_rcu(&netdev_vport->rcu, free_port_rcu);
}

int ovs_netdev_set_addr(struct vport *vport, const unsigned char *addr)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	struct sockaddr sa;

	sa.sa_family = ARPHRD_ETHER;
	memcpy(sa.sa_data, addr, ETH_ALEN);

	return dev_set_mac_address(netdev_vport->dev, &sa);
}

const char *ovs_netdev_get_name(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->name;
}

const unsigned char *ovs_netdev_get_addr(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->dev_addr;
}

struct kobject *ovs_netdev_get_kobj(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return &netdev_vport->dev->NETDEV_DEV_MEMBER.kobj;
}

unsigned ovs_netdev_get_dev_flags(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return dev_get_flags(netdev_vport->dev);
}

int ovs_netdev_is_running(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netif_running(netdev_vport->dev);
}

unsigned char ovs_netdev_get_operstate(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->operstate;
}

int ovs_netdev_get_ifindex(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->ifindex;
}

int ovs_netdev_get_mtu(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->mtu;
}

/* Must be called with rcu_read_lock. */
static void netdev_port_receive(struct vport *vport, struct sk_buff *skb)
{
	if (unlikely(!vport))
		goto error;

	if (unlikely(skb_warn_if_lro(skb)))
		goto error;

	/* Make our own copy of the packet.  Otherwise we will mangle the
	 * packet for anyone who came before us (e.g. tcpdump via AF_PACKET).
	 * (No one comes after us, since we tell handle_bridge() that we took
	 * the packet.) */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		return;

	skb_push(skb, ETH_HLEN);

	if (unlikely(compute_ip_summed(skb, false)))
		goto error;

	vlan_copy_skb_tci(skb);

	ovs_vport_receive(vport, skb);
	return;

error:
	kfree_skb(skb);
}

static unsigned int packet_length(const struct sk_buff *skb)
{
	unsigned int length = skb->len - ETH_HLEN;

	if (skb->protocol == htons(ETH_P_8021Q))
		length -= VLAN_HLEN;

	return length;
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
	int mtu = netdev_vport->dev->mtu;
	int len;

	if (unlikely(packet_length(skb) > mtu && !skb_is_gso(skb))) {
		net_warn_ratelimited("%s: dropped over-mtu packet: %d > %d\n",
				     netdev_vport->dev->name,
				     packet_length(skb), mtu);
		goto error;
	}

	skb->dev = netdev_vport->dev;
	forward_ip_summed(skb, true);

	if (vlan_tx_tag_present(skb) && !dev_supports_vlan_tx(skb->dev)) {
		int features;

		features = netif_skb_features(skb);

		if (!vlan_tso)
			features &= ~(NETIF_F_TSO | NETIF_F_TSO6 |
				      NETIF_F_UFO | NETIF_F_FSO);

		if (netif_needs_gso(skb, features)) {
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

error:
	kfree_skb(skb);
	ovs_vport_record_error(vport, VPORT_E_TX_DROPPED);
	return 0;
}

/* Returns null if this device is not attached to a datapath. */
struct vport *ovs_netdev_get_vport(struct net_device *dev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36) || \
    defined HAVE_RHEL_OVS_HOOK
#if IFF_OVS_DATAPATH != 0
	if (likely(dev->priv_flags & IFF_OVS_DATAPATH))
#else
	if (likely(rcu_access_pointer(dev->rx_handler) == netdev_frame_hook))
#endif
#ifdef HAVE_RHEL_OVS_HOOK
		return (struct vport *)rcu_dereference_rtnl(dev->ax25_ptr);
#else
		return (struct vport *)rcu_dereference_rtnl(dev->rx_handler_data);
#endif
	else
		return NULL;
#else
	return (struct vport *)rcu_dereference_rtnl(dev->br_port);
#endif
}

const struct vport_ops ovs_netdev_vport_ops = {
	.type		= OVS_VPORT_TYPE_NETDEV,
	.flags          = VPORT_F_REQUIRED,
	.init		= netdev_init,
	.exit		= netdev_exit,
	.create		= netdev_create,
	.destroy	= netdev_destroy,
	.set_addr	= ovs_netdev_set_addr,
	.get_name	= ovs_netdev_get_name,
	.get_addr	= ovs_netdev_get_addr,
	.get_kobj	= ovs_netdev_get_kobj,
	.get_dev_flags	= ovs_netdev_get_dev_flags,
	.is_running	= ovs_netdev_is_running,
	.get_operstate	= ovs_netdev_get_operstate,
	.get_ifindex	= ovs_netdev_get_ifindex,
	.get_mtu	= ovs_netdev_get_mtu,
	.send		= netdev_send,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36) && \
    !defined HAVE_RHEL_OVS_HOOK
/*
 * In kernels earlier than 2.6.36, Open vSwitch cannot safely coexist with the
 * Linux bridge module, because there is only a single bridge hook function and
 * only a single br_port member in struct net_device, so this prevents loading
 * both bridge and openvswitch at the same time.
 */
BRIDGE_MUTUAL_EXCLUSION;
#endif
