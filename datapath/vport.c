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

#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/compat.h>
#include <linux/version.h>
#include <net/net_namespace.h>

#include "datapath.h"
#include "vport.h"
#include "vport-internal_dev.h"

/* List of statically compiled vport implementations.  Don't forget to also
 * add yours to the list at the bottom of vport.h. */
static const struct vport_ops *base_vport_ops_list[] = {
	&ovs_netdev_vport_ops,
	&ovs_internal_vport_ops,
	&ovs_patch_vport_ops,
	&ovs_gre_vport_ops,
	&ovs_gre_ft_vport_ops,
	&ovs_gre64_vport_ops,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	&ovs_capwap_vport_ops,
#endif
};

static const struct vport_ops **vport_ops_list;
static int n_vport_types;

/* Protected by RCU read lock for reading, RTNL lock for writing. */
static struct hlist_head *dev_table;
#define VPORT_HASH_BUCKETS 1024

/**
 *	ovs_vport_init - initialize vport subsystem
 *
 * Called at module load time to initialize the vport subsystem and any
 * compiled in vport types.
 */
int ovs_vport_init(void)
{
	int err;
	int i;

	dev_table = kzalloc(VPORT_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (!dev_table) {
		err = -ENOMEM;
		goto error;
	}

	vport_ops_list = kmalloc(ARRAY_SIZE(base_vport_ops_list) *
				 sizeof(struct vport_ops *), GFP_KERNEL);
	if (!vport_ops_list) {
		err = -ENOMEM;
		goto error_dev_table;
	}

	for (i = 0; i < ARRAY_SIZE(base_vport_ops_list); i++) {
		const struct vport_ops *new_ops = base_vport_ops_list[i];

		if (new_ops->init)
			err = new_ops->init();
		else
			err = 0;

		if (!err)
			vport_ops_list[n_vport_types++] = new_ops;
		else if (new_ops->flags & VPORT_F_REQUIRED) {
			ovs_vport_exit();
			goto error;
		}
	}

	return 0;

error_dev_table:
	kfree(dev_table);
error:
	return err;
}

/**
 *	ovs_vport_exit - shutdown vport subsystem
 *
 * Called at module exit time to shutdown the vport subsystem and any
 * initialized vport types.
 */
void ovs_vport_exit(void)
{
	int i;

	for (i = 0; i < n_vport_types; i++) {
		if (vport_ops_list[i]->exit)
			vport_ops_list[i]->exit();
	}

	kfree(vport_ops_list);
	kfree(dev_table);
}

static struct hlist_head *hash_bucket(struct net *net, const char *name)
{
	unsigned int hash = jhash(name, strlen(name), (unsigned long) net);
	return &dev_table[hash & (VPORT_HASH_BUCKETS - 1)];
}

/**
 *	ovs_vport_locate - find a port that has already been created
 *
 * @name: name of port to find
 *
 * Must be called with RTNL or RCU read lock.
 */
struct vport *ovs_vport_locate(struct net *net, const char *name)
{
	struct hlist_head *bucket = hash_bucket(net, name);
	struct vport *vport;
	struct hlist_node *node;

	hlist_for_each_entry_rcu(vport, node, bucket, hash_node)
		if (!strcmp(name, vport->ops->get_name(vport)) &&
		    net_eq(ovs_dp_get_net(vport->dp), net))
			return vport;

	return NULL;
}

static void release_vport(struct kobject *kobj)
{
	struct vport *p = container_of(kobj, struct vport, kobj);
	kfree(p);
}

static struct kobj_type brport_ktype = {
#ifdef CONFIG_SYSFS
	.sysfs_ops = &ovs_brport_sysfs_ops,
#endif
	.release = release_vport
};

/**
 *	ovs_vport_alloc - allocate and initialize new vport
 *
 * @priv_size: Size of private data area to allocate.
 * @ops: vport device ops
 *
 * Allocate and initialize a new vport defined by @ops.  The vport will contain
 * a private data area of size @priv_size that can be accessed using
 * vport_priv().  vports that are no longer needed should be released with
 * ovs_vport_free().
 */
struct vport *ovs_vport_alloc(int priv_size, const struct vport_ops *ops,
			      const struct vport_parms *parms)
{
	struct vport *vport;
	size_t alloc_size;

	alloc_size = sizeof(struct vport);
	if (priv_size) {
		alloc_size = ALIGN(alloc_size, VPORT_ALIGN);
		alloc_size += priv_size;
	}

	vport = kzalloc(alloc_size, GFP_KERNEL);
	if (!vport)
		return ERR_PTR(-ENOMEM);

	vport->dp = parms->dp;
	vport->port_no = parms->port_no;
	vport->upcall_portid = parms->upcall_portid;
	vport->ops = ops;
	INIT_HLIST_NODE(&vport->dp_hash_node);

	/* Initialize kobject for bridge.  This will be added as
	 * /sys/class/net/<devname>/brport later, if sysfs is enabled. */
	vport->kobj.kset = NULL;
	kobject_init(&vport->kobj, &brport_ktype);

	vport->percpu_stats = alloc_percpu(struct vport_percpu_stats);
	if (!vport->percpu_stats) {
		kfree(vport);
		return ERR_PTR(-ENOMEM);
	}

	spin_lock_init(&vport->stats_lock);

	return vport;
}

/**
 *	ovs_vport_free - uninitialize and free vport
 *
 * @vport: vport to free
 *
 * Frees a vport allocated with ovs_vport_alloc() when it is no longer needed.
 *
 * The caller must ensure that an RCU grace period has passed since the last
 * time @vport was in a datapath.
 */
void ovs_vport_free(struct vport *vport)
{
	free_percpu(vport->percpu_stats);

	kobject_put(&vport->kobj);
}

/**
 *	ovs_vport_add - add vport device (for kernel callers)
 *
 * @parms: Information about new vport.
 *
 * Creates a new vport with the specified configuration (which is dependent on
 * device type).  RTNL lock must be held.
 */
struct vport *ovs_vport_add(const struct vport_parms *parms)
{
	struct vport *vport;
	int err = 0;
	int i;

	ASSERT_RTNL();

	for (i = 0; i < n_vport_types; i++) {
		if (vport_ops_list[i]->type == parms->type) {
			struct hlist_head *bucket;

			vport = vport_ops_list[i]->create(parms);
			if (IS_ERR(vport)) {
				err = PTR_ERR(vport);
				goto out;
			}

			bucket = hash_bucket(ovs_dp_get_net(vport->dp),
					     vport->ops->get_name(vport));
			hlist_add_head_rcu(&vport->hash_node, bucket);
			return vport;
		}
	}

	err = -EAFNOSUPPORT;

out:
	return ERR_PTR(err);
}

/**
 *	ovs_vport_set_options - modify existing vport device (for kernel callers)
 *
 * @vport: vport to modify.
 * @port: New configuration.
 *
 * Modifies an existing device with the specified configuration (which is
 * dependent on device type).  RTNL lock must be held.
 */
int ovs_vport_set_options(struct vport *vport, struct nlattr *options)
{
	ASSERT_RTNL();

	if (!vport->ops->set_options)
		return -EOPNOTSUPP;
	return vport->ops->set_options(vport, options);
}

/**
 *	ovs_vport_del - delete existing vport device
 *
 * @vport: vport to delete.
 *
 * Detaches @vport from its datapath and destroys it.  It is possible to fail
 * for reasons such as lack of memory.  RTNL lock must be held.
 */
void ovs_vport_del(struct vport *vport)
{
	ASSERT_RTNL();

	hlist_del_rcu(&vport->hash_node);

	vport->ops->destroy(vport);
}

/**
 *	ovs_vport_set_addr - set device Ethernet address (for kernel callers)
 *
 * @vport: vport on which to set Ethernet address.
 * @addr: New address.
 *
 * Sets the Ethernet address of the given device.  Some devices may not support
 * setting the Ethernet address, in which case the result will always be
 * -EOPNOTSUPP.  RTNL lock must be held.
 */
int ovs_vport_set_addr(struct vport *vport, const unsigned char *addr)
{
	ASSERT_RTNL();

	if (!is_valid_ether_addr(addr))
		return -EADDRNOTAVAIL;

	if (vport->ops->set_addr)
		return vport->ops->set_addr(vport, addr);
	else
		return -EOPNOTSUPP;
}

/**
 *	ovs_vport_set_stats - sets offset device stats
 *
 * @vport: vport on which to set stats
 * @stats: stats to set
 *
 * Provides a set of transmit, receive, and error stats to be added as an
 * offset to the collect data when stats are retreived.  Some devices may not
 * support setting the stats, in which case the result will always be
 * -EOPNOTSUPP.
 *
 * Must be called with RTNL lock.
 */
void ovs_vport_set_stats(struct vport *vport, struct ovs_vport_stats *stats)
{
	ASSERT_RTNL();

	spin_lock_bh(&vport->stats_lock);
	vport->offset_stats = *stats;
	spin_unlock_bh(&vport->stats_lock);
}

/**
 *	ovs_vport_get_stats - retrieve device stats
 *
 * @vport: vport from which to retrieve the stats
 * @stats: location to store stats
 *
 * Retrieves transmit, receive, and error stats for the given device.
 *
 * Must be called with RTNL lock or rcu_read_lock.
 */
void ovs_vport_get_stats(struct vport *vport, struct ovs_vport_stats *stats)
{
	int i;

	/* We potentially have 3 sources of stats that need to be
	 * combined: those we have collected (split into err_stats and
	 * percpu_stats), offset_stats from set_stats(), and device
	 * error stats from netdev->get_stats() (for errors that happen
	 * downstream and therefore aren't reported through our
	 * vport_record_error() function).
	 * Stats from first two sources are merged and reported by ovs over
	 * OVS_VPORT_ATTR_STATS.
	 * netdev-stats can be directly read over netlink-ioctl.
	 */

	spin_lock_bh(&vport->stats_lock);

	*stats = vport->offset_stats;

	stats->rx_errors	+= vport->err_stats.rx_errors;
	stats->tx_errors	+= vport->err_stats.tx_errors;
	stats->tx_dropped	+= vport->err_stats.tx_dropped;
	stats->rx_dropped	+= vport->err_stats.rx_dropped;

	spin_unlock_bh(&vport->stats_lock);

	for_each_possible_cpu(i) {
		const struct vport_percpu_stats *percpu_stats;
		struct vport_percpu_stats local_stats;
		unsigned int start;

		percpu_stats = per_cpu_ptr(vport->percpu_stats, i);

		do {
			start = u64_stats_fetch_begin_bh(&percpu_stats->sync);
			local_stats = *percpu_stats;
		} while (u64_stats_fetch_retry_bh(&percpu_stats->sync, start));

		stats->rx_bytes		+= local_stats.rx_bytes;
		stats->rx_packets	+= local_stats.rx_packets;
		stats->tx_bytes		+= local_stats.tx_bytes;
		stats->tx_packets	+= local_stats.tx_packets;
	}
}

/**
 *	ovs_vport_get_options - retrieve device options
 *
 * @vport: vport from which to retrieve the options.
 * @skb: sk_buff where options should be appended.
 *
 * Retrieves the configuration of the given device, appending an
 * %OVS_VPORT_ATTR_OPTIONS attribute that in turn contains nested
 * vport-specific attributes to @skb.
 *
 * Returns 0 if successful, -EMSGSIZE if @skb has insufficient room, or another
 * negative error code if a real error occurred.  If an error occurs, @skb is
 * left unmodified.
 *
 * Must be called with RTNL lock or rcu_read_lock.
 */
int ovs_vport_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct nlattr *nla;

	nla = nla_nest_start(skb, OVS_VPORT_ATTR_OPTIONS);
	if (!nla)
		return -EMSGSIZE;

	if (vport->ops->get_options) {
		int err = vport->ops->get_options(vport, skb);
		if (err) {
			nla_nest_cancel(skb, nla);
			return err;
		}
	}

	nla_nest_end(skb, nla);
	return 0;
}

/**
 *	ovs_vport_receive - pass up received packet to the datapath for processing
 *
 * @vport: vport that received the packet
 * @skb: skb that was received
 *
 * Must be called with rcu_read_lock.  The packet cannot be shared and
 * skb->data should point to the Ethernet header.  The caller must have already
 * called compute_ip_summed() to initialize the checksumming fields.
 */
void ovs_vport_receive(struct vport *vport, struct sk_buff *skb)
{
	struct vport_percpu_stats *stats;

	stats = per_cpu_ptr(vport->percpu_stats, smp_processor_id());

	u64_stats_update_begin(&stats->sync);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->sync);

	if (!(vport->ops->flags & VPORT_F_FLOW))
		OVS_CB(skb)->flow = NULL;

	if (!(vport->ops->flags & VPORT_F_TUN_ID))
		OVS_CB(skb)->tun_key = NULL;

	ovs_dp_process_received_packet(vport, skb);
}

/**
 *	ovs_vport_send - send a packet on a device
 *
 * @vport: vport on which to send the packet
 * @skb: skb to send
 *
 * Sends the given packet and returns the length of data sent.  Either RTNL
 * lock or rcu_read_lock must be held.
 */
int ovs_vport_send(struct vport *vport, struct sk_buff *skb)
{
	int sent = vport->ops->send(vport, skb);

	if (likely(sent)) {
		struct vport_percpu_stats *stats;

		stats = per_cpu_ptr(vport->percpu_stats, smp_processor_id());

		u64_stats_update_begin(&stats->sync);
		stats->tx_packets++;
		stats->tx_bytes += sent;
		u64_stats_update_end(&stats->sync);
	}
	return sent;
}

/**
 *	ovs_vport_record_error - indicate device error to generic stats layer
 *
 * @vport: vport that encountered the error
 * @err_type: one of enum vport_err_type types to indicate the error type
 *
 * If using the vport generic stats layer indicate that an error of the given
 * type has occured.
 */
void ovs_vport_record_error(struct vport *vport, enum vport_err_type err_type)
{
	spin_lock(&vport->stats_lock);

	switch (err_type) {
	case VPORT_E_RX_DROPPED:
		vport->err_stats.rx_dropped++;
		break;

	case VPORT_E_RX_ERROR:
		vport->err_stats.rx_errors++;
		break;

	case VPORT_E_TX_DROPPED:
		vport->err_stats.tx_dropped++;
		break;

	case VPORT_E_TX_ERROR:
		vport->err_stats.tx_errors++;
		break;
	}

	spin_unlock(&vport->stats_lock);
}
