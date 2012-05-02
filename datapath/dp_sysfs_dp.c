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

#include <linux/version.h>

/*
 *	Sysfs attributes of bridge for Open vSwitch
 *
 *  This has been shamelessly copied from the kernel sources.
 */

#include <linux/capability.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/if_bridge.h>
#include <linux/rtnetlink.h>
#include <linux/version.h>

#include "dp_sysfs.h"
#include "datapath.h"
#include "vport-internal_dev.h"

#ifdef CONFIG_SYSFS

/* Hack to attempt to build on more platforms. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
#define INTERNAL_DEVICE_ATTR CLASS_DEVICE_ATTR
#define DEVICE_PARAMS struct class_device *d
#define DEVICE_ARGS d
#define DEV_ATTR(NAME) class_device_attr_##NAME
#else
#define INTERNAL_DEVICE_ATTR DEVICE_ATTR
#define DEVICE_PARAMS struct device *d, struct device_attribute *attr
#define DEVICE_ARGS d, attr
#define DEV_ATTR(NAME) dev_attr_##NAME
#endif

static struct datapath *sysfs_get_dp(struct net_device *netdev)
{
	struct vport *vport = ovs_internal_dev_get_vport(netdev);
	return vport ? vport->dp : NULL;
}
/*
 * Common code for storing bridge parameters.
 */
static ssize_t store_bridge_parm(DEVICE_PARAMS,
				 const char *buf, size_t len,
				 void (*set)(struct datapath *, unsigned long))
{
	char *endp;
	unsigned long val;
	ssize_t result = len;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	val = simple_strtoul(buf, &endp, 0);
	if (endp == buf)
		return -EINVAL;

	/* xxx We use a default value of 0 for all fields.  If the caller is
	 * xxx attempting to set the value to our default, just silently
	 * xxx ignore the request.
	 */
	if (val != 0) {
		struct datapath *dp;

		rcu_read_lock();

		dp = sysfs_get_dp(to_net_dev(d));
		if (dp)
			pr_warning("%s: xxx writing dp parms not supported yet!\n",
			       ovs_dp_name(dp));
		else
			result = -ENODEV;

		rcu_read_unlock();
	}

	return result;
}


static ssize_t show_forward_delay(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}

static void set_forward_delay(struct datapath *dp, unsigned long val)
{
	pr_info("%s: xxx attempt to set_forward_delay()\n", ovs_dp_name(dp));
}

static ssize_t store_forward_delay(DEVICE_PARAMS,
				   const char *buf, size_t len)
{
	return store_bridge_parm(DEVICE_ARGS, buf, len, set_forward_delay);
}
static INTERNAL_DEVICE_ATTR(forward_delay, S_IRUGO | S_IWUSR,
		   show_forward_delay, store_forward_delay);

static ssize_t show_hello_time(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}

static void set_hello_time(struct datapath *dp, unsigned long val)
{
	pr_info("%s: xxx attempt to set_hello_time()\n", ovs_dp_name(dp));
}

static ssize_t store_hello_time(DEVICE_PARAMS,
				const char *buf,
				size_t len)
{
	return store_bridge_parm(DEVICE_ARGS, buf, len, set_hello_time);
}
static INTERNAL_DEVICE_ATTR(hello_time, S_IRUGO | S_IWUSR, show_hello_time,
		   store_hello_time);

static ssize_t show_max_age(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}

static void set_max_age(struct datapath *dp, unsigned long val)
{
	pr_info("%s: xxx attempt to set_max_age()\n", ovs_dp_name(dp));
}

static ssize_t store_max_age(DEVICE_PARAMS,
			     const char *buf, size_t len)
{
	return store_bridge_parm(DEVICE_ARGS, buf, len, set_max_age);
}
static INTERNAL_DEVICE_ATTR(max_age, S_IRUGO | S_IWUSR, show_max_age, store_max_age);

static ssize_t show_ageing_time(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}

static void set_ageing_time(struct datapath *dp, unsigned long val)
{
	pr_info("%s: xxx attempt to set_ageing_time()\n", ovs_dp_name(dp));
}

static ssize_t store_ageing_time(DEVICE_PARAMS,
				 const char *buf, size_t len)
{
	return store_bridge_parm(DEVICE_ARGS, buf, len, set_ageing_time);
}
static INTERNAL_DEVICE_ATTR(ageing_time, S_IRUGO | S_IWUSR, show_ageing_time,
		   store_ageing_time);

static ssize_t show_stp_state(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}


static ssize_t store_stp_state(DEVICE_PARAMS,
			       const char *buf,
			       size_t len)
{
	struct datapath *dp;
	ssize_t result = len;

	rcu_read_lock();

	dp = sysfs_get_dp(to_net_dev(d));
	if (dp)
		pr_info("%s: xxx attempt to set_stp_state()\n", ovs_dp_name(dp));
	else
		result = -ENODEV;

	rcu_read_unlock();

	return result;
}
static INTERNAL_DEVICE_ATTR(stp_state, S_IRUGO | S_IWUSR, show_stp_state,
		   store_stp_state);

static ssize_t show_priority(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}

static void set_priority(struct datapath *dp, unsigned long val)
{
	pr_info("%s: xxx attempt to set_priority()\n", ovs_dp_name(dp));
}

static ssize_t store_priority(DEVICE_PARAMS,
			       const char *buf, size_t len)
{
	return store_bridge_parm(DEVICE_ARGS, buf, len, set_priority);
}
static INTERNAL_DEVICE_ATTR(priority, S_IRUGO | S_IWUSR, show_priority, store_priority);

static ssize_t show_root_id(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "0000.010203040506\n");
}
static INTERNAL_DEVICE_ATTR(root_id, S_IRUGO, show_root_id, NULL);

static ssize_t show_bridge_id(DEVICE_PARAMS, char *buf)
{
	struct vport *vport;
	ssize_t result;

	rcu_read_lock();

	vport = ovs_internal_dev_get_vport(to_net_dev(d));
	if (vport) {
		const unsigned char *addr;

		addr = vport->ops->get_addr(vport);
		result = sprintf(buf, "%.2x%.2x.%.2x%.2x%.2x%.2x%.2x%.2x\n",
				 0, 0, addr[0], addr[1], addr[2], addr[3],
				 addr[4], addr[5]);
	} else
		result = -ENODEV;

	rcu_read_unlock();

	return result;
}
static INTERNAL_DEVICE_ATTR(bridge_id, S_IRUGO, show_bridge_id, NULL);

static ssize_t show_root_port(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}
static INTERNAL_DEVICE_ATTR(root_port, S_IRUGO, show_root_port, NULL);

static ssize_t show_root_path_cost(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}
static INTERNAL_DEVICE_ATTR(root_path_cost, S_IRUGO, show_root_path_cost, NULL);

static ssize_t show_topology_change(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}
static INTERNAL_DEVICE_ATTR(topology_change, S_IRUGO, show_topology_change, NULL);

static ssize_t show_topology_change_detected(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}
static INTERNAL_DEVICE_ATTR(topology_change_detected, S_IRUGO,
		   show_topology_change_detected, NULL);

static ssize_t show_hello_timer(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}
static INTERNAL_DEVICE_ATTR(hello_timer, S_IRUGO, show_hello_timer, NULL);

static ssize_t show_tcn_timer(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}
static INTERNAL_DEVICE_ATTR(tcn_timer, S_IRUGO, show_tcn_timer, NULL);

static ssize_t show_topology_change_timer(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}
static INTERNAL_DEVICE_ATTR(topology_change_timer, S_IRUGO, show_topology_change_timer,
		   NULL);

static ssize_t show_gc_timer(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "%d\n", 0);
}
static INTERNAL_DEVICE_ATTR(gc_timer, S_IRUGO, show_gc_timer, NULL);

static ssize_t show_group_addr(DEVICE_PARAMS, char *buf)
{
	return sprintf(buf, "00:01:02:03:04:05\n");
}

static ssize_t store_group_addr(DEVICE_PARAMS,
				const char *buf, size_t len)
{
	struct datapath *dp;
	ssize_t result = len;

	rcu_read_lock();

	dp = sysfs_get_dp(to_net_dev(d));
	if (dp)
		pr_info("%s: xxx attempt to store_group_addr()\n",
		       ovs_dp_name(dp));
	else
		result = -ENODEV;

	rcu_read_unlock();

	return result;
}

static INTERNAL_DEVICE_ATTR(group_addr, S_IRUGO | S_IWUSR,
		   show_group_addr, store_group_addr);

static struct attribute *bridge_attrs[] = {
	&DEV_ATTR(forward_delay).attr,
	&DEV_ATTR(hello_time).attr,
	&DEV_ATTR(max_age).attr,
	&DEV_ATTR(ageing_time).attr,
	&DEV_ATTR(stp_state).attr,
	&DEV_ATTR(priority).attr,
	&DEV_ATTR(bridge_id).attr,
	&DEV_ATTR(root_id).attr,
	&DEV_ATTR(root_path_cost).attr,
	&DEV_ATTR(root_port).attr,
	&DEV_ATTR(topology_change).attr,
	&DEV_ATTR(topology_change_detected).attr,
	&DEV_ATTR(hello_timer).attr,
	&DEV_ATTR(tcn_timer).attr,
	&DEV_ATTR(topology_change_timer).attr,
	&DEV_ATTR(gc_timer).attr,
	&DEV_ATTR(group_addr).attr,
	NULL
};

static struct attribute_group bridge_group = {
	.name = SYSFS_BRIDGE_ATTR, /* "bridge" */
	.attrs = bridge_attrs,
};

/*
 * Add entries in sysfs onto the existing network class device
 * for the bridge.
 *   Adds a attribute group "bridge" containing tuning parameters.
 *   Sub directory to hold links to interfaces.
 *
 * Note: the ifobj exists only to be a subdirectory
 *   to hold links.  The ifobj exists in the same data structure
 *   as its parent the bridge so reference counting works.
 */
int ovs_dp_sysfs_add_dp(struct datapath *dp)
{
	struct vport *vport = ovs_vport_rtnl(dp, OVSP_LOCAL);
	struct kobject *kobj = vport->ops->get_kobj(vport);
	int err;

#ifdef CONFIG_NET_NS
	/* Due to bug in 2.6.32 kernel, sysfs_create_group() could panic
	 * in other namespace than init_net. Following check is to avoid it. */
	if (!kobj->sd)
		return -ENOENT;
#endif
	/* Create /sys/class/net/<devname>/bridge directory. */
	err = sysfs_create_group(kobj, &bridge_group);
	if (err) {
		pr_info("%s: can't create group %s/%s\n",
			__func__, ovs_dp_name(dp), bridge_group.name);
		goto out1;
	}

	/* Create /sys/class/net/<devname>/brif directory. */
	err = kobject_add(&dp->ifobj, kobj, SYSFS_BRIDGE_PORT_SUBDIR);
	if (err) {
		pr_info("%s: can't add kobject (directory) %s/%s\n",
			__func__, ovs_dp_name(dp), kobject_name(&dp->ifobj));
		goto out2;
	}
	kobject_uevent(&dp->ifobj, KOBJ_ADD);
	return 0;

 out2:
	sysfs_remove_group(kobj, &bridge_group);
 out1:
	return err;
}

int ovs_dp_sysfs_del_dp(struct datapath *dp)
{
	struct vport *vport = ovs_vport_rtnl(dp, OVSP_LOCAL);
	struct kobject *kobj = vport->ops->get_kobj(vport);

#ifdef CONFIG_NET_NS
	if (!kobj->sd)
		return 0;
#endif

	kobject_del(&dp->ifobj);
	sysfs_remove_group(kobj, &bridge_group);

	return 0;
}
#else /* !CONFIG_SYSFS */
int ovs_dp_sysfs_add_dp(struct datapath *dp) { return 0; }
int ovs_dp_sysfs_del_dp(struct datapath *dp) { return 0; }
int dp_sysfs_add_if(struct vport *p) { return 0; }
int dp_sysfs_del_if(struct vport *p) { return 0; }
#endif /* !CONFIG_SYSFS */
