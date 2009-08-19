/*
 * Copyright (c) 2009 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

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
#include <linux/spinlock.h>
#include <linux/times.h>
#include <linux/version.h>

#include "dp_sysfs.h"
#include "datapath.h"
#include "dp_dev.h"

#ifdef CONFIG_SYSFS
#define to_dev(obj)	container_of(obj, struct device, kobj)

/* Hack to attempt to build on more platforms. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
#define DP_DEVICE_ATTR CLASS_DEVICE_ATTR
#define DEVICE_PARAMS struct class_device *d
#define DEVICE_ARGS d
#define DEV_ATTR(NAME) class_device_attr_##NAME
#else
#define DP_DEVICE_ATTR DEVICE_ATTR
#define DEVICE_PARAMS struct device *d, struct device_attribute *attr
#define DEVICE_ARGS d, attr
#define DEV_ATTR(NAME) dev_attr_##NAME
#endif

/*
 * Common code for storing bridge parameters.
 */
static ssize_t store_bridge_parm(DEVICE_PARAMS,
				 const char *buf, size_t len,
				 void (*set)(struct datapath *, unsigned long))
{
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
	char *endp;
	unsigned long val;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	val = simple_strtoul(buf, &endp, 0);
	if (endp == buf)
		return -EINVAL;

#if 0
	spin_lock_bh(&br->lock);
	(*set)(br, val);
	spin_unlock_bh(&br->lock);
#else
	/* xxx We use a default value of 0 for all fields.  If the caller is
	 * xxx attempting to set the value to our default, just silently
	 * xxx ignore the request. 
	 */
	if (val != 0) {
		printk("%s: xxx writing dp parms not supported yet!\n", 
		       dp_name(dp));
	}
#endif
	return len;
}


static ssize_t show_forward_delay(DEVICE_PARAMS, char *buf)
{
#if 0
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
	return sprintf(buf, "%lu\n", jiffies_to_clock_t(br->forward_delay));
#else
	return sprintf(buf, "%d\n", 0);
#endif
}

static void set_forward_delay(struct datapath *dp, unsigned long val)
{
#if 0
	unsigned long delay = clock_t_to_jiffies(val);
	br->forward_delay = delay;
	if (br_is_root_bridge(br))
		br->bridge_forward_delay = delay;
#else
	printk("%s: xxx attempt to set_forward_delay()\n", dp_name(dp));
#endif
}

static ssize_t store_forward_delay(DEVICE_PARAMS,
				   const char *buf, size_t len)
{
	return store_bridge_parm(DEVICE_ARGS, buf, len, set_forward_delay);
}
static DP_DEVICE_ATTR(forward_delay, S_IRUGO | S_IWUSR,
		   show_forward_delay, store_forward_delay);

static ssize_t show_hello_time(DEVICE_PARAMS, char *buf)
{
#if 0
	return sprintf(buf, "%lu\n",
		       jiffies_to_clock_t(to_bridge(d)->hello_time));
#else
	return sprintf(buf, "%d\n", 0);
#endif
}

static void set_hello_time(struct datapath *dp, unsigned long val)
{
#if 0
	unsigned long t = clock_t_to_jiffies(val);
	br->hello_time = t;
	if (br_is_root_bridge(br))
		br->bridge_hello_time = t;
#else
	printk("%s: xxx attempt to set_hello_time()\n", dp_name(dp));
#endif
}

static ssize_t store_hello_time(DEVICE_PARAMS,
				const char *buf,
				size_t len)
{
	return store_bridge_parm(DEVICE_ARGS, buf, len, set_hello_time);
}
static DP_DEVICE_ATTR(hello_time, S_IRUGO | S_IWUSR, show_hello_time,
		   store_hello_time);

static ssize_t show_max_age(DEVICE_PARAMS, char *buf)
{
#if 0
	return sprintf(buf, "%lu\n",
		       jiffies_to_clock_t(to_bridge(d)->max_age));
#else
	return sprintf(buf, "%d\n", 0);
#endif
}

static void set_max_age(struct datapath *dp, unsigned long val)
{
#if 0
	unsigned long t = clock_t_to_jiffies(val);
	br->max_age = t;
	if (br_is_root_bridge(br))
		br->bridge_max_age = t;
#else
	printk("%s: xxx attempt to set_max_age()\n", dp_name(dp));
#endif
}

static ssize_t store_max_age(DEVICE_PARAMS,
			     const char *buf, size_t len)
{
	return store_bridge_parm(DEVICE_ARGS, buf, len, set_max_age);
}
static DP_DEVICE_ATTR(max_age, S_IRUGO | S_IWUSR, show_max_age, store_max_age);

static ssize_t show_ageing_time(DEVICE_PARAMS, char *buf)
{
#if 0
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
	return sprintf(buf, "%lu\n", jiffies_to_clock_t(br->ageing_time));
#else
	return sprintf(buf, "%d\n", 0);
#endif
}

static void set_ageing_time(struct datapath *dp, unsigned long val)
{
#if 0
	br->ageing_time = clock_t_to_jiffies(val);
#else
	printk("%s: xxx attempt to set_ageing_time()\n", dp_name(dp));
#endif
}

static ssize_t store_ageing_time(DEVICE_PARAMS,
				 const char *buf, size_t len)
{
	return store_bridge_parm(DEVICE_ARGS, buf, len, set_ageing_time);
}
static DP_DEVICE_ATTR(ageing_time, S_IRUGO | S_IWUSR, show_ageing_time,
		   store_ageing_time);

static ssize_t show_stp_state(DEVICE_PARAMS, char *buf)
{
#if 0
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
	return sprintf(buf, "%d\n", br->stp_enabled);
#else
	return sprintf(buf, "%d\n", 0);
#endif
}


static ssize_t store_stp_state(DEVICE_PARAMS,
			       const char *buf,
			       size_t len)
{
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
#if 0
	char *endp;
	unsigned long val;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	val = simple_strtoul(buf, &endp, 0);
	if (endp == buf)
		return -EINVAL;

	rtnl_lock();
	br_stp_set_enabled(br, val);
	rtnl_unlock();
#else
	printk("%s: xxx attempt to set_stp_state()\n", dp_name(dp));
#endif

	return len;
}
static DP_DEVICE_ATTR(stp_state, S_IRUGO | S_IWUSR, show_stp_state,
		   store_stp_state);

static ssize_t show_priority(DEVICE_PARAMS, char *buf)
{
#if 0
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
	return sprintf(buf, "%d\n",
		       (br->bridge_id.prio[0] << 8) | br->bridge_id.prio[1]);
#else
	return sprintf(buf, "%d\n", 0);
#endif
}

static void set_priority(struct datapath *dp, unsigned long val)
{
#if 0
	br_stp_set_bridge_priority(br, (u16) val);
#else
	printk("%s: xxx attempt to set_priority()\n", dp_name(dp));
#endif
}

static ssize_t store_priority(DEVICE_PARAMS,
			       const char *buf, size_t len)
{
	return store_bridge_parm(DEVICE_ARGS, buf, len, set_priority);
}
static DP_DEVICE_ATTR(priority, S_IRUGO | S_IWUSR, show_priority, store_priority);

static ssize_t show_root_id(DEVICE_PARAMS, char *buf)
{
#if 0
	return br_show_bridge_id(buf, &to_bridge(d)->designated_root);
#else
	return sprintf(buf, "0000.010203040506\n");
#endif
}
static DP_DEVICE_ATTR(root_id, S_IRUGO, show_root_id, NULL);

static ssize_t show_bridge_id(DEVICE_PARAMS, char *buf)
{
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
	const unsigned char *addr = dp->ports[ODPP_LOCAL]->dev->dev_addr;

	/* xxx Do we need a lock of some sort? */
	return sprintf(buf, "%.2x%.2x.%.2x%.2x%.2x%.2x%.2x%.2x\n",
			0, 0, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}
static DP_DEVICE_ATTR(bridge_id, S_IRUGO, show_bridge_id, NULL);

static ssize_t show_root_port(DEVICE_PARAMS, char *buf)
{
#if 0
	return sprintf(buf, "%d\n", to_bridge(d)->root_port);
#else
	return sprintf(buf, "%d\n", 0);
#endif
}
static DP_DEVICE_ATTR(root_port, S_IRUGO, show_root_port, NULL);

static ssize_t show_root_path_cost(DEVICE_PARAMS, char *buf)
{
#if 0
	return sprintf(buf, "%d\n", to_bridge(d)->root_path_cost);
#else
	return sprintf(buf, "%d\n", 0);
#endif
}
static DP_DEVICE_ATTR(root_path_cost, S_IRUGO, show_root_path_cost, NULL);

static ssize_t show_topology_change(DEVICE_PARAMS, char *buf)
{
#if 0
	return sprintf(buf, "%d\n", to_bridge(d)->topology_change);
#else
	return sprintf(buf, "%d\n", 0);
#endif
}
static DP_DEVICE_ATTR(topology_change, S_IRUGO, show_topology_change, NULL);

static ssize_t show_topology_change_detected(DEVICE_PARAMS, char *buf)
{
#if 0
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
	return sprintf(buf, "%d\n", br->topology_change_detected);
#else
	return sprintf(buf, "%d\n", 0);
#endif
}
static DP_DEVICE_ATTR(topology_change_detected, S_IRUGO,
		   show_topology_change_detected, NULL);

static ssize_t show_hello_timer(DEVICE_PARAMS, char *buf)
{
#if 0
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
	return sprintf(buf, "%ld\n", br_timer_value(&br->hello_timer));
#else
	return sprintf(buf, "%d\n", 0);
#endif
}
static DP_DEVICE_ATTR(hello_timer, S_IRUGO, show_hello_timer, NULL);

static ssize_t show_tcn_timer(DEVICE_PARAMS, char *buf)
{
#if 0
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
	return sprintf(buf, "%ld\n", br_timer_value(&br->tcn_timer));
#else
	return sprintf(buf, "%d\n", 0);
#endif
}
static DP_DEVICE_ATTR(tcn_timer, S_IRUGO, show_tcn_timer, NULL);

static ssize_t show_topology_change_timer(DEVICE_PARAMS, char *buf)
{
#if 0
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
	return sprintf(buf, "%ld\n", br_timer_value(&br->topology_change_timer));
#else
	return sprintf(buf, "%d\n", 0);
#endif
}
static DP_DEVICE_ATTR(topology_change_timer, S_IRUGO, show_topology_change_timer,
		   NULL);

static ssize_t show_gc_timer(DEVICE_PARAMS, char *buf)
{
#if 0
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
	return sprintf(buf, "%ld\n", br_timer_value(&br->gc_timer));
#else
	return sprintf(buf, "%d\n", 0);
#endif
}
static DP_DEVICE_ATTR(gc_timer, S_IRUGO, show_gc_timer, NULL);

static ssize_t show_group_addr(DEVICE_PARAMS, char *buf)
{
#if 0
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
	return sprintf(buf, "%x:%x:%x:%x:%x:%x\n",
		       br->group_addr[0], br->group_addr[1],
		       br->group_addr[2], br->group_addr[3],
		       br->group_addr[4], br->group_addr[5]);
#else
	return sprintf(buf, "00:01:02:03:04:05\n");
#endif
}

static ssize_t store_group_addr(DEVICE_PARAMS,
				const char *buf, size_t len)
{
	struct datapath *dp = dp_dev_get_dp(to_net_dev(d));
#if 0
	unsigned new_addr[6];
	int i;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (sscanf(buf, "%x:%x:%x:%x:%x:%x",
		   &new_addr[0], &new_addr[1], &new_addr[2],
		   &new_addr[3], &new_addr[4], &new_addr[5]) != 6)
		return -EINVAL;

	/* Must be 01:80:c2:00:00:0X */
	for (i = 0; i < 5; i++)
		if (new_addr[i] != br_group_address[i])
			return -EINVAL;

	if (new_addr[5] & ~0xf)
		return -EINVAL;

	if (new_addr[5] == 1 	/* 802.3x Pause address */
	    || new_addr[5] == 2 /* 802.3ad Slow protocols */
	    || new_addr[5] == 3) /* 802.1X PAE address */
		return -EINVAL;

	spin_lock_bh(&br->lock);
	for (i = 0; i < 6; i++)
		br->group_addr[i] = new_addr[i];
	spin_unlock_bh(&br->lock);
#else
	printk("%s: xxx attempt to store_group_addr()\n", dp_name(dp));
#endif
	return len;
}

static DP_DEVICE_ATTR(group_addr, S_IRUGO | S_IWUSR,
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
int dp_sysfs_add_dp(struct datapath *dp)
{
	struct kobject *kobj = &dp->ports[ODPP_LOCAL]->dev->NETDEV_DEV_MEMBER.kobj;
	int err;

	/* Create /sys/class/net/<devname>/bridge directory. */
	err = sysfs_create_group(kobj, &bridge_group);
	if (err) {
		pr_info("%s: can't create group %s/%s\n",
			__func__, dp_name(dp), bridge_group.name);
		goto out1;
	}

	/* Create /sys/class/net/<devname>/brif directory. */
	err = kobject_add(&dp->ifobj, kobj, SYSFS_BRIDGE_PORT_SUBDIR);
	if (err) {
		pr_info("%s: can't add kobject (directory) %s/%s\n",
			__FUNCTION__, dp_name(dp), kobject_name(&dp->ifobj));
		goto out2;
	}
	kobject_uevent(&dp->ifobj, KOBJ_ADD);
	return 0;

 out2:
	sysfs_remove_group(kobj, &bridge_group);
 out1:
	return err;
}

int dp_sysfs_del_dp(struct datapath *dp)
{
	struct kobject *kobj = &dp->ports[ODPP_LOCAL]->dev->NETDEV_DEV_MEMBER.kobj;

	kobject_del(&dp->ifobj);
	sysfs_remove_group(kobj, &bridge_group);

	return 0;
}
#else /* !CONFIG_SYSFS */
int dp_sysfs_add_dp(struct datapath *dp) { return 0; }
int dp_sysfs_del_dp(struct datapath *dp) { return 0; }
int dp_sysfs_add_if(struct net_bridge_port *p) { return 0; }
int dp_sysfs_del_if(struct net_bridge_port *p) { return 0; }
#endif /* !CONFIG_SYSFS */
