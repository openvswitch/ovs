/*
 * Copyright (c) 2013 Nicira, Inc.
 * Copyright (c) 2013 Cisco Systems, Inc.
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

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/rculist.h>
#include <linux/udp.h>
#include <linux/module.h>
#include <linux/vhost.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/ip_tunnels.h>
#include <net/rtnetlink.h>
#include <net/route.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/vxlan.h>

#include "datapath.h"
#include "vport.h"

static int vhost_get_options(const struct vport *vport, struct sk_buff *skb)
{
	return 0;
}

static void vhost_tnl_destroy(struct vport *vport)
{
}

static struct vport *vhost_tnl_create(const struct vport_parms *parms)
{
	return NULL;
}

static int vhost_tnl_send(struct vport *vport, struct sk_buff *skb)
{
	return 0;
}

static int vhost_get_egress_tun_info(struct vport *vport, struct sk_buff *skb,
				     struct ovs_tunnel_info *egress_tun_info)
{
	return 0;
}

static const char *vhost_get_name(const struct vport *vport)
{
	return NULL;
}

static struct vport_ops ovs_vhost_vport_ops = {
	.type			= OVS_VPORT_TYPE_VHOST,
	.create			= vhost_tnl_create,
	.destroy		= vhost_tnl_destroy,
	.get_name		= vhost_get_name,
	.get_options		= vhost_get_options,
	.send			= vhost_tnl_send,
	.get_egress_tun_info	= vhost_get_egress_tun_info,
	.owner			= THIS_MODULE,
};

static int vhost_net_release(struct inode *inode, struct file *f)
{
	return 0;
}

static long vhost_net_ioctl(struct file *f, unsigned int ioctl,
			    unsigned long arg)
{
	switch (ioctl) {
	case VHOST_NET_SET_BACKEND:
		return 0;
	case VHOST_GET_FEATURES:
		return 0;
	case VHOST_SET_FEATURES:
		return 0;
	case VHOST_RESET_OWNER:
		return 0;
	case VHOST_SET_OWNER:
		return 0;
	default:
		return 0;
	}
}
static long vhost_net_compat_ioctl(struct file *f, unsigned int ioctl,
				   unsigned long arg)
{
	return vhost_net_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}

static int vhost_net_open(struct inode *inode, struct file *f)
{
	return 0;
}

static const struct file_operations vhost_net_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_net_release,
	.unlocked_ioctl = vhost_net_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = vhost_net_compat_ioctl,
#endif
	.open           = vhost_net_open,
	.llseek		= noop_llseek,
};

static struct miscdevice vhost_net_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vhost-net",
	.fops = &vhost_net_fops,
};

static int __init ovs_vhost_tnl_init(void)
{
	int err;

	err = misc_register(&vhost_net_misc);
	if (err)
		return err;
	err = ovs_vport_ops_register(&ovs_vhost_vport_ops);
	return err;
}

static void __exit ovs_vhost_tnl_exit(void)
{
	ovs_vport_ops_unregister(&ovs_vhost_vport_ops);
	misc_deregister(&vhost_net_misc);
}

module_init(ovs_vhost_tnl_init);
module_exit(ovs_vhost_tnl_exit);

MODULE_DESCRIPTION("OVS: VHOST switching port");
MODULE_LICENSE("GPL");
MODULE_ALIAS("vport-type-107");

