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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/completion.h>
#include <linux/etherdevice.h>
#include <linux/if_bridge.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/genetlink.h>

#include "openvswitch/brcompat-netlink.h"
#include "datapath.h"

static struct genl_family brc_genl_family;
static struct genl_multicast_group brc_mc_group;

/* Time to wait for ovs-vswitchd to respond to a datapath action, in
 * jiffies. */
#define BRC_TIMEOUT (HZ * 5)

/* Mutex to serialize ovs-brcompatd callbacks.  (Some callbacks naturally hold
 * br_ioctl_mutex, others hold rtnl_lock, but we can't take the former
 * ourselves and we don't want to hold the latter over a potentially long
 * period of time.) */
static DEFINE_MUTEX(brc_serial);

/* Userspace communication. */
static DEFINE_SPINLOCK(brc_lock);    /* Ensure atomic access to these vars. */
static DECLARE_COMPLETION(brc_done); /* Userspace signaled operation done? */
static struct sk_buff *brc_reply;    /* Reply from userspace. */
static u32 brc_seq;		     /* Sequence number for current op. */

static struct sk_buff *brc_send_command(struct net *,
					struct sk_buff *,
					struct nlattr **attrs);
static int brc_send_simple_command(struct net *, struct sk_buff *);

static struct sk_buff *brc_make_request(int op, const char *bridge,
					const char *port)
{
	struct sk_buff *skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		goto error;

	genlmsg_put(skb, 0, 0, &brc_genl_family, 0, op);

	if (bridge && nla_put_string(skb, BRC_GENL_A_DP_NAME, bridge))
		goto nla_put_failure;
	if (port && nla_put_string(skb, BRC_GENL_A_PORT_NAME, port))
		goto nla_put_failure;

	return skb;

nla_put_failure:
	kfree_skb(skb);
error:
	return NULL;
}

static int brc_send_simple_command(struct net *net, struct sk_buff *request)
{
	struct nlattr *attrs[BRC_GENL_A_MAX + 1];
	struct sk_buff *reply;
	int error;

	reply = brc_send_command(net, request, attrs);
	if (IS_ERR(reply))
		return PTR_ERR(reply);

	error = nla_get_u32(attrs[BRC_GENL_A_ERR_CODE]);
	kfree_skb(reply);
	return -error;
}

static int brc_add_del_bridge(struct net *net, char __user *uname, int add)
{
	struct sk_buff *request;
	char name[IFNAMSIZ];

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (copy_from_user(name, uname, IFNAMSIZ))
		return -EFAULT;

	name[IFNAMSIZ - 1] = 0;
	request = brc_make_request(add ? BRC_GENL_C_DP_ADD : BRC_GENL_C_DP_DEL,
				   name, NULL);
	if (!request)
		return -ENOMEM;

	return brc_send_simple_command(net, request);
}

static int brc_get_indices(struct net *net,
			   int op, const char *br_name,
			   int __user *uindices, int n)
{
	struct nlattr *attrs[BRC_GENL_A_MAX + 1];
	struct sk_buff *request, *reply;
	int *indices;
	int ret;
	int len;

	if (n < 0)
		return -EINVAL;
	if (n >= 2048)
		return -ENOMEM;

	request = brc_make_request(op, br_name, NULL);
	if (!request)
		return -ENOMEM;

	reply = brc_send_command(net, request, attrs);
	ret = PTR_ERR(reply);
	if (IS_ERR(reply))
		goto exit;

	ret = -nla_get_u32(attrs[BRC_GENL_A_ERR_CODE]);
	if (ret < 0)
		goto exit_free_skb;

	ret = -EINVAL;
	if (!attrs[BRC_GENL_A_IFINDEXES])
		goto exit_free_skb;

	len = nla_len(attrs[BRC_GENL_A_IFINDEXES]);
	indices = nla_data(attrs[BRC_GENL_A_IFINDEXES]);
	if (len % sizeof(int))
		goto exit_free_skb;

	n = min_t(int, n, len / sizeof(int));
	ret = copy_to_user(uindices, indices, n * sizeof(int)) ? -EFAULT : n;

exit_free_skb:
	kfree_skb(reply);
exit:
	return ret;
}

/* Called with br_ioctl_mutex. */
static int brc_get_bridges(struct net *net, int __user *uindices, int n)
{
	return brc_get_indices(net, BRC_GENL_C_GET_BRIDGES, NULL, uindices, n);
}

/* Legacy deviceless bridge ioctl's.  Called with br_ioctl_mutex. */
static int old_deviceless(struct net *net, void __user *uarg)
{
	unsigned long args[3];

	if (copy_from_user(args, uarg, sizeof(args)))
		return -EFAULT;

	switch (args[0]) {
	case BRCTL_GET_BRIDGES:
		return brc_get_bridges(net, (int __user *)args[1], args[2]);

	case BRCTL_ADD_BRIDGE:
		return brc_add_del_bridge(net, (void __user *)args[1], 1);
	case BRCTL_DEL_BRIDGE:
		return brc_add_del_bridge(net, (void __user *)args[1], 0);
	}

	return -EOPNOTSUPP;
}

/* Called with the br_ioctl_mutex. */
static int
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
brc_ioctl_deviceless_stub(unsigned int cmd, void __user *uarg)
{
	struct net *net = NULL;
#else
brc_ioctl_deviceless_stub(struct net *net, unsigned int cmd, void __user *uarg)
{
#endif
	switch (cmd) {
	case SIOCGIFBR:
	case SIOCSIFBR:
		return old_deviceless(net, uarg);

	case SIOCBRADDBR:
		return brc_add_del_bridge(net, uarg, 1);
	case SIOCBRDELBR:
		return brc_add_del_bridge(net, uarg, 0);
	}

	return -EOPNOTSUPP;
}

static int brc_add_del_port(struct net_device *dev, int port_ifindex, int add)
{
	struct sk_buff *request;
	struct net_device *port;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	port = __dev_get_by_index(dev_net(dev), port_ifindex);
	if (!port)
		return -EINVAL;

	/* Save name of dev and port because there's a race between the
	 * rtnl_unlock() and the brc_send_simple_command(). */
	request = brc_make_request(add ? BRC_GENL_C_PORT_ADD : BRC_GENL_C_PORT_DEL,
				   dev->name, port->name);
	if (!request)
		return -ENOMEM;

	rtnl_unlock();
	err = brc_send_simple_command(dev_net(dev), request);
	rtnl_lock();

	return err;
}

static int brc_get_bridge_info(struct net_device *dev,
			       struct __bridge_info __user *ub)
{
	struct __bridge_info b;

	memset(&b, 0, sizeof(struct __bridge_info));

	/* First two bytes are the priority, which we should skip.  This comes
	 * from struct bridge_id in br_private.h, which is unavailable to us.
	 */
	memcpy((u8 *)&b.bridge_id + 2, dev->dev_addr, ETH_ALEN);
	b.stp_enabled = 0;

	if (copy_to_user(ub, &b, sizeof(struct __bridge_info)))
		return -EFAULT;

	return 0;
}

static int brc_get_port_list(struct net_device *dev, int __user *uindices,
			     int num)
{
	int retval;

	rtnl_unlock();
	retval = brc_get_indices(dev_net(dev), BRC_GENL_C_GET_PORTS, dev->name,
				 uindices, num);
	rtnl_lock();

	return retval;
}

/*
 * Format up to a page worth of forwarding table entries
 * userbuf -- where to copy result
 * maxnum  -- maximum number of entries desired
 *            (limited to a page for sanity)
 * offset  -- number of records to skip
 */
static int brc_get_fdb_entries(struct net_device *dev, void __user *userbuf,
			       unsigned long maxnum, unsigned long offset)
{
	struct nlattr *attrs[BRC_GENL_A_MAX + 1];
	struct sk_buff *request, *reply;
	int retval;
	int len;

	/* Clamp size to PAGE_SIZE, test maxnum to avoid overflow */
	if (maxnum > PAGE_SIZE/sizeof(struct __fdb_entry))
		maxnum = PAGE_SIZE/sizeof(struct __fdb_entry);

	request = brc_make_request(BRC_GENL_C_FDB_QUERY, dev->name, NULL);
	if (!request)
		return -ENOMEM;
	if (nla_put_u64(request, BRC_GENL_A_FDB_COUNT, maxnum) ||
	    nla_put_u64(request, BRC_GENL_A_FDB_SKIP, offset))
		goto nla_put_failure;

	rtnl_unlock();
	reply = brc_send_command(dev_net(dev), request, attrs);
	retval = PTR_ERR(reply);
	if (IS_ERR(reply))
		goto exit;

	retval = -nla_get_u32(attrs[BRC_GENL_A_ERR_CODE]);
	if (retval < 0)
		goto exit_free_skb;

	retval = -EINVAL;
	if (!attrs[BRC_GENL_A_FDB_DATA])
		goto exit_free_skb;
	len = nla_len(attrs[BRC_GENL_A_FDB_DATA]);
	if (len % sizeof(struct __fdb_entry) ||
	    len / sizeof(struct __fdb_entry) > maxnum)
		goto exit_free_skb;

	retval = len / sizeof(struct __fdb_entry);
	if (copy_to_user(userbuf, nla_data(attrs[BRC_GENL_A_FDB_DATA]), len))
		retval = -EFAULT;

exit_free_skb:
	kfree_skb(reply);
exit:
	rtnl_lock();
	return retval;

nla_put_failure:
	kfree_skb(request);
	return -ENOMEM;
}

/* Legacy ioctl's through SIOCDEVPRIVATE.  Called with rtnl_lock. */
static int old_dev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	unsigned long args[4];

	if (copy_from_user(args, rq->ifr_data, sizeof(args)))
		return -EFAULT;

	switch (args[0]) {
	case BRCTL_ADD_IF:
		return brc_add_del_port(dev, args[1], 1);
	case BRCTL_DEL_IF:
		return brc_add_del_port(dev, args[1], 0);

	case BRCTL_GET_BRIDGE_INFO:
		return brc_get_bridge_info(dev, (struct __bridge_info __user *)args[1]);

	case BRCTL_GET_PORT_LIST:
		return brc_get_port_list(dev, (int __user *)args[1], args[2]);

	case BRCTL_GET_FDB_ENTRIES:
		return brc_get_fdb_entries(dev, (void __user *)args[1],
					   args[2], args[3]);
	}

	return -EOPNOTSUPP;
}

/* Called with the rtnl_lock. */
static int brc_dev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	int err;

	switch (cmd) {
	case SIOCDEVPRIVATE:
		err = old_dev_ioctl(dev, rq, cmd);
		break;

	case SIOCBRADDIF:
		return brc_add_del_port(dev, rq->ifr_ifindex, 1);
	case SIOCBRDELIF:
		return brc_add_del_port(dev, rq->ifr_ifindex, 0);

	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}


static struct genl_family brc_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = BRC_GENL_FAMILY_NAME,
	.version = 1,
	.maxattr = BRC_GENL_A_MAX,
	 SET_NETNSOK
};

static int brc_genl_query(struct sk_buff *skb, struct genl_info *info)
{
	int err = -EINVAL;
	struct sk_buff *ans_skb;
	void *data;

	ans_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!ans_skb)
		return -ENOMEM;

	data = genlmsg_put_reply(ans_skb, info, &brc_genl_family,
				 0, BRC_GENL_C_QUERY_MC);
	if (data == NULL) {
		err = -ENOMEM;
		goto err;
	}
	if (nla_put_u32(ans_skb, BRC_GENL_A_MC_GROUP, brc_mc_group.id))
		goto nla_put_failure;

	genlmsg_end(ans_skb, data);
	return genlmsg_reply(ans_skb, info);

err:
nla_put_failure:
	kfree_skb(ans_skb);
	return err;
}

/* Attribute policy: what each attribute may contain.  */
static struct nla_policy brc_genl_policy[BRC_GENL_A_MAX + 1] = {
	[BRC_GENL_A_ERR_CODE] = { .type = NLA_U32 },
	[BRC_GENL_A_FDB_DATA] = { .type = NLA_UNSPEC },
};

static int brc_genl_dp_result(struct sk_buff *skb, struct genl_info *info)
{
	unsigned long int flags;
	int err;

	if (!info->attrs[BRC_GENL_A_ERR_CODE])
		return -EINVAL;

	skb = skb_clone(skb, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	spin_lock_irqsave(&brc_lock, flags);
	if (brc_seq == info->snd_seq) {
		brc_seq++;

		kfree_skb(brc_reply);
		brc_reply = skb;

		complete(&brc_done);
		err = 0;
	} else {
		kfree_skb(skb);
		err = -ESTALE;
	}
	spin_unlock_irqrestore(&brc_lock, flags);

	return err;
}

static struct genl_ops brc_genl_ops[] = {
	{ .cmd = BRC_GENL_C_QUERY_MC,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privelege. */
	  .policy = NULL,
	  .doit = brc_genl_query,
	},
	{ .cmd = BRC_GENL_C_DP_RESULT,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privelege. */
	  .policy = brc_genl_policy,
	  .doit = brc_genl_dp_result,
	},
};

static struct sk_buff *brc_send_command(struct net *net,
					struct sk_buff *request,
					struct nlattr **attrs)
{
	unsigned long int flags;
	struct sk_buff *reply;
	int error;

	mutex_lock(&brc_serial);

	/* Increment sequence number first, so that we ignore any replies
	 * to stale requests. */
	spin_lock_irqsave(&brc_lock, flags);
	nlmsg_hdr(request)->nlmsg_seq = ++brc_seq;
	INIT_COMPLETION(brc_done);
	spin_unlock_irqrestore(&brc_lock, flags);

	nlmsg_end(request, nlmsg_hdr(request));

	/* Send message. */
	error = genlmsg_multicast_netns(net, request, 0,
					brc_mc_group.id, GFP_KERNEL);
	if (error < 0)
		goto error;

	/* Wait for reply. */
	error = -ETIMEDOUT;
	if (!wait_for_completion_timeout(&brc_done, BRC_TIMEOUT)) {
		pr_warn("timed out waiting for userspace\n");
		goto error;
	}

	/* Grab reply. */
	spin_lock_irqsave(&brc_lock, flags);
	reply = brc_reply;
	brc_reply = NULL;
	spin_unlock_irqrestore(&brc_lock, flags);

	mutex_unlock(&brc_serial);

	/* Re-parse message.  Can't fail, since it parsed correctly once
	 * already. */
	error = nlmsg_parse(nlmsg_hdr(reply), GENL_HDRLEN,
			    attrs, BRC_GENL_A_MAX, brc_genl_policy);
	WARN_ON(error);

	return reply;

error:
	mutex_unlock(&brc_serial);
	return ERR_PTR(error);
}

static int __init brc_init(void)
{
	int err;

	pr_info("Open vSwitch Bridge Compatibility, built "__DATE__" "__TIME__"\n");

	/* Set the bridge ioctl handler */
	brioctl_set(brc_ioctl_deviceless_stub);

	/* Set the openvswitch device ioctl handler */
	ovs_dp_ioctl_hook = brc_dev_ioctl;

	/* Randomize the initial sequence number.  This is not a security
	 * feature; it only helps avoid crossed wires between userspace and
	 * the kernel when the module is unloaded and reloaded. */
	brc_seq = net_random();

	/* Register generic netlink family to communicate changes to
	 * userspace. */
	err = genl_register_family_with_ops(&brc_genl_family,
					    brc_genl_ops, ARRAY_SIZE(brc_genl_ops));
	if (err)
		goto error;

	strcpy(brc_mc_group.name, "brcompat");
	err = genl_register_mc_group(&brc_genl_family, &brc_mc_group);
	if (err < 0)
		goto err_unregister;

	return 0;

err_unregister:
	genl_unregister_family(&brc_genl_family);
error:
	pr_emerg("failed to install!\n");
	return err;
}

static void brc_cleanup(void)
{
	/* Unregister ioctl hooks */
	ovs_dp_ioctl_hook = NULL;
	brioctl_set(NULL);

	genl_unregister_family(&brc_genl_family);
}

module_init(brc_init);
module_exit(brc_cleanup);

MODULE_DESCRIPTION("Open vSwitch bridge compatibility");
MODULE_AUTHOR("Nicira, Inc.");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
/*
 * In kernels 2.6.36 and later, Open vSwitch can safely coexist with
 * the Linux bridge module, but it does not make sense to load both bridge and
 * brcompat, so this prevents it.
 */
BRIDGE_MUTUAL_EXCLUSION;
#endif
