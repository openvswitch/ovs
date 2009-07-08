#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/if_bridge.h>
#include <linux/rculist.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/genetlink.h>

#include "compat.h"
#include "openvswitch/brcompat-netlink.h"
#include "brc_procfs.h"
#include "brc_sysfs.h"
#include "datapath.h"
#include "dp_dev.h"

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
static int brc_err;		     /* Error code from userspace. */
static u32 brc_seq;		     /* Sequence number for current op. */

static int brc_send_command(const char *bridge, const char *port, int op);

static int
get_dp_ifindices(int *indices, int num)
{
	int i, index = 0;

	rcu_read_lock();
	for (i=0; i < ODP_MAX && index < num; i++) {
		struct datapath *dp = get_dp(i);
		if (!dp)
			continue;
		indices[index++] = dp->ports[ODPP_LOCAL]->dev->ifindex;
	}
	rcu_read_unlock();

	return index;
}

static void
get_port_ifindices(struct datapath *dp, int *ifindices, int num)
{
	struct net_bridge_port *p;

	rcu_read_lock();
	list_for_each_entry_rcu (p, &dp->port_list, node) {
		if (p->port_no < num)
			ifindices[p->port_no] = p->dev->ifindex;
	}
	rcu_read_unlock();
}

static int brc_add_del_bridge(char __user *uname, int add)
{
	char name[IFNAMSIZ];

	if (copy_from_user(name, uname, IFNAMSIZ))
		return -EFAULT;

	name[IFNAMSIZ - 1] = 0;
	return brc_send_command(name, NULL,
				add ? BRC_GENL_C_DP_ADD : BRC_GENL_C_DP_DEL);
}

static int brc_get_bridges(int __user *uindices, int n)
{
	int *indices;
	int ret;

	if (n >= 2048)
		return -ENOMEM;

	indices = kcalloc(n, sizeof(int), GFP_KERNEL);
	if (indices == NULL)
		return -ENOMEM;

	n = get_dp_ifindices(indices, n);

	ret = copy_to_user(uindices, indices, n * sizeof(int)) ? -EFAULT : n;

	kfree(indices);
	return ret;
}

/* Legacy deviceless bridge ioctl's.  Called with br_ioctl_mutex. */
static int
old_deviceless(void __user *uarg)
{
	unsigned long args[3];

	if (copy_from_user(args, uarg, sizeof(args)))
		return -EFAULT;

	switch (args[0]) {
	case BRCTL_GET_BRIDGES:
		return brc_get_bridges((int __user *)args[1], args[2]);

	case BRCTL_ADD_BRIDGE:
		return brc_add_del_bridge((void __user *)args[1], 1);
	case BRCTL_DEL_BRIDGE:
		return brc_add_del_bridge((void __user *)args[1], 0);
	}

	return -EOPNOTSUPP;
}

/* Called with the br_ioctl_mutex. */
static int
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
brc_ioctl_deviceless_stub(unsigned int cmd, void __user *uarg)
#else
brc_ioctl_deviceless_stub(struct net *net, unsigned int cmd, void __user *uarg)
#endif
{
	switch (cmd) {
	case SIOCGIFBR:
	case SIOCSIFBR:
		return old_deviceless(uarg);

	case SIOCBRADDBR:
		return brc_add_del_bridge(uarg, 1);
	case SIOCBRDELBR:
		return brc_add_del_bridge(uarg, 0);
	}

	return -EOPNOTSUPP;
}

static int
brc_add_del_port(struct net_device *dev, int port_ifindex, int add)
{
	struct net_device *port;
	char dev_name[IFNAMSIZ], port_name[IFNAMSIZ];
	int err;

	port = __dev_get_by_index(&init_net, port_ifindex);
	if (!port)
		return -EINVAL;

	/* Save name of dev and port because there's a race between the
	 * rtnl_unlock() and the brc_send_command(). */
	strcpy(dev_name, dev->name);
	strcpy(port_name, port->name);

	rtnl_unlock();
	err = brc_send_command(dev_name, port_name,
			       add ? BRC_GENL_C_PORT_ADD : BRC_GENL_C_PORT_DEL);
	rtnl_lock();

	return err;
}

static int
brc_get_bridge_info(struct net_device *dev, struct __bridge_info __user *ub)
{
	struct __bridge_info b;
	u64 id = 0;
	int i;

	memset(&b, 0, sizeof(struct __bridge_info));

	for (i=0; i<ETH_ALEN; i++)
		id |= (u64)dev->dev_addr[i] << (8*(ETH_ALEN-1 - i));
	b.bridge_id = cpu_to_be64(id);
	b.stp_enabled = 0;

	if (copy_to_user(ub, &b, sizeof(struct __bridge_info)))
		return -EFAULT;

	return 0;
}

static int
brc_get_port_list(struct net_device *dev, int __user *uindices, int num)
{
	struct dp_dev *dp_dev = netdev_priv(dev);
	struct datapath *dp = dp_dev->dp;
	int *indices;

	if (num < 0)
		return -EINVAL;
	if (num == 0)
		num = 256;
	if (num > DP_MAX_PORTS)
		num = DP_MAX_PORTS;

	indices = kcalloc(num, sizeof(int), GFP_KERNEL);
	if (indices == NULL)
		return -ENOMEM;

	get_port_ifindices(dp, indices, num);
	if (copy_to_user(uindices, indices, num * sizeof(int)))
		num = -EFAULT;
	kfree(indices);
	return num;
}

/* Legacy ioctl's through SIOCDEVPRIVATE.  Called with rtnl_lock. */
static int
old_dev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
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
	}

	return -EOPNOTSUPP;
}

/* Called with the rtnl_lock. */
static int
brc_dev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
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
	NLA_PUT_U32(ans_skb, BRC_GENL_A_MC_GROUP, brc_mc_group.id);

	genlmsg_end(ans_skb, data);
	return genlmsg_reply(ans_skb, info);

err:
nla_put_failure:
	kfree_skb(ans_skb);
	return err;
}

static struct genl_ops brc_genl_ops_query_dp = {
	.cmd = BRC_GENL_C_QUERY_MC,
	.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privelege. */
	.policy = NULL,
	.doit = brc_genl_query,
	.dumpit = NULL
};

/* Attribute policy: what each attribute may contain.  */
static struct nla_policy brc_genl_policy[BRC_GENL_A_MAX + 1] = {
	[BRC_GENL_A_ERR_CODE] = { .type = NLA_U32 },
	[BRC_GENL_A_PROC_DIR] = { .type = NLA_NUL_STRING },
	[BRC_GENL_A_PROC_NAME] = { .type = NLA_NUL_STRING },
	[BRC_GENL_A_PROC_DATA] = { .type = NLA_NUL_STRING },
};

static int
brc_genl_dp_result(struct sk_buff *skb, struct genl_info *info)
{
	unsigned long int flags;
	int err;

	if (!info->attrs[BRC_GENL_A_ERR_CODE])
		return -EINVAL;

	spin_lock_irqsave(&brc_lock, flags);
	if (brc_seq == info->snd_seq) {
		brc_err = nla_get_u32(info->attrs[BRC_GENL_A_ERR_CODE]);
		complete(&brc_done);
		err = 0;
	} else {
		err = -ESTALE;
	}
	spin_unlock_irqrestore(&brc_lock, flags);

	return err;
}

static struct genl_ops brc_genl_ops_dp_result = {
	.cmd = BRC_GENL_C_DP_RESULT,
	.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privelege. */
	.policy = brc_genl_policy,
	.doit = brc_genl_dp_result,
	.dumpit = NULL
};

static struct genl_ops brc_genl_ops_set_proc = {
	.cmd = BRC_GENL_C_SET_PROC,
	.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privelege. */
	.policy = brc_genl_policy,
	.doit = brc_genl_set_proc,
	.dumpit = NULL
};

static int brc_send_command(const char *bridge, const char *port, int op)
{
	unsigned long int flags;
	struct sk_buff *skb;
	void *data;
	int error;

	mutex_lock(&brc_serial);

	/* Increment sequence number first, so that we ignore any replies
	 * to stale requests. */
	spin_lock_irqsave(&brc_lock, flags);
	brc_seq++;
	INIT_COMPLETION(brc_done);
	spin_unlock_irqrestore(&brc_lock, flags);

	/* Compose message. */
	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	error = -ENOMEM;
	if (skb == NULL)
		goto exit_unlock;
	data = genlmsg_put(skb, 0, brc_seq, &brc_genl_family, 0, op);

	NLA_PUT_STRING(skb, BRC_GENL_A_DP_NAME, bridge);
	if (port)
		NLA_PUT_STRING(skb, BRC_GENL_A_PORT_NAME, port);

	genlmsg_end(skb, data);

	/* Send message. */
	error = genlmsg_multicast(skb, 0, brc_mc_group.id, GFP_KERNEL);
	if (error < 0)
		goto exit_unlock;

	/* Wait for reply. */
	error = -ETIMEDOUT;
	if (!wait_for_completion_timeout(&brc_done, BRC_TIMEOUT))
		goto exit_unlock;

	error = -brc_err;
	goto exit_unlock;

nla_put_failure:
	kfree_skb(skb);
exit_unlock:
	mutex_unlock(&brc_serial);
	return error;
}

int brc_add_dp(struct datapath *dp)
{
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;
#ifdef SUPPORT_SYSFS
	brc_sysfs_add_dp(dp);
#endif

	return 0;
}

int brc_del_dp(struct datapath *dp) 
{
#ifdef SUPPORT_SYSFS
	brc_sysfs_del_dp(dp);
#endif
	module_put(THIS_MODULE);

	return 0;
}

static int 
__init brc_init(void)
{
	int i;
	int err;

	printk("Open vSwitch Bridge Compatibility, built "__DATE__" "__TIME__"\n");

	rcu_read_lock();
	for (i=0; i<ODP_MAX; i++) {
		if (get_dp(i)) {
			rcu_read_unlock();
			printk(KERN_EMERG "brcompat: no datapaths may exist!\n");
			return -EEXIST;
		}
	}
	rcu_read_unlock();

	/* Set the bridge ioctl handler */
	brioctl_set(brc_ioctl_deviceless_stub);

	/* Set the openvswitch_mod device ioctl handler */
	dp_ioctl_hook = brc_dev_ioctl;

	/* Register hooks for datapath adds and deletes */
	dp_add_dp_hook = brc_add_dp;
	dp_del_dp_hook = brc_del_dp;

	/* Register hooks for interface adds and deletes */
#ifdef SUPPORT_SYSFS
	dp_add_if_hook = brc_sysfs_add_if;
	dp_del_if_hook = brc_sysfs_del_if;
#endif

	/* Randomize the initial sequence number.  This is not a security
	 * feature; it only helps avoid crossed wires between userspace and
	 * the kernel when the module is unloaded and reloaded. */
	brc_seq = net_random();

	/* Register generic netlink family to communicate changes to
	 * userspace. */
	err = genl_register_family(&brc_genl_family);
	if (err)
		goto error;

	err = genl_register_ops(&brc_genl_family, &brc_genl_ops_query_dp);
	if (err != 0) 
		goto err_unregister;

	err = genl_register_ops(&brc_genl_family, &brc_genl_ops_dp_result);
	if (err != 0) 
		goto err_unregister;

	err = genl_register_ops(&brc_genl_family, &brc_genl_ops_set_proc);
	if (err != 0) 
		goto err_unregister;

	strcpy(brc_mc_group.name, "brcompat");
	err = genl_register_mc_group(&brc_genl_family, &brc_mc_group);
	if (err < 0)
		goto err_unregister;

	return 0;

err_unregister:
	genl_unregister_family(&brc_genl_family);
error:
	printk(KERN_EMERG "brcompat: failed to install!");
	return err;
}

static void 
brc_cleanup(void)
{
	/* Unregister hooks for datapath adds and deletes */
	dp_add_dp_hook = NULL;
	dp_del_dp_hook = NULL;
	
	/* Unregister hooks for interface adds and deletes */
	dp_add_if_hook = NULL;
	dp_del_if_hook = NULL;

	/* Unregister ioctl hooks */
	dp_ioctl_hook = NULL;
	brioctl_set(NULL);

	genl_unregister_family(&brc_genl_family);
	brc_procfs_exit();
}

module_init(brc_init);
module_exit(brc_cleanup);

MODULE_DESCRIPTION("Open vSwitch bridge compatibility");
MODULE_AUTHOR("Nicira Networks");
MODULE_LICENSE("GPL");
