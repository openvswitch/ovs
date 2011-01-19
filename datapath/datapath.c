/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2011 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

/* Functions for managing the dp interface/device. */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/wait.h>
#include <asm/system.h>
#include <asm/div64.h>
#include <asm/bug.h>
#include <linux/highmem.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/dmi.h>
#include <net/inet_ecn.h>
#include <net/genetlink.h>
#include <linux/compat.h>

#include "openvswitch/datapath-protocol.h"
#include "checksum.h"
#include "datapath.h"
#include "actions.h"
#include "flow.h"
#include "loop_counter.h"
#include "odp-compat.h"
#include "table.h"
#include "vport-internal_dev.h"

int (*dp_ioctl_hook)(struct net_device *dev, struct ifreq *rq, int cmd);
EXPORT_SYMBOL(dp_ioctl_hook);

/* Datapaths.  Protected on the read side by rcu_read_lock, on the write side
 * by dp_mutex.
 *
 * dp_mutex nests inside the RTNL lock: if you need both you must take the RTNL
 * lock first.
 *
 * It is safe to access the datapath and vport structures with just
 * dp_mutex.
 */
static struct datapath __rcu *dps[ODP_MAX];
static DEFINE_MUTEX(dp_mutex);

static struct vport *new_vport(const struct vport_parms *);

/* Must be called with rcu_read_lock or dp_mutex. */
struct datapath *get_dp(int dp_idx)
{
	if (dp_idx < 0 || dp_idx >= ODP_MAX)
		return NULL;
	return rcu_dereference_check(dps[dp_idx], rcu_read_lock_held() ||
					 lockdep_is_held(&dp_mutex));
}
EXPORT_SYMBOL_GPL(get_dp);

static struct datapath *get_dp_locked(int dp_idx)
{
	struct datapath *dp;

	mutex_lock(&dp_mutex);
	dp = get_dp(dp_idx);
	if (dp)
		mutex_lock(&dp->mutex);
	mutex_unlock(&dp_mutex);
	return dp;
}

static struct tbl *get_table_protected(struct datapath *dp)
{
	return rcu_dereference_protected(dp->table,
					 lockdep_is_held(&dp->mutex));
}

static struct vport *get_vport_protected(struct datapath *dp, u16 port_no)
{
	return rcu_dereference_protected(dp->ports[port_no],
					 lockdep_is_held(&dp->mutex));
}

/* Must be called with rcu_read_lock or RTNL lock. */
const char *dp_name(const struct datapath *dp)
{
	return vport_get_name(rcu_dereference_rtnl(dp->ports[ODPP_LOCAL]));
}

static inline size_t br_nlmsg_size(void)
{
	return NLMSG_ALIGN(sizeof(struct ifinfomsg))
	       + nla_total_size(IFNAMSIZ) /* IFLA_IFNAME */
	       + nla_total_size(MAX_ADDR_LEN) /* IFLA_ADDRESS */
	       + nla_total_size(4) /* IFLA_MASTER */
	       + nla_total_size(4) /* IFLA_MTU */
	       + nla_total_size(4) /* IFLA_LINK */
	       + nla_total_size(1); /* IFLA_OPERSTATE */
}

static int dp_fill_ifinfo(struct sk_buff *skb,
			  const struct vport *port,
			  int event, unsigned int flags)
{
	struct datapath *dp = port->dp;
	int ifindex = vport_get_ifindex(port);
	int iflink = vport_get_iflink(port);
	struct ifinfomsg *hdr;
	struct nlmsghdr *nlh;

	if (ifindex < 0)
		return ifindex;

	if (iflink < 0)
		return iflink;

	nlh = nlmsg_put(skb, 0, 0, event, sizeof(*hdr), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	hdr = nlmsg_data(nlh);
	hdr->ifi_family = AF_BRIDGE;
	hdr->__ifi_pad = 0;
	hdr->ifi_type = ARPHRD_ETHER;
	hdr->ifi_index = ifindex;
	hdr->ifi_flags = vport_get_flags(port);
	hdr->ifi_change = 0;

	NLA_PUT_STRING(skb, IFLA_IFNAME, vport_get_name(port));
	NLA_PUT_U32(skb, IFLA_MASTER,
		vport_get_ifindex(get_vport_protected(dp, ODPP_LOCAL)));
	NLA_PUT_U32(skb, IFLA_MTU, vport_get_mtu(port));
#ifdef IFLA_OPERSTATE
	NLA_PUT_U8(skb, IFLA_OPERSTATE,
		   vport_is_running(port)
			? vport_get_operstate(port)
			: IF_OPER_DOWN);
#endif

	NLA_PUT(skb, IFLA_ADDRESS, ETH_ALEN, vport_get_addr(port));

	if (ifindex != iflink)
		NLA_PUT_U32(skb, IFLA_LINK,iflink);

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static void dp_ifinfo_notify(int event, struct vport *port)
{
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(br_nlmsg_size(), GFP_KERNEL);
	if (skb == NULL)
		goto errout;

	err = dp_fill_ifinfo(skb, port, event, 0);
	if (err < 0) {
		/* -EMSGSIZE implies BUG in br_nlmsg_size() */
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}
	rtnl_notify(skb, &init_net, 0, RTNLGRP_LINK, NULL, GFP_KERNEL);
	return;
errout:
	if (err < 0)
		rtnl_set_sk_err(&init_net, RTNLGRP_LINK, err);
}

static void release_dp(struct kobject *kobj)
{
	struct datapath *dp = container_of(kobj, struct datapath, ifobj);
	kfree(dp);
}

static struct kobj_type dp_ktype = {
	.release = release_dp
};

static int create_dp(int dp_idx, const char __user *devnamep)
{
	struct vport_parms parms;
	char devname[IFNAMSIZ];
	struct vport *vport;
	struct datapath *dp;
	int err;
	int i;

	if (devnamep) {
		int retval = strncpy_from_user(devname, devnamep, IFNAMSIZ);
		if (retval < 0) {
			err = -EFAULT;
			goto err;
		} else if (retval >= IFNAMSIZ) {
			err = -ENAMETOOLONG;
			goto err;
		}
	} else {
		snprintf(devname, sizeof(devname), "of%d", dp_idx);
	}

	rtnl_lock();
	mutex_lock(&dp_mutex);
	err = -ENODEV;
	if (!try_module_get(THIS_MODULE))
		goto err_unlock;

	/* Exit early if a datapath with that number already exists.
	 * (We don't use -EEXIST because that's ambiguous with 'devname'
	 * conflicting with an existing network device name.) */
	err = -EBUSY;
	if (get_dp(dp_idx))
		goto err_put_module;

	err = -ENOMEM;
	dp = kzalloc(sizeof(*dp), GFP_KERNEL);
	if (dp == NULL)
		goto err_put_module;
	INIT_LIST_HEAD(&dp->port_list);
	mutex_init(&dp->mutex);
	mutex_lock(&dp->mutex);
	dp->dp_idx = dp_idx;
	for (i = 0; i < DP_N_QUEUES; i++)
		skb_queue_head_init(&dp->queues[i]);
	init_waitqueue_head(&dp->waitqueue);

	/* Initialize kobject for bridge.  This will be added as
	 * /sys/class/net/<devname>/brif later, if sysfs is enabled. */
	dp->ifobj.kset = NULL;
	kobject_init(&dp->ifobj, &dp_ktype);

	/* Allocate table. */
	err = -ENOMEM;
	rcu_assign_pointer(dp->table, tbl_create(TBL_MIN_BUCKETS));
	if (!dp->table)
		goto err_free_dp;

	/* Set up our datapath device. */
	parms.name = devname;
	parms.type = ODP_VPORT_TYPE_INTERNAL;
	parms.options = NULL;
	parms.dp = dp;
	parms.port_no = ODPP_LOCAL;
	vport = new_vport(&parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		if (err == -EBUSY)
			err = -EEXIST;

		goto err_destroy_table;
	}

	dp->drop_frags = 0;
	dp->stats_percpu = alloc_percpu(struct dp_stats_percpu);
	if (!dp->stats_percpu) {
		err = -ENOMEM;
		goto err_destroy_local_port;
	}

	rcu_assign_pointer(dps[dp_idx], dp);
	dp_sysfs_add_dp(dp);

	mutex_unlock(&dp->mutex);
	mutex_unlock(&dp_mutex);
	rtnl_unlock();

	return 0;

err_destroy_local_port:
	dp_detach_port(get_vport_protected(dp, ODPP_LOCAL));
err_destroy_table:
	tbl_destroy(get_table_protected(dp), NULL);
err_free_dp:
	mutex_unlock(&dp->mutex);
	kfree(dp);
err_put_module:
	module_put(THIS_MODULE);
err_unlock:
	mutex_unlock(&dp_mutex);
	rtnl_unlock();
err:
	return err;
}

static void destroy_dp_rcu(struct rcu_head *rcu)
{
	struct datapath *dp = container_of(rcu, struct datapath, rcu);
	int i;

	for (i = 0; i < DP_N_QUEUES; i++)
		skb_queue_purge(&dp->queues[i]);

	tbl_destroy((struct tbl __force *)dp->table, flow_free_tbl);
	free_percpu(dp->stats_percpu);
	kobject_put(&dp->ifobj);
}

static int destroy_dp(int dp_idx)
{
	struct datapath *dp;
	int err = 0;
	struct vport *p, *n;

	rtnl_lock();
	mutex_lock(&dp_mutex);
	dp = get_dp(dp_idx);
	if (!dp) {
		err = -ENODEV;
		goto out;
	}

	mutex_lock(&dp->mutex);

	list_for_each_entry_safe (p, n, &dp->port_list, node)
		if (p->port_no != ODPP_LOCAL)
			dp_detach_port(p);

	dp_sysfs_del_dp(dp);
	rcu_assign_pointer(dps[dp->dp_idx], NULL);
	dp_detach_port(get_vport_protected(dp, ODPP_LOCAL));

	mutex_unlock(&dp->mutex);
	call_rcu(&dp->rcu, destroy_dp_rcu);
	module_put(THIS_MODULE);

out:
	mutex_unlock(&dp_mutex);
	rtnl_unlock();
	return err;
}

/* Called with RTNL lock and dp->mutex. */
static struct vport *new_vport(const struct vport_parms *parms)
{
	struct vport *vport;

	vport_lock();
	vport = vport_add(parms);
	if (!IS_ERR(vport)) {
		struct datapath *dp = parms->dp;

		rcu_assign_pointer(dp->ports[parms->port_no], vport);
		list_add_rcu(&vport->node, &dp->port_list);

		dp_ifinfo_notify(RTM_NEWLINK, vport);
	}
	vport_unlock();

	return vport;
}

int dp_detach_port(struct vport *p)
{
	int err;

	ASSERT_RTNL();

	if (p->port_no != ODPP_LOCAL)
		dp_sysfs_del_if(p);
	dp_ifinfo_notify(RTM_DELLINK, p);

	/* First drop references to device. */
	list_del_rcu(&p->node);
	rcu_assign_pointer(p->dp->ports[p->port_no], NULL);

	/* Then destroy it. */
	vport_lock();
	err = vport_del(p);
	vport_unlock();

	return err;
}

/* Must be called with rcu_read_lock. */
void dp_process_received_packet(struct vport *p, struct sk_buff *skb)
{
	struct datapath *dp = p->dp;
	struct dp_stats_percpu *stats;
	int stats_counter_off;
	struct sw_flow_actions *acts;
	struct loop_counter *loop;
	int error;

	OVS_CB(skb)->vport = p;

	if (!OVS_CB(skb)->flow) {
		struct sw_flow_key key;
		struct tbl_node *flow_node;
		bool is_frag;

		/* Extract flow from 'skb' into 'key'. */
		error = flow_extract(skb, p ? p->port_no : ODPP_NONE, &key, &is_frag);
		if (unlikely(error)) {
			kfree_skb(skb);
			return;
		}

		if (is_frag && dp->drop_frags) {
			kfree_skb(skb);
			stats_counter_off = offsetof(struct dp_stats_percpu, n_frags);
			goto out;
		}

		/* Look up flow. */
		flow_node = tbl_lookup(rcu_dereference(dp->table), &key,
					flow_hash(&key), flow_cmp);
		if (unlikely(!flow_node)) {
			struct dp_upcall_info upcall;

			upcall.type = _ODPL_MISS_NR;
			upcall.key = &key;
			upcall.userdata = 0;
			upcall.sample_pool = 0;
			upcall.actions = NULL;
			upcall.actions_len = 0;
			dp_upcall(dp, skb, &upcall);
			stats_counter_off = offsetof(struct dp_stats_percpu, n_missed);
			goto out;
		}

		OVS_CB(skb)->flow = flow_cast(flow_node);
	}

	stats_counter_off = offsetof(struct dp_stats_percpu, n_hit);
	flow_used(OVS_CB(skb)->flow, skb);

	acts = rcu_dereference(OVS_CB(skb)->flow->sf_acts);

	/* Check whether we've looped too much. */
	loop = loop_get_counter();
	if (unlikely(++loop->count > MAX_LOOPS))
		loop->looping = true;
	if (unlikely(loop->looping)) {
		loop_suppress(dp, acts);
		kfree_skb(skb);
		goto out_loop;
	}

	/* Execute actions. */
	execute_actions(dp, skb, &OVS_CB(skb)->flow->key, acts->actions,
			acts->actions_len);

	/* Check whether sub-actions looped too much. */
	if (unlikely(loop->looping))
		loop_suppress(dp, acts);

out_loop:
	/* Decrement loop counter. */
	if (!--loop->count)
		loop->looping = false;
	loop_put_counter();

out:
	/* Update datapath statistics. */
	local_bh_disable();
	stats = per_cpu_ptr(dp->stats_percpu, smp_processor_id());

	write_seqcount_begin(&stats->seqlock);
	(*(u64 *)((u8 *)stats + stats_counter_off))++;
	write_seqcount_end(&stats->seqlock);

	local_bh_enable();
}

static void copy_and_csum_skb(struct sk_buff *skb, void *to)
{
	u16 csum_start, csum_offset;
	__wsum csum;

	get_skb_csum_pointers(skb, &csum_start, &csum_offset);
	csum_start -= skb_headroom(skb);
	BUG_ON(csum_start >= skb_headlen(skb));

	skb_copy_bits(skb, 0, to, csum_start);

	csum = skb_copy_and_csum_bits(skb, csum_start, to + csum_start,
				      skb->len - csum_start, 0);
	*(__sum16 *)(to + csum_start + csum_offset) = csum_fold(csum);
}

/* Append each packet in 'skb' list to 'queue'.  There will be only one packet
 * unless we broke up a GSO packet. */
static int queue_control_packets(struct datapath *dp, struct sk_buff *skb,
				 const struct dp_upcall_info *upcall_info)
{
	struct sk_buff *nskb;
	int port_no;
	int err;

	if (OVS_CB(skb)->vport)
		port_no = OVS_CB(skb)->vport->port_no;
	else
		port_no = ODPP_LOCAL;

	do {
		struct odp_packet *upcall;
		struct sk_buff *user_skb; /* to be queued to userspace */
		struct nlattr *nla;
		unsigned int len;

		nskb = skb->next;
		skb->next = NULL;

		len = sizeof(struct odp_packet);
		len += nla_total_size(4); /* ODP_PACKET_ATTR_TYPE. */
		len += nla_total_size(skb->len);
		len += nla_total_size(FLOW_BUFSIZE);
		if (upcall_info->userdata)
			len += nla_total_size(8);
		if (upcall_info->sample_pool)
			len += nla_total_size(4);
		if (upcall_info->actions_len)
			len += nla_total_size(upcall_info->actions_len);

		user_skb = alloc_skb(len, GFP_ATOMIC);
		if (!user_skb)
			goto err_kfree_skbs;

		upcall = (struct odp_packet *)__skb_put(user_skb, sizeof(*upcall));
		upcall->dp_idx = dp->dp_idx;

		nla_put_u32(user_skb, ODP_PACKET_ATTR_TYPE, upcall_info->type);

		nla = nla_nest_start(user_skb, ODP_PACKET_ATTR_KEY);
		flow_to_nlattrs(upcall_info->key, user_skb);
		nla_nest_end(user_skb, nla);

		if (upcall_info->userdata)
			nla_put_u64(user_skb, ODP_PACKET_ATTR_USERDATA, upcall_info->userdata);
		if (upcall_info->sample_pool)
			nla_put_u32(user_skb, ODP_PACKET_ATTR_SAMPLE_POOL, upcall_info->sample_pool);
		if (upcall_info->actions_len) {
			const struct nlattr *actions = upcall_info->actions;
			u32 actions_len = upcall_info->actions_len;

			nla = nla_nest_start(user_skb, ODP_PACKET_ATTR_ACTIONS);
			memcpy(__skb_put(user_skb, actions_len), actions, actions_len);
			nla_nest_end(user_skb, nla);
		}

		nla = __nla_reserve(user_skb, ODP_PACKET_ATTR_PACKET, skb->len);
		if (skb->ip_summed == CHECKSUM_PARTIAL)
			copy_and_csum_skb(skb, nla_data(nla));
		else
			skb_copy_bits(skb, 0, nla_data(nla), skb->len);

		upcall->len = user_skb->len;
		skb_queue_tail(&dp->queues[upcall_info->type], user_skb);

		kfree_skb(skb);
		skb = nskb;
	} while (skb);
	return 0;

err_kfree_skbs:
	kfree_skb(skb);
	while ((skb = nskb) != NULL) {
		nskb = skb->next;
		kfree_skb(skb);
	}
	return err;
}

int dp_upcall(struct datapath *dp, struct sk_buff *skb, const struct dp_upcall_info *upcall_info)
{
	struct dp_stats_percpu *stats;
	struct sk_buff_head *queue;
	int err;

	WARN_ON_ONCE(skb_shared(skb));
	BUG_ON(upcall_info->type >= DP_N_QUEUES);

	queue = &dp->queues[upcall_info->type];
	err = -ENOBUFS;
	if (skb_queue_len(queue) >= DP_MAX_QUEUE_LEN)
		goto err_kfree_skb;

	forward_ip_summed(skb);

	err = vswitch_skb_checksum_setup(skb);
	if (err)
		goto err_kfree_skb;

	/* Break apart GSO packets into their component pieces.  Otherwise
	 * userspace may try to stuff a 64kB packet into a 1500-byte MTU. */
	if (skb_is_gso(skb)) {
		struct sk_buff *nskb = skb_gso_segment(skb, NETIF_F_SG | NETIF_F_HW_CSUM);
		
		kfree_skb(skb);
		skb = nskb;
		if (IS_ERR(skb)) {
			err = PTR_ERR(skb);
			goto err;
		}
	}

	err = queue_control_packets(dp, skb, upcall_info);
	wake_up_interruptible(&dp->waitqueue);
	return err;

err_kfree_skb:
	kfree_skb(skb);
err:
	local_bh_disable();
	stats = per_cpu_ptr(dp->stats_percpu, smp_processor_id());

	write_seqcount_begin(&stats->seqlock);
	stats->n_lost++;
	write_seqcount_end(&stats->seqlock);

	local_bh_enable();

	return err;
}

static int flush_flows(int dp_idx)
{
	struct tbl *old_table;
	struct tbl *new_table;
	struct datapath *dp;
	int err;

	dp = get_dp_locked(dp_idx);
	err = -ENODEV;
	if (!dp)
		goto exit;

	old_table = get_table_protected(dp);
	new_table = tbl_create(TBL_MIN_BUCKETS);
	err = -ENOMEM;
	if (!new_table)
		goto exit_unlock;

	rcu_assign_pointer(dp->table, new_table);

	tbl_deferred_destroy(old_table, flow_free_tbl);

	err = 0;

exit_unlock:
	mutex_unlock(&dp->mutex);
exit:
	return err;
}

static int validate_actions(const struct nlattr *actions, u32 actions_len)
{
	const struct nlattr *a;
	int rem;

	nla_for_each_attr(a, actions, actions_len, rem) {
		static const u32 action_lens[ODPAT_MAX + 1] = {
			[ODPAT_OUTPUT] = 4,
			[ODPAT_CONTROLLER] = 8,
			[ODPAT_SET_DL_TCI] = 2,
			[ODPAT_STRIP_VLAN] = 0,
			[ODPAT_SET_DL_SRC] = ETH_ALEN,
			[ODPAT_SET_DL_DST] = ETH_ALEN,
			[ODPAT_SET_NW_SRC] = 4,
			[ODPAT_SET_NW_DST] = 4,
			[ODPAT_SET_NW_TOS] = 1,
			[ODPAT_SET_TP_SRC] = 2,
			[ODPAT_SET_TP_DST] = 2,
			[ODPAT_SET_TUNNEL] = 8,
			[ODPAT_SET_PRIORITY] = 4,
			[ODPAT_POP_PRIORITY] = 0,
			[ODPAT_DROP_SPOOFED_ARP] = 0,
		};
		int type = nla_type(a);

		if (type > ODPAT_MAX || nla_len(a) != action_lens[type])
			return -EINVAL;

		switch (type) {
		case ODPAT_UNSPEC:
			return -EINVAL;

		case ODPAT_CONTROLLER:
		case ODPAT_STRIP_VLAN:
		case ODPAT_SET_DL_SRC:
		case ODPAT_SET_DL_DST:
		case ODPAT_SET_NW_SRC:
		case ODPAT_SET_NW_DST:
		case ODPAT_SET_TP_SRC:
		case ODPAT_SET_TP_DST:
		case ODPAT_SET_TUNNEL:
		case ODPAT_SET_PRIORITY:
		case ODPAT_POP_PRIORITY:
		case ODPAT_DROP_SPOOFED_ARP:
			/* No validation needed. */
			break;

		case ODPAT_OUTPUT:
			if (nla_get_u32(a) >= DP_MAX_PORTS)
				return -EINVAL;
			break;

		case ODPAT_SET_DL_TCI:
			if (nla_get_be16(a) & htons(VLAN_CFI_MASK))
				return -EINVAL;
			break;

		case ODPAT_SET_NW_TOS:
			if (nla_get_u8(a) & INET_ECN_MASK)
				return -EINVAL;
			break;

		default:
			return -EOPNOTSUPP;
		}
	}

	if (rem > 0)
		return -EINVAL;

	return 0;
}

static struct sw_flow_actions *get_actions(const struct odp_flow *flow)
{
	struct sw_flow_actions *actions;
	int error;

	actions = flow_actions_alloc(flow->actions_len);
	error = PTR_ERR(actions);
	if (IS_ERR(actions))
		goto error;

	error = -EFAULT;
	if (copy_from_user(actions->actions,
			   (struct nlattr __user __force *)flow->actions,
			   flow->actions_len))
		goto error_free_actions;
	error = validate_actions(actions->actions, actions->actions_len);
	if (error)
		goto error_free_actions;

	return actions;

error_free_actions:
	kfree(actions);
error:
	return ERR_PTR(error);
}

static void get_stats(struct sw_flow *flow, struct odp_flow_stats *stats)
{
	if (flow->used) {
		struct timespec offset_ts, used, now_mono;

		ktime_get_ts(&now_mono);
		jiffies_to_timespec(jiffies - flow->used, &offset_ts);
		set_normalized_timespec(&used, now_mono.tv_sec - offset_ts.tv_sec,
					now_mono.tv_nsec - offset_ts.tv_nsec);

		stats->used_sec = used.tv_sec;
		stats->used_nsec = used.tv_nsec;
	} else {
		stats->used_sec = 0;
		stats->used_nsec = 0;
	}

	stats->n_packets = flow->packet_count;
	stats->n_bytes = flow->byte_count;
	stats->reserved = 0;
	stats->tcp_flags = flow->tcp_flags;
}

static void clear_stats(struct sw_flow *flow)
{
	flow->used = 0;
	flow->tcp_flags = 0;
	flow->packet_count = 0;
	flow->byte_count = 0;
}

static int expand_table(struct datapath *dp)
{
	struct tbl *old_table = get_table_protected(dp);
	struct tbl *new_table;

	new_table = tbl_expand(old_table);
	if (IS_ERR(new_table))
		return PTR_ERR(new_table);

	rcu_assign_pointer(dp->table, new_table);
	tbl_deferred_destroy(old_table, NULL);

	return 0;
}

static int do_put_flow(struct datapath *dp, struct odp_flow_put *uf,
		       struct odp_flow_stats *stats)
{
	struct tbl_node *flow_node;
	struct sw_flow_key key;
	struct sw_flow *flow;
	struct tbl *table;
	struct sw_flow_actions *acts = NULL;
	int error;
	u32 hash;

	error = flow_copy_from_user(&key, (const struct nlattr __force __user *)uf->flow.key,
				    uf->flow.key_len);
	if (error)
		return error;

	hash = flow_hash(&key);
	table = get_table_protected(dp);
	flow_node = tbl_lookup(table, &key, hash, flow_cmp);
	if (!flow_node) {
		/* No such flow. */
		error = -ENOENT;
		if (!(uf->flags & ODPPF_CREATE))
			goto error;

		/* Expand table, if necessary, to make room. */
		if (tbl_count(table) >= tbl_n_buckets(table)) {
			error = expand_table(dp);
			if (error)
				goto error;
			table = get_table_protected(dp);
		}

		/* Allocate flow. */
		flow = flow_alloc();
		if (IS_ERR(flow)) {
			error = PTR_ERR(flow);
			goto error;
		}
		flow->key = key;
		clear_stats(flow);

		/* Obtain actions. */
		acts = get_actions(&uf->flow);
		error = PTR_ERR(acts);
		if (IS_ERR(acts))
			goto error_free_flow;
		rcu_assign_pointer(flow->sf_acts, acts);

		/* Put flow in bucket. */
		error = tbl_insert(table, &flow->tbl_node, hash);
		if (error)
			goto error_free_flow_acts;

		memset(stats, 0, sizeof(struct odp_flow_stats));
	} else {
		/* We found a matching flow. */
		struct sw_flow_actions *old_acts, *new_acts;

		flow = flow_cast(flow_node);

		/* Bail out if we're not allowed to modify an existing flow. */
		error = -EEXIST;
		if (!(uf->flags & ODPPF_MODIFY))
			goto error;

		/* Swap actions. */
		new_acts = get_actions(&uf->flow);
		error = PTR_ERR(new_acts);
		if (IS_ERR(new_acts))
			goto error;

		old_acts = rcu_dereference_protected(flow->sf_acts,
						     lockdep_is_held(&dp->mutex));
		if (old_acts->actions_len != new_acts->actions_len ||
		    memcmp(old_acts->actions, new_acts->actions,
			   old_acts->actions_len)) {
			rcu_assign_pointer(flow->sf_acts, new_acts);
			flow_deferred_free_acts(old_acts);
		} else {
			kfree(new_acts);
		}

		/* Fetch stats, then clear them if necessary. */
		spin_lock_bh(&flow->lock);
		get_stats(flow, stats);
		if (uf->flags & ODPPF_ZERO_STATS)
			clear_stats(flow);
		spin_unlock_bh(&flow->lock);
	}

	return 0;

error_free_flow_acts:
	kfree(acts);
error_free_flow:
	flow->sf_acts = NULL;
	flow_put(flow);
error:
	return error;
}

static int put_flow(struct odp_flow_put __user *ufp)
{
	struct odp_flow_stats stats;
	struct odp_flow_put uf;
	struct datapath *dp;
	int error;

	if (copy_from_user(&uf, ufp, sizeof(struct odp_flow_put)))
		return -EFAULT;

	dp = get_dp_locked(uf.flow.dp_idx);
	if (!dp)
		return -ENODEV;

	error = do_put_flow(dp, &uf, &stats);
	if (!error) {
		if (copy_to_user(&ufp->flow.stats, &stats,
				 sizeof(struct odp_flow_stats)))
			error = -EFAULT;
	}
	mutex_unlock(&dp->mutex);

	return error;
}

static int do_answer_query(struct datapath *dp, struct sw_flow *flow,
			   struct odp_flow_stats __user *ustats,
			   struct nlattr __user *actions,
			   u32 __user *actions_lenp)
{
	struct sw_flow_actions *sf_acts;
	struct odp_flow_stats stats;
	u32 actions_len;

	spin_lock_bh(&flow->lock);
	get_stats(flow, &stats);
	spin_unlock_bh(&flow->lock);

	if (copy_to_user(ustats, &stats, sizeof(struct odp_flow_stats)) ||
	    get_user(actions_len, actions_lenp))
		return -EFAULT;

	if (!actions_len)
		return 0;

	sf_acts = rcu_dereference_protected(flow->sf_acts,
					    lockdep_is_held(&dp->mutex));
	if (put_user(sf_acts->actions_len, actions_lenp) ||
	    (actions && copy_to_user(actions, sf_acts->actions,
				     min(sf_acts->actions_len, actions_len))))
		return -EFAULT;

	return 0;
}

static int answer_query(struct datapath *dp, struct sw_flow *flow,
			struct odp_flow __user *ufp)
{
	struct nlattr __user *actions;

	if (get_user(actions, (struct nlattr __user * __user *)&ufp->actions))
		return -EFAULT;

	return do_answer_query(dp, flow, &ufp->stats, actions, &ufp->actions_len);
}

static struct sw_flow *do_del_flow(struct datapath *dp, const struct nlattr __user *key, u32 key_len)
{
	struct tbl *table = get_table_protected(dp);
	struct tbl_node *flow_node;
	struct sw_flow_key swkey;
	int error;

	error = flow_copy_from_user(&swkey, key, key_len);
	if (error)
		return ERR_PTR(error);

	flow_node = tbl_lookup(table, &swkey, flow_hash(&swkey), flow_cmp);
	if (!flow_node)
		return ERR_PTR(-ENOENT);

	error = tbl_remove(table, flow_node);
	if (error)
		return ERR_PTR(error);

	/* XXX Returned flow_node's statistics might lose a few packets, since
	 * other CPUs can be using this flow.  We used to synchronize_rcu() to
	 * make sure that we get completely accurate stats, but that blows our
	 * performance, badly. */
	return flow_cast(flow_node);
}

static int del_flow(struct odp_flow __user *ufp)
{
	struct sw_flow *flow;
	struct datapath *dp;
	struct odp_flow uf;
	int error;

	if (copy_from_user(&uf, ufp, sizeof(uf)))
		return -EFAULT;

	dp = get_dp_locked(uf.dp_idx);
	if (!dp)
		return -ENODEV;

	flow = do_del_flow(dp, (const struct nlattr __force __user *)uf.key, uf.key_len);
	error = PTR_ERR(flow);
	if (!IS_ERR(flow)) {
		error = answer_query(dp, flow, ufp);
		flow_deferred_free(flow);
	}
	mutex_unlock(&dp->mutex);

	return error;
}

static int query_flow(struct odp_flow __user *uflow)
{
	struct tbl_node *flow_node;
	struct sw_flow_key key;
	struct odp_flow flow;
	struct datapath *dp;
	int error;

	if (copy_from_user(&flow, uflow, sizeof(flow)))
		return -EFAULT;

	dp = get_dp_locked(flow.dp_idx);
	if (!dp)
		return -ENODEV;

	error = flow_copy_from_user(&key, (const struct nlattr __force __user *)flow.key, flow.key_len);
	if (!error) {
		struct tbl *table = get_table_protected(dp);
		flow_node = tbl_lookup(table, &flow.key, flow_hash(&key), flow_cmp);
		if (flow_node)
			error = answer_query(dp, flow_cast(flow_node), uflow);
		else
			error = -ENOENT;
	}
	mutex_unlock(&dp->mutex);

	return error;
}

static int dump_flow(struct odp_flow_dump __user *udump)
{
	struct odp_flow __user *uflow;
	struct nlattr __user *ukey;
	struct tbl_node *tbl_node;
	struct odp_flow_dump dump;
	struct sw_flow *flow;
	struct datapath *dp;
	struct tbl *table;
	u32 key_len;
	int err;

	err = -EFAULT;
	if (copy_from_user(&dump, udump, sizeof(struct odp_flow_dump)))
		goto exit;
	uflow = (struct odp_flow __user __force *)dump.flow;

	dp = get_dp_locked(dump.dp_idx);
	err = -ENODEV;
	if (!dp)
		goto exit;

	table = get_table_protected(dp);
	tbl_node = tbl_next(table, &dump.state[0], &dump.state[1]);
	if (!tbl_node) {
		err = put_user(0, &uflow->key_len);
		goto exit_unlock;
	}
	flow = flow_cast(tbl_node);

	err = -EFAULT;
	if (copy_to_user(udump->state, dump.state, 2 * sizeof(uint32_t)) ||
	    get_user(ukey, (struct nlattr __user * __user*)&uflow->key) ||
	    get_user(key_len, &uflow->key_len))
		goto exit_unlock;

	key_len = flow_copy_to_user(ukey, &flow->key, key_len);
	err = key_len;
	if (key_len < 0)
		goto exit_unlock;
	err = -EFAULT;
	if (put_user(key_len, &uflow->key_len))
		goto exit_unlock;

	err = answer_query(dp, flow, uflow);

exit_unlock:
	mutex_unlock(&dp->mutex);
exit:
	return err;
}

static int do_execute(struct datapath *dp, const struct odp_execute *execute)
{
	struct sw_flow_key key;
	struct sk_buff *skb;
	struct sw_flow_actions *actions;
	struct ethhdr *eth;
	bool is_frag;
	int err;

	err = -EINVAL;
	if (execute->length < ETH_HLEN || execute->length > 65535)
		goto error;

	actions = flow_actions_alloc(execute->actions_len);
	if (IS_ERR(actions)) {
		err = PTR_ERR(actions);
		goto error;
	}

	err = -EFAULT;
	if (copy_from_user(actions->actions,
	    (struct nlattr __user __force *)execute->actions, execute->actions_len))
		goto error_free_actions;

	err = validate_actions(actions->actions, execute->actions_len);
	if (err)
		goto error_free_actions;

	err = -ENOMEM;
	skb = alloc_skb(execute->length, GFP_KERNEL);
	if (!skb)
		goto error_free_actions;

	err = -EFAULT;
	if (copy_from_user(skb_put(skb, execute->length),
			   (const void __user __force *)execute->data,
			   execute->length))
		goto error_free_skb;

	skb_reset_mac_header(skb);
	eth = eth_hdr(skb);

	/* Normally, setting the skb 'protocol' field would be handled by a
	 * call to eth_type_trans(), but it assumes there's a sending
	 * device, which we may not have. */
	if (ntohs(eth->h_proto) >= 1536)
		skb->protocol = eth->h_proto;
	else
		skb->protocol = htons(ETH_P_802_2);

	err = flow_extract(skb, -1, &key, &is_frag);
	if (err)
		goto error_free_skb;

	rcu_read_lock();
	err = execute_actions(dp, skb, &key, actions->actions, actions->actions_len);
	rcu_read_unlock();

	kfree(actions);
	return err;

error_free_skb:
	kfree_skb(skb);
error_free_actions:
	kfree(actions);
error:
	return err;
}

static int execute_packet(const struct odp_execute __user *executep)
{
	struct odp_execute execute;
	struct datapath *dp;
	int error;

	if (copy_from_user(&execute, executep, sizeof(execute)))
		return -EFAULT;

	dp = get_dp_locked(execute.dp_idx);
	if (!dp)
		return -ENODEV;
	error = do_execute(dp, &execute);
	mutex_unlock(&dp->mutex);

	return error;
}

static int get_dp_stats(struct datapath *dp, struct odp_stats __user *statsp)
{
	struct odp_stats stats;
	int i;

	stats.n_frags = stats.n_hit = stats.n_missed = stats.n_lost = 0;
	for_each_possible_cpu(i) {
		const struct dp_stats_percpu *percpu_stats;
		struct dp_stats_percpu local_stats;
		unsigned seqcount;

		percpu_stats = per_cpu_ptr(dp->stats_percpu, i);

		do {
			seqcount = read_seqcount_begin(&percpu_stats->seqlock);
			local_stats = *percpu_stats;
		} while (read_seqcount_retry(&percpu_stats->seqlock, seqcount));

		stats.n_frags += local_stats.n_frags;
		stats.n_hit += local_stats.n_hit;
		stats.n_missed += local_stats.n_missed;
		stats.n_lost += local_stats.n_lost;
	}
	return copy_to_user(statsp, &stats, sizeof(stats)) ? -EFAULT : 0;
}

/* MTU of the dp pseudo-device: ETH_DATA_LEN or the minimum of the ports */
int dp_min_mtu(const struct datapath *dp)
{
	struct vport *p;
	int mtu = 0;

	ASSERT_RTNL();

	list_for_each_entry_rcu (p, &dp->port_list, node) {
		int dev_mtu;

		/* Skip any internal ports, since that's what we're trying to
		 * set. */
		if (is_internal_vport(p))
			continue;

		dev_mtu = vport_get_mtu(p);
		if (!mtu || dev_mtu < mtu)
			mtu = dev_mtu;
	}

	return mtu ? mtu : ETH_DATA_LEN;
}

/* Sets the MTU of all datapath devices to the minimum of the ports.  Must
 * be called with RTNL lock. */
void set_internal_devs_mtu(const struct datapath *dp)
{
	struct vport *p;
	int mtu;

	ASSERT_RTNL();

	mtu = dp_min_mtu(dp);

	list_for_each_entry_rcu (p, &dp->port_list, node) {
		if (is_internal_vport(p))
			vport_set_mtu(p, mtu);
	}
}

static int get_listen_mask(const struct file *f)
{
	return (long)f->private_data;
}

static void set_listen_mask(struct file *f, int listen_mask)
{
	f->private_data = (void*)(long)listen_mask;
}

static const struct nla_policy vport_policy[ODP_VPORT_ATTR_MAX + 1] = {
	[ODP_VPORT_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[ODP_VPORT_ATTR_PORT_NO] = { .type = NLA_U32 },
	[ODP_VPORT_ATTR_TYPE] = { .type = NLA_U32 },
	[ODP_VPORT_ATTR_STATS] = { .len = sizeof(struct rtnl_link_stats64) },
	[ODP_VPORT_ATTR_ADDRESS] = { .len = ETH_ALEN },
	[ODP_VPORT_ATTR_MTU] = { .type = NLA_U32 },
	[ODP_VPORT_ATTR_OPTIONS] = { .type = NLA_NESTED },
};

static int copy_vport_to_user(void __user *dst, struct vport *vport, uint32_t total_len)
{
	struct odp_vport *odp_vport;
	struct sk_buff *skb;
	struct nlattr *nla;
	int ifindex, iflink;
	int err;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	err = -ENOMEM;
	if (!skb)
		goto exit;

	rcu_read_lock();
	odp_vport = (struct odp_vport*)__skb_put(skb, sizeof(struct odp_vport));
	odp_vport->dp_idx = vport->dp->dp_idx;
	odp_vport->total_len = total_len;

	NLA_PUT_U32(skb, ODP_VPORT_ATTR_PORT_NO, vport->port_no);
	NLA_PUT_U32(skb, ODP_VPORT_ATTR_TYPE, vport_get_type(vport));
	NLA_PUT_STRING(skb, ODP_VPORT_ATTR_NAME, vport_get_name(vport));

	nla = nla_reserve(skb, ODP_VPORT_ATTR_STATS, sizeof(struct rtnl_link_stats64));
	if (!nla)
		goto nla_put_failure;
	if (vport_get_stats(vport, nla_data(nla)))
		__skb_trim(skb, skb->len - nla->nla_len);

	NLA_PUT(skb, ODP_VPORT_ATTR_ADDRESS, ETH_ALEN, vport_get_addr(vport));

	NLA_PUT_U32(skb, ODP_VPORT_ATTR_MTU, vport_get_mtu(vport));

	err = vport_get_options(vport, skb);

	ifindex = vport_get_ifindex(vport);
	if (ifindex > 0)
		NLA_PUT_U32(skb, ODP_VPORT_ATTR_IFINDEX, ifindex);

	iflink = vport_get_iflink(vport);
	if (iflink > 0)
		NLA_PUT_U32(skb, ODP_VPORT_ATTR_IFLINK, iflink);

	err = -EMSGSIZE;
	if (skb->len > total_len)
		goto exit_unlock;

	odp_vport->len = skb->len;
	err = copy_to_user(dst, skb->data, skb->len) ? -EFAULT : 0;
	goto exit_unlock;

nla_put_failure:
	err = -EMSGSIZE;
exit_unlock:
	rcu_read_unlock();
	kfree_skb(skb);
exit:
	return err;
}

static struct sk_buff *copy_vport_from_user(struct odp_vport __user *uodp_vport,
					    struct nlattr *a[ODP_VPORT_ATTR_MAX + 1])
{
	struct odp_vport *odp_vport;
	struct sk_buff *skb;
	u32 len;
	int err;

	if (get_user(len, &uodp_vport->len))
		return ERR_PTR(-EFAULT);
	if (len < sizeof(struct odp_vport))
		return ERR_PTR(-EINVAL);

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	err = -EFAULT;
	if (copy_from_user(__skb_put(skb, len), uodp_vport, len))
		goto error_free_skb;

	odp_vport = (struct odp_vport *)skb->data;
	err = -EINVAL;
	if (odp_vport->len != len)
		goto error_free_skb;

	err = nla_parse(a, ODP_VPORT_ATTR_MAX, (struct nlattr *)(skb->data + sizeof(struct odp_vport)),
			skb->len - sizeof(struct odp_vport), vport_policy);
	if (err)
		goto error_free_skb;

	err = VERIFY_NUL_STRING(a[ODP_VPORT_ATTR_NAME], IFNAMSIZ - 1);
	if (err)
		goto error_free_skb;

	return skb;

error_free_skb:
	kfree_skb(skb);
	return ERR_PTR(err);
}


/* Called without any locks (or with RTNL lock).
 * Returns holding vport->dp->mutex.
 */
static struct vport *lookup_vport(struct odp_vport *odp_vport,
				  struct nlattr *a[ODP_VPORT_ATTR_MAX + 1])
{
	struct datapath *dp;
	struct vport *vport;

	if (a[ODP_VPORT_ATTR_NAME]) {
		int dp_idx, port_no;

	retry:
		vport_lock();
		vport = vport_locate(nla_data(a[ODP_VPORT_ATTR_NAME]));
		if (!vport) {
			vport_unlock();
			return ERR_PTR(-ENODEV);
		}
		dp_idx = vport->dp->dp_idx;
		port_no = vport->port_no;
		vport_unlock();

		dp = get_dp_locked(dp_idx);
		if (!dp)
			goto retry;

		vport = get_vport_protected(dp, port_no);
		if (!vport ||
		    strcmp(vport_get_name(vport), nla_data(a[ODP_VPORT_ATTR_NAME]))) {
			mutex_unlock(&dp->mutex);
			goto retry;
		}

		return vport;
	} else if (a[ODP_VPORT_ATTR_PORT_NO]) {
		u32 port_no = nla_get_u32(a[ODP_VPORT_ATTR_PORT_NO]);

		if (port_no >= DP_MAX_PORTS)
			return ERR_PTR(-EINVAL);

		dp = get_dp_locked(odp_vport->dp_idx);
		if (!dp)
			return ERR_PTR(-ENODEV);

		vport = get_vport_protected(dp, port_no);
		if (!vport) {
			mutex_unlock(&dp->mutex);
			return ERR_PTR(-ENOENT);
		}
		return vport;
	} else
		return ERR_PTR(-EINVAL);
}

static int change_vport(struct vport *vport, struct nlattr *a[ODP_VPORT_ATTR_MAX + 1])
{
	int err = 0;
	if (a[ODP_VPORT_ATTR_STATS])
		err = vport_set_stats(vport, nla_data(a[ODP_VPORT_ATTR_STATS]));
	if (!err && a[ODP_VPORT_ATTR_ADDRESS])
		err = vport_set_addr(vport, nla_data(a[ODP_VPORT_ATTR_ADDRESS]));
	if (!err && a[ODP_VPORT_ATTR_MTU])
		err = vport_set_mtu(vport, nla_get_u32(a[ODP_VPORT_ATTR_MTU]));
	return err;
}

static int attach_vport(struct odp_vport __user *uodp_vport)
{
	struct nlattr *a[ODP_VPORT_ATTR_MAX + 1];
	struct odp_vport *odp_vport;
	struct vport_parms parms;
	struct vport *vport;
	struct sk_buff *skb;
	struct datapath *dp;
	u32 port_no;
	int err;

	skb = copy_vport_from_user(uodp_vport, a);
	err = PTR_ERR(skb);
	if (IS_ERR(skb))
		goto exit;
	odp_vport = (struct odp_vport *)skb->data;

	err = -EINVAL;
	if (!a[ODP_VPORT_ATTR_NAME] || !a[ODP_VPORT_ATTR_TYPE])
		goto exit_kfree_skb;

	rtnl_lock();

	dp = get_dp_locked(odp_vport->dp_idx);
	err = -ENODEV;
	if (!dp)
		goto exit_unlock_rtnl;

	if (a[ODP_VPORT_ATTR_PORT_NO]) {
		port_no = nla_get_u32(a[ODP_VPORT_ATTR_PORT_NO]);

		err = -EFBIG;
		if (port_no >= DP_MAX_PORTS)
			goto exit_unlock_dp;

		vport = get_vport_protected(dp, port_no);
		err = -EBUSY;
		if (vport)
			goto exit_unlock_dp;
	} else {
		for (port_no = 1; ; port_no++) {
			if (port_no >= DP_MAX_PORTS) {
				err = -EFBIG;
				goto exit_unlock_dp;
			}
			vport = get_vport_protected(dp, port_no);
			if (!vport)
				break;
		}
	}

	parms.name = nla_data(a[ODP_VPORT_ATTR_NAME]);
	parms.type = nla_get_u32(a[ODP_VPORT_ATTR_TYPE]);
	parms.options = a[ODP_VPORT_ATTR_OPTIONS];
	parms.dp = dp;
	parms.port_no = port_no;

	vport = new_vport(&parms);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock_dp;

 	set_internal_devs_mtu(dp);
 	dp_sysfs_add_if(vport);

	err = change_vport(vport, a);
	if (err) {
		dp_detach_port(vport);
		goto exit_unlock_dp;
	}

	err = copy_vport_to_user(uodp_vport, vport, odp_vport->total_len);

exit_unlock_dp:
	mutex_unlock(&dp->mutex);
exit_unlock_rtnl:
	rtnl_unlock();
exit_kfree_skb:
	kfree_skb(skb);
exit:
	return err;
}

static int set_vport(unsigned int cmd, struct odp_vport __user *uodp_vport)
{
	struct nlattr *a[ODP_VPORT_ATTR_MAX + 1];
	struct vport *vport;
	struct sk_buff *skb;
	int err;

	skb = copy_vport_from_user(uodp_vport, a);
	err = PTR_ERR(skb);
	if (IS_ERR(skb))
		goto exit;

	rtnl_lock();
	vport = lookup_vport((struct odp_vport *)skb->data, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_free;

	err = 0;
	if (a[ODP_VPORT_ATTR_OPTIONS])
		err = vport_set_options(vport, a[ODP_VPORT_ATTR_OPTIONS]);
	if (!err)
		err = change_vport(vport, a);

	mutex_unlock(&vport->dp->mutex);
exit_free:
	kfree_skb(skb);
	rtnl_unlock();
exit:
	return err;
}

static int del_vport(unsigned int cmd, struct odp_vport __user *uodp_vport)
{
	struct nlattr *a[ODP_VPORT_ATTR_MAX + 1];
	struct datapath *dp;
	struct vport *vport;
	struct sk_buff *skb;
	int err;

	skb = copy_vport_from_user(uodp_vport, a);
	err = PTR_ERR(skb);
	if (IS_ERR(skb))
		goto exit;

	rtnl_lock();
	vport = lookup_vport((struct odp_vport *)skb->data, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_free;
	dp = vport->dp;

	err = -EINVAL;
	if (vport->port_no == ODPP_LOCAL)
		goto exit_free;

	err = dp_detach_port(vport);
	mutex_unlock(&dp->mutex);
exit_free:
	kfree_skb(skb);
	rtnl_unlock();
exit:
	return err;
}

static int get_vport(struct odp_vport __user *uodp_vport)
{
	struct nlattr *a[ODP_VPORT_ATTR_MAX + 1];
	struct odp_vport *odp_vport;
	struct vport *vport;
	struct sk_buff *skb;
	int err;

	skb = copy_vport_from_user(uodp_vport, a);
	err = PTR_ERR(skb);
	if (IS_ERR(skb))
		goto exit;
	odp_vport = (struct odp_vport *)skb->data;

	vport = lookup_vport(odp_vport, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_free;

	err = copy_vport_to_user(uodp_vport, vport, odp_vport->total_len);
	mutex_unlock(&vport->dp->mutex);
exit_free:
	kfree_skb(skb);
exit:
	return err;
}

static int dump_vport(struct odp_vport __user *uodp_vport)
{
	struct nlattr *a[ODP_VPORT_ATTR_MAX + 1];
	struct odp_vport *odp_vport;
	struct sk_buff *skb;
	struct datapath *dp;
	u32 port_no;
	int err;

	skb = copy_vport_from_user(uodp_vport, a);
	err = PTR_ERR(skb);
	if (IS_ERR(skb))
		goto exit;
	odp_vport = (struct odp_vport *)skb->data;

	dp = get_dp_locked(odp_vport->dp_idx);
	err = -ENODEV;
	if (!dp)
		goto exit_free;

	port_no = 0;
	if (a[ODP_VPORT_ATTR_PORT_NO])
		port_no = nla_get_u32(a[ODP_VPORT_ATTR_PORT_NO]);
	for (; port_no < DP_MAX_PORTS; port_no++) {
		struct vport *vport = get_vport_protected(dp, port_no);
		if (vport) {
			err = copy_vport_to_user(uodp_vport, vport, odp_vport->total_len);
			goto exit_unlock_dp;
		}
	}
	err = -ENODEV;

exit_unlock_dp:
	mutex_unlock(&dp->mutex);
exit_free:
	kfree_skb(skb);
exit:
	return err;
}

static long openvswitch_ioctl(struct file *f, unsigned int cmd,
			   unsigned long argp)
{
	int dp_idx = iminor(f->f_dentry->d_inode);
	struct datapath *dp;
	int drop_frags, listeners;
	unsigned int sflow_probability;
	int err;

	/* Handle commands with special locking requirements up front. */
	switch (cmd) {
	case ODP_DP_CREATE:
		err = create_dp(dp_idx, (char __user *)argp);
		goto exit;

	case ODP_DP_DESTROY:
		err = destroy_dp(dp_idx);
		goto exit;

	case ODP_VPORT_NEW:
		err = attach_vport((struct odp_vport __user *)argp);
		goto exit;

	case ODP_VPORT_GET:
		err = get_vport((struct odp_vport __user *)argp);
		goto exit;

	case ODP_VPORT_DEL:
		err = del_vport(cmd, (struct odp_vport __user *)argp);
		goto exit;

	case ODP_VPORT_SET:
		err = set_vport(cmd, (struct odp_vport __user *)argp);
		goto exit;

	case ODP_VPORT_DUMP:
		err = dump_vport((struct odp_vport __user *)argp);
		goto exit;

	case ODP_FLOW_FLUSH:
		err = flush_flows(argp);
		goto exit;

	case ODP_FLOW_PUT:
		err = put_flow((struct odp_flow_put __user *)argp);
		goto exit;

	case ODP_FLOW_DEL:
		err = del_flow((struct odp_flow __user *)argp);
		goto exit;

	case ODP_FLOW_GET:
		err = query_flow((struct odp_flow __user *)argp);
		goto exit;

	case ODP_FLOW_DUMP:
		err = dump_flow((struct odp_flow_dump __user *)argp);
		goto exit;

	case ODP_EXECUTE:
		err = execute_packet((struct odp_execute __user *)argp);
		goto exit;
	}

	dp = get_dp_locked(dp_idx);
	err = -ENODEV;
	if (!dp)
		goto exit;

	switch (cmd) {
	case ODP_DP_STATS:
		err = get_dp_stats(dp, (struct odp_stats __user *)argp);
		break;

	case ODP_GET_DROP_FRAGS:
		err = put_user(dp->drop_frags, (int __user *)argp);
		break;

	case ODP_SET_DROP_FRAGS:
		err = get_user(drop_frags, (int __user *)argp);
		if (err)
			break;
		err = -EINVAL;
		if (drop_frags != 0 && drop_frags != 1)
			break;
		dp->drop_frags = drop_frags;
		err = 0;
		break;

	case ODP_GET_LISTEN_MASK:
		err = put_user(get_listen_mask(f), (int __user *)argp);
		break;

	case ODP_SET_LISTEN_MASK:
		err = get_user(listeners, (int __user *)argp);
		if (err)
			break;
		err = -EINVAL;
		if (listeners & ~ODPL_ALL)
			break;
		err = 0;
		set_listen_mask(f, listeners);
		break;

	case ODP_GET_SFLOW_PROBABILITY:
		err = put_user(dp->sflow_probability, (unsigned int __user *)argp);
		break;

	case ODP_SET_SFLOW_PROBABILITY:
		err = get_user(sflow_probability, (unsigned int __user *)argp);
		if (!err)
			dp->sflow_probability = sflow_probability;
		break;

	default:
		err = -ENOIOCTLCMD;
		break;
	}
	mutex_unlock(&dp->mutex);
exit:
	return err;
}

static int dp_has_packet_of_interest(struct datapath *dp, int listeners)
{
	int i;
	for (i = 0; i < DP_N_QUEUES; i++) {
		if (listeners & (1 << i) && !skb_queue_empty(&dp->queues[i]))
			return 1;
	}
	return 0;
}

#ifdef CONFIG_COMPAT
static int compat_get_flow(struct odp_flow *flow, const struct compat_odp_flow __user *compat)
{
	compat_uptr_t key, actions;

	if (!access_ok(VERIFY_READ, compat, sizeof(struct compat_odp_flow)) ||
	    __copy_from_user(&flow->stats, &compat->stats, sizeof(struct odp_flow_stats)) ||
	    __get_user(key, &compat->key) ||
	    __get_user(flow->key_len, &compat->key_len) ||
	    __get_user(actions, &compat->actions) ||
	    __get_user(flow->actions_len, &compat->actions_len))
		return -EFAULT;

	flow->key = (struct nlattr __force *)compat_ptr(key);
	flow->actions = (struct nlattr __force *)compat_ptr(actions);
	return 0;
}

static int compat_put_flow(struct compat_odp_flow_put __user *ufp)
{
	struct odp_flow_stats stats;
	struct odp_flow_put uf;
	struct datapath *dp;
	int error;

	if (compat_get_flow(&uf.flow, &ufp->flow) ||
	    get_user(uf.flags, &ufp->flags))
		return -EFAULT;

	dp = get_dp_locked(uf.flow.dp_idx);
	if (!dp)
		return -ENODEV;

	error = do_put_flow(dp, &uf, &stats);
	if (!error) {
		if (copy_to_user(&ufp->flow.stats, &stats,
				 sizeof(struct odp_flow_stats)))
			error = -EFAULT;
	}
	mutex_unlock(&dp->mutex);

	return error;
}


static int compat_answer_query(struct datapath *dp, struct sw_flow *flow,
			       struct compat_odp_flow __user *ufp)
{
	compat_uptr_t actions;

	if (get_user(actions, &ufp->actions))
		return -EFAULT;

	return do_answer_query(dp, flow, &ufp->stats,
			       compat_ptr(actions), &ufp->actions_len);
}

static int compat_del_flow(struct compat_odp_flow __user *ufp)
{
	struct sw_flow *flow;
	struct datapath *dp;
	struct odp_flow uf;
	int error;

	if (compat_get_flow(&uf, ufp))
		return -EFAULT;

	dp = get_dp_locked(uf.dp_idx);
	if (!dp)
		return -ENODEV;

	flow = do_del_flow(dp, (const struct nlattr __force __user *)uf.key, uf.key_len);
	error = PTR_ERR(flow);
	if (!IS_ERR(flow)) {
		error = compat_answer_query(dp, flow, ufp);
		flow_deferred_free(flow);
	}
	mutex_unlock(&dp->mutex);

	return error;
}

static int compat_query_flow(struct compat_odp_flow __user *uflow)
{
	struct tbl_node *flow_node;
	struct sw_flow_key key;
	struct odp_flow flow;
	struct datapath *dp;
	int error;

	if (compat_get_flow(&flow, uflow))
		return -EFAULT;

	dp = get_dp_locked(flow.dp_idx);
	if (!dp)
		return -ENODEV;

	error = flow_copy_from_user(&key, (const struct nlattr __force __user *)flow.key, flow.key_len);
	if (!error) {
		struct tbl *table = get_table_protected(dp);
		flow_node = tbl_lookup(table, &flow.key, flow_hash(&key), flow_cmp);
		if (flow_node)
			error = compat_answer_query(dp, flow_cast(flow_node), uflow);
		else
			error = -ENOENT;
	}
	mutex_unlock(&dp->mutex);

	return error;
}

static int compat_dump_flow(struct compat_odp_flow_dump __user *udump)
{
	struct compat_odp_flow __user *uflow;
	struct nlattr __user *ukey;
	struct tbl_node *tbl_node;
	struct compat_odp_flow_dump dump;
	struct sw_flow *flow;
	compat_uptr_t ukey32;
	struct datapath *dp;
	struct tbl *table;
	u32 key_len;
	int err;

	err = -EFAULT;
	if (copy_from_user(&dump, udump, sizeof(struct compat_odp_flow_dump)))
		goto exit;
	uflow =compat_ptr(dump.flow);

	dp = get_dp_locked(dump.dp_idx);
	err = -ENODEV;
	if (!dp)
		goto exit;

	table = get_table_protected(dp);
	tbl_node = tbl_next(table, &dump.state[0], &dump.state[1]);
	if (!tbl_node) {
		err = put_user(0, &uflow->key_len);
		goto exit_unlock;
	}
	flow = flow_cast(tbl_node);

	err = -EFAULT;
	if (copy_to_user(udump->state, dump.state, 2 * sizeof(uint32_t)) ||
	    get_user(ukey32, &uflow->key) ||
	    get_user(key_len, &uflow->key_len))
		goto exit_unlock;
	ukey = compat_ptr(ukey32);

	key_len = flow_copy_to_user(ukey, &flow->key, key_len);
	err = key_len;
	if (key_len < 0)
		goto exit_unlock;
	err = -EFAULT;
	if (put_user(key_len, &uflow->key_len))
		goto exit_unlock;

	err = compat_answer_query(dp, flow, uflow);

exit_unlock:
	mutex_unlock(&dp->mutex);
exit:
	return err;
}

static int compat_execute(const struct compat_odp_execute __user *uexecute)
{
	struct odp_execute execute;
	compat_uptr_t actions;
	compat_uptr_t data;
	struct datapath *dp;
	int error;

	if (!access_ok(VERIFY_READ, uexecute, sizeof(struct compat_odp_execute)) ||
	    __get_user(execute.dp_idx, &uexecute->dp_idx) ||
	    __get_user(actions, &uexecute->actions) ||
	    __get_user(execute.actions_len, &uexecute->actions_len) ||
	    __get_user(data, &uexecute->data) ||
	    __get_user(execute.length, &uexecute->length))
		return -EFAULT;

	execute.actions = (struct nlattr __force *)compat_ptr(actions);
	execute.data = (const void __force *)compat_ptr(data);

	dp = get_dp_locked(execute.dp_idx);
	if (!dp)
		return -ENODEV;
	error = do_execute(dp, &execute);
	mutex_unlock(&dp->mutex);

	return error;
}

static long openvswitch_compat_ioctl(struct file *f, unsigned int cmd, unsigned long argp)
{
	switch (cmd) {
	case ODP_DP_DESTROY:
	case ODP_FLOW_FLUSH:
		/* Ioctls that don't need any translation at all. */
		return openvswitch_ioctl(f, cmd, argp);

	case ODP_DP_CREATE:
	case ODP_VPORT_NEW:
	case ODP_VPORT_DEL:
	case ODP_VPORT_GET:
	case ODP_VPORT_SET:
	case ODP_VPORT_DUMP:
	case ODP_DP_STATS:
	case ODP_GET_DROP_FRAGS:
	case ODP_SET_DROP_FRAGS:
	case ODP_SET_LISTEN_MASK:
	case ODP_GET_LISTEN_MASK:
	case ODP_SET_SFLOW_PROBABILITY:
	case ODP_GET_SFLOW_PROBABILITY:
		/* Ioctls that just need their pointer argument extended. */
		return openvswitch_ioctl(f, cmd, (unsigned long)compat_ptr(argp));

	case ODP_FLOW_PUT32:
		return compat_put_flow(compat_ptr(argp));

	case ODP_FLOW_DEL32:
		return compat_del_flow(compat_ptr(argp));

	case ODP_FLOW_GET32:
		return compat_query_flow(compat_ptr(argp));

	case ODP_FLOW_DUMP32:
		return compat_dump_flow(compat_ptr(argp));

	case ODP_EXECUTE32:
		return compat_execute(compat_ptr(argp));

	default:
		return -ENOIOCTLCMD;
	}
}
#endif

static ssize_t openvswitch_read(struct file *f, char __user *buf,
				size_t nbytes, loff_t *ppos)
{
	int listeners = get_listen_mask(f);
	int dp_idx = iminor(f->f_dentry->d_inode);
	struct datapath *dp = get_dp_locked(dp_idx);
	struct sk_buff *skb;
	struct iovec iov;
	int retval;

	if (!dp)
		return -ENODEV;

	if (nbytes == 0 || !listeners)
		return 0;

	for (;;) {
		int i;

		for (i = 0; i < DP_N_QUEUES; i++) {
			if (listeners & (1 << i)) {
				skb = skb_dequeue(&dp->queues[i]);
				if (skb)
					goto success;
			}
		}

		if (f->f_flags & O_NONBLOCK) {
			retval = -EAGAIN;
			goto error;
		}

		wait_event_interruptible(dp->waitqueue,
					 dp_has_packet_of_interest(dp,
								   listeners));

		if (signal_pending(current)) {
			retval = -ERESTARTSYS;
			goto error;
		}
	}
success:
	mutex_unlock(&dp->mutex);

	iov.iov_base = buf;
	iov.iov_len = min_t(size_t, skb->len, nbytes);
	retval = skb_copy_datagram_iovec(skb, 0, &iov, iov.iov_len);
	if (!retval)
		retval = skb->len;

	kfree_skb(skb);
	return retval;

error:
	mutex_unlock(&dp->mutex);
	return retval;
}

static unsigned int openvswitch_poll(struct file *file, poll_table *wait)
{
	int dp_idx = iminor(file->f_dentry->d_inode);
	struct datapath *dp = get_dp_locked(dp_idx);
	unsigned int mask;

	if (dp) {
		mask = 0;
		poll_wait(file, &dp->waitqueue, wait);
		if (dp_has_packet_of_interest(dp, get_listen_mask(file)))
			mask |= POLLIN | POLLRDNORM;
		mutex_unlock(&dp->mutex);
	} else {
		mask = POLLIN | POLLRDNORM | POLLHUP;
	}
	return mask;
}

static struct file_operations openvswitch_fops = {
	.owner = THIS_MODULE,
	.read  = openvswitch_read,
	.poll  = openvswitch_poll,
	.unlocked_ioctl = openvswitch_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = openvswitch_compat_ioctl,
#endif
};

static int major;

static int __init dp_init(void)
{
	struct sk_buff *dummy_skb;
	int err;

	BUILD_BUG_ON(sizeof(struct ovs_skb_cb) > sizeof(dummy_skb->cb));

	printk("Open vSwitch %s, built "__DATE__" "__TIME__"\n", VERSION BUILDNR);

	err = flow_init();
	if (err)
		goto error;

	err = vport_init();
	if (err)
		goto error_flow_exit;

	err = register_netdevice_notifier(&dp_device_notifier);
	if (err)
		goto error_vport_exit;

	major = register_chrdev(0, "openvswitch", &openvswitch_fops);
	if (err < 0)
		goto error_unreg_notifier;

	return 0;

error_unreg_notifier:
	unregister_netdevice_notifier(&dp_device_notifier);
error_vport_exit:
	vport_exit();
error_flow_exit:
	flow_exit();
error:
	return err;
}

static void dp_cleanup(void)
{
	rcu_barrier();
	unregister_chrdev(major, "openvswitch");
	unregister_netdevice_notifier(&dp_device_notifier);
	vport_exit();
	flow_exit();
}

module_init(dp_init);
module_exit(dp_cleanup);

MODULE_DESCRIPTION("Open vSwitch switching datapath");
MODULE_LICENSE("GPL");
