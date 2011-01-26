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
static struct datapath __rcu *dps[256];
static DEFINE_MUTEX(dp_mutex);

static struct vport *new_vport(const struct vport_parms *);

/* Must be called with rcu_read_lock or dp_mutex. */
struct datapath *get_dp(int dp_idx)
{
	if (dp_idx < 0 || dp_idx >= ARRAY_SIZE(dps))
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

/* Caller must hold RTNL, dp_mutex, and dp->mutex. */
static void destroy_dp(struct datapath *dp)
{
	struct vport *p, *n;

	list_for_each_entry_safe (p, n, &dp->port_list, node)
		if (p->port_no != ODPP_LOCAL)
			dp_detach_port(p);

	dp_sysfs_del_dp(dp);
	rcu_assign_pointer(dps[dp->dp_idx], NULL);
	dp_detach_port(get_vport_protected(dp, ODPP_LOCAL));

	mutex_unlock(&dp->mutex);
	call_rcu(&dp->rcu, destroy_dp_rcu);
	module_put(THIS_MODULE);
}

/* Called with RTNL lock and dp->mutex. */
static struct vport *new_vport(const struct vport_parms *parms)
{
	struct vport *vport;

	vport = vport_add(parms);
	if (!IS_ERR(vport)) {
		struct datapath *dp = parms->dp;

		rcu_assign_pointer(dp->ports[parms->port_no], vport);
		list_add_rcu(&vport->node, &dp->port_list);

		dp_ifinfo_notify(RTM_NEWLINK, vport);
	}

	return vport;
}

int dp_detach_port(struct vport *p)
{
	ASSERT_RTNL();

	if (p->port_no != ODPP_LOCAL)
		dp_sysfs_del_if(p);
	dp_ifinfo_notify(RTM_DELLINK, p);

	/* First drop references to device. */
	list_del_rcu(&p->node);
	rcu_assign_pointer(p->dp->ports[p->port_no], NULL);

	/* Then destroy it. */
	return vport_del(p);
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
		error = flow_extract(skb, p->port_no, &key, &is_frag);
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

struct dp_flowcmd {
	u32 nlmsg_flags;
	u32 dp_idx;
	u32 total_len;
	struct sw_flow_key key;
	const struct nlattr *actions;
	u32 actions_len;
	bool clear;
	u64 state;
};

static struct sw_flow_actions *get_actions(const struct dp_flowcmd *flowcmd)
{
	struct sw_flow_actions *actions;

	actions = flow_actions_alloc(flowcmd->actions_len);
	if (!IS_ERR(actions) && flowcmd->actions_len)
		memcpy(actions->actions, flowcmd->actions, flowcmd->actions_len);
	return actions;
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

static const struct nla_policy execute_policy[ODP_PACKET_ATTR_MAX + 1] = {
	[ODP_PACKET_ATTR_PACKET] = { .type = NLA_UNSPEC },
	[ODP_PACKET_ATTR_ACTIONS] = { .type = NLA_NESTED },
};

static int execute_packet(const struct odp_packet __user *uodp_packet)
{
	struct nlattr *a[ODP_PACKET_ATTR_MAX + 1];
	struct odp_packet *odp_packet;
	struct sk_buff *skb, *packet;
	unsigned int actions_len;
	struct nlattr *actions;
	struct sw_flow_key key;
	struct datapath *dp;
	struct ethhdr *eth;
	bool is_frag;
	u32 len;
	int err;

	if (get_user(len, &uodp_packet->len))
		return -EFAULT;
	if (len < sizeof(struct odp_packet))
		return -EINVAL;

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	err = -EFAULT;
	if (copy_from_user(__skb_put(skb, len), uodp_packet, len))
		goto exit_free_skb;

	odp_packet = (struct odp_packet *)skb->data;
	err = -EINVAL;
	if (odp_packet->len != len)
		goto exit_free_skb;

	__skb_pull(skb, sizeof(struct odp_packet));
	err = nla_parse(a, ODP_PACKET_ATTR_MAX, (struct nlattr *)skb->data,
			skb->len, execute_policy);
	if (err)
		goto exit_free_skb;

	err = -EINVAL;
	if (!a[ODP_PACKET_ATTR_PACKET] || !a[ODP_PACKET_ATTR_ACTIONS] ||
	    nla_len(a[ODP_PACKET_ATTR_PACKET]) < ETH_HLEN)
		goto exit_free_skb;

	actions = nla_data(a[ODP_PACKET_ATTR_ACTIONS]);
	actions_len = nla_len(a[ODP_PACKET_ATTR_ACTIONS]);
	err = validate_actions(actions, actions_len);
	if (err)
		goto exit_free_skb;

	packet = skb_clone(skb, GFP_KERNEL);
	err = -ENOMEM;
	if (!packet)
		goto exit_free_skb;
	packet->data = nla_data(a[ODP_PACKET_ATTR_PACKET]);
	packet->len = nla_len(a[ODP_PACKET_ATTR_PACKET]);

	skb_reset_mac_header(packet);
	eth = eth_hdr(packet);

	/* Normally, setting the skb 'protocol' field would be handled by a
	 * call to eth_type_trans(), but it assumes there's a sending
	 * device, which we may not have. */
	if (ntohs(eth->h_proto) >= 1536)
		packet->protocol = eth->h_proto;
	else
		packet->protocol = htons(ETH_P_802_2);

	err = flow_extract(packet, -1, &key, &is_frag);
	if (err)
		goto exit_free_skb;

	rcu_read_lock();
	dp = get_dp(odp_packet->dp_idx);
	err = -ENODEV;
	if (dp)
		err = execute_actions(dp, packet, &key, actions, actions_len);
	rcu_read_unlock();

exit_free_skb:
	kfree_skb(skb);
	return err;
}

static void get_dp_stats(struct datapath *dp, struct odp_stats *stats)
{
	int i;

	stats->n_frags = stats->n_hit = stats->n_missed = stats->n_lost = 0;
	for_each_possible_cpu(i) {
		const struct dp_stats_percpu *percpu_stats;
		struct dp_stats_percpu local_stats;
		unsigned seqcount;

		percpu_stats = per_cpu_ptr(dp->stats_percpu, i);

		do {
			seqcount = read_seqcount_begin(&percpu_stats->seqlock);
			local_stats = *percpu_stats;
		} while (read_seqcount_retry(&percpu_stats->seqlock, seqcount));

		stats->n_frags += local_stats.n_frags;
		stats->n_hit += local_stats.n_hit;
		stats->n_missed += local_stats.n_missed;
		stats->n_lost += local_stats.n_lost;
	}
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

static const struct nla_policy flow_policy[ODP_FLOW_ATTR_MAX + 1] = {
	[ODP_FLOW_ATTR_KEY] = { .type = NLA_NESTED },
	[ODP_FLOW_ATTR_ACTIONS] = { .type = NLA_NESTED },
	[ODP_FLOW_ATTR_CLEAR] = { .type = NLA_FLAG },
	[ODP_FLOW_ATTR_STATE] = { .type = NLA_U64 },
};

static int copy_flow_to_user(struct odp_flow __user *dst, struct datapath *dp,
			     struct sw_flow *flow, u32 total_len, u64 state)
{
	const struct sw_flow_actions *sf_acts;
	struct odp_flow_stats stats;
	struct odp_flow *odp_flow;
	struct sk_buff *skb;
	struct nlattr *nla;
	unsigned long used;
	u8 tcp_flags;
	int err;

	sf_acts = rcu_dereference_protected(flow->sf_acts,
					    lockdep_is_held(&dp->mutex));

	skb = alloc_skb(128 + FLOW_BUFSIZE + sf_acts->actions_len, GFP_KERNEL);
	err = -ENOMEM;
	if (!skb)
		goto exit;

	rcu_read_lock();
	odp_flow = (struct odp_flow*)__skb_put(skb, sizeof(struct odp_flow));
	odp_flow->dp_idx = dp->dp_idx;
	odp_flow->total_len = total_len;

	nla = nla_nest_start(skb, ODP_FLOW_ATTR_KEY);
	if (!nla)
		goto nla_put_failure;
	err = flow_to_nlattrs(&flow->key, skb);
	if (err)
		goto exit_unlock;
	nla_nest_end(skb, nla);

	nla = nla_nest_start(skb, ODP_FLOW_ATTR_ACTIONS);
	if (!nla || skb_tailroom(skb) < sf_acts->actions_len)
		goto nla_put_failure;
	memcpy(__skb_put(skb, sf_acts->actions_len), sf_acts->actions, sf_acts->actions_len);
	nla_nest_end(skb, nla);

	spin_lock_bh(&flow->lock);
	used = flow->used;
	stats.n_packets = flow->packet_count;
	stats.n_bytes = flow->byte_count;
	tcp_flags = flow->tcp_flags;
	spin_unlock_bh(&flow->lock);

	if (used)
		NLA_PUT_MSECS(skb, ODP_FLOW_ATTR_USED, used);

	if (stats.n_packets)
		NLA_PUT(skb, ODP_FLOW_ATTR_STATS, sizeof(struct odp_flow_stats), &stats);

	if (tcp_flags)
		NLA_PUT_U8(skb, ODP_FLOW_ATTR_TCP_FLAGS, tcp_flags);

	if (state)
		NLA_PUT_U64(skb, ODP_FLOW_ATTR_STATE, state);

	if (skb->len > total_len)
		goto nla_put_failure;

	odp_flow->len = skb->len;
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

static struct sk_buff *copy_flow_from_user(struct odp_flow __user *uodp_flow,
					   struct dp_flowcmd *flowcmd)
{
	struct nlattr *a[ODP_FLOW_ATTR_MAX + 1];
	struct odp_flow *odp_flow;
	struct sk_buff *skb;
	u32 len;
	int err;

	if (get_user(len, &uodp_flow->len))
		return ERR_PTR(-EFAULT);
	if (len < sizeof(struct odp_flow))
		return ERR_PTR(-EINVAL);

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	err = -EFAULT;
	if (copy_from_user(__skb_put(skb, len), uodp_flow, len))
		goto error_free_skb;

	odp_flow = (struct odp_flow *)skb->data;
	err = -EINVAL;
	if (odp_flow->len != len)
		goto error_free_skb;

	flowcmd->nlmsg_flags = odp_flow->nlmsg_flags;
	flowcmd->dp_idx = odp_flow->dp_idx;
	flowcmd->total_len = odp_flow->total_len;

	err = nla_parse(a, ODP_FLOW_ATTR_MAX,
			(struct nlattr *)(skb->data + sizeof(struct odp_flow)),
			skb->len - sizeof(struct odp_flow), flow_policy);
	if (err)
		goto error_free_skb;

	/* ODP_FLOW_ATTR_KEY. */
	if (a[ODP_FLOW_ATTR_KEY]) {
		err = flow_from_nlattrs(&flowcmd->key, a[ODP_FLOW_ATTR_KEY]);
		if (err)
			goto error_free_skb;
	} else
		memset(&flowcmd->key, 0, sizeof(struct sw_flow_key));

	/* ODP_FLOW_ATTR_ACTIONS. */
	if (a[ODP_FLOW_ATTR_ACTIONS]) {
		flowcmd->actions = nla_data(a[ODP_FLOW_ATTR_ACTIONS]);
		flowcmd->actions_len = nla_len(a[ODP_FLOW_ATTR_ACTIONS]);
		err = validate_actions(flowcmd->actions, flowcmd->actions_len);
		if (err)
			goto error_free_skb;
	} else {
		flowcmd->actions = NULL;
		flowcmd->actions_len = 0;
	}

	flowcmd->clear = a[ODP_FLOW_ATTR_CLEAR] != NULL;

	flowcmd->state = a[ODP_FLOW_ATTR_STATE] ? nla_get_u64(a[ODP_FLOW_ATTR_STATE]) : 0;

	return skb;

error_free_skb:
	kfree_skb(skb);
	return ERR_PTR(err);
}

static int new_flow(unsigned int cmd, struct odp_flow __user *uodp_flow)
{
	struct tbl_node *flow_node;
	struct dp_flowcmd flowcmd;
	struct sw_flow *flow;
	struct sk_buff *skb;
	struct datapath *dp;
	struct tbl *table;
	u32 hash;
	int error;

	skb = copy_flow_from_user(uodp_flow, &flowcmd);
	error = PTR_ERR(skb);
	if (IS_ERR(skb))
		goto exit;

	dp = get_dp_locked(flowcmd.dp_idx);
	error = -ENODEV;
	if (!dp)
		goto error_kfree_skb;

	hash = flow_hash(&flowcmd.key);
	table = get_table_protected(dp);
	flow_node = tbl_lookup(table, &flowcmd.key, hash, flow_cmp);
	if (!flow_node) {
		struct sw_flow_actions *acts;

		/* Bail out if we're not allowed to create a new flow. */
		error = -ENOENT;
		if (cmd == ODP_FLOW_SET)
			goto error_unlock_dp;

		/* Expand table, if necessary, to make room. */
		if (tbl_count(table) >= tbl_n_buckets(table)) {
			error = expand_table(dp);
			if (error)
				goto error_unlock_dp;
			table = get_table_protected(dp);
		}

		/* Allocate flow. */
		flow = flow_alloc();
		if (IS_ERR(flow)) {
			error = PTR_ERR(flow);
			goto error_unlock_dp;
		}
		flow->key = flowcmd.key;
		clear_stats(flow);

		/* Obtain actions. */
		acts = get_actions(&flowcmd);
		error = PTR_ERR(acts);
		if (IS_ERR(acts))
			goto error_free_flow;
		rcu_assign_pointer(flow->sf_acts, acts);

		error = copy_flow_to_user(uodp_flow, dp, flow, flowcmd.total_len, 0);
		if (error)
			goto error_free_flow;

		/* Put flow in bucket. */
		error = tbl_insert(table, &flow->tbl_node, hash);
		if (error)
			goto error_free_flow;
	} else {
		/* We found a matching flow. */
		struct sw_flow_actions *old_acts;

		/* Bail out if we're not allowed to modify an existing flow.
		 * We accept NLM_F_CREATE in place of the intended NLM_F_EXCL
		 * because Generic Netlink treats the latter as a dump
		 * request.  We also accept NLM_F_EXCL in case that bug ever
		 * gets fixed.
		 */
		error = -EEXIST;
		if (flowcmd.nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL))
			goto error_kfree_skb;

		/* Update actions. */
		flow = flow_cast(flow_node);
		old_acts = rcu_dereference_protected(flow->sf_acts,
						     lockdep_is_held(&dp->mutex));
		if (flowcmd.actions &&
		    (old_acts->actions_len != flowcmd.actions_len ||
		     memcmp(old_acts->actions, flowcmd.actions,
			    flowcmd.actions_len))) {
			struct sw_flow_actions *new_acts;

			new_acts = get_actions(&flowcmd);
			error = PTR_ERR(new_acts);
			if (IS_ERR(new_acts))
				goto error_kfree_skb;

			rcu_assign_pointer(flow->sf_acts, new_acts);
			flow_deferred_free_acts(old_acts);
		}

		error = copy_flow_to_user(uodp_flow, dp, flow, flowcmd.total_len, 0);
		if (error)
			goto error_kfree_skb;

		/* Clear stats. */
		if (flowcmd.clear) {
			spin_lock_bh(&flow->lock);
			clear_stats(flow);
			spin_unlock_bh(&flow->lock);
		}
	}
	kfree_skb(skb);
	mutex_unlock(&dp->mutex);
	return 0;

error_free_flow:
	flow_put(flow);
error_unlock_dp:
	mutex_unlock(&dp->mutex);
error_kfree_skb:
	kfree_skb(skb);
exit:
	return error;
}

static int get_or_del_flow(unsigned int cmd, struct odp_flow __user *uodp_flow)
{
	struct tbl_node *flow_node;
	struct dp_flowcmd flowcmd;
	struct sw_flow *flow;
	struct sk_buff *skb;
	struct datapath *dp;
	struct tbl *table;
	int err;

	skb = copy_flow_from_user(uodp_flow, &flowcmd);
	err = PTR_ERR(skb);
	if (IS_ERR(skb))
		goto exit;

	dp = get_dp_locked(flowcmd.dp_idx);
	err = -ENODEV;
	if (!dp)
		goto exit_kfree_skb;

	table = get_table_protected(dp);
	flow_node = tbl_lookup(table, &flowcmd.key, flow_hash(&flowcmd.key), flow_cmp);
	err = -ENOENT;
	if (!flow_node)
		goto exit_unlock_dp;

	if (cmd == ODP_FLOW_DEL) {
		err = tbl_remove(table, flow_node);
		if (err)
			goto exit_unlock_dp;
	}

	flow = flow_cast(flow_node);
	err = copy_flow_to_user(uodp_flow, dp, flow, flowcmd.total_len, 0);
	if (!err && cmd == ODP_FLOW_DEL)
		flow_deferred_free(flow);

exit_unlock_dp:
	mutex_unlock(&dp->mutex);
exit_kfree_skb:
	kfree_skb(skb);
exit:
	return err;
}

static int dump_flow(struct odp_flow __user *uodp_flow)
{
	struct tbl_node *flow_node;
	struct dp_flowcmd flowcmd;
	struct sw_flow *flow;
	struct sk_buff *skb;
	struct datapath *dp;
	u32 bucket, obj;
	int err;

	skb = copy_flow_from_user(uodp_flow, &flowcmd);
	err = PTR_ERR(skb);
	if (IS_ERR(skb))
		goto exit;

	dp = get_dp_locked(flowcmd.dp_idx);
	err = -ENODEV;
	if (!dp)
		goto exit_free;

	bucket = flowcmd.state >> 32;
	obj = flowcmd.state;
	flow_node = tbl_next(dp->table, &bucket, &obj);
	err = -ENODEV;
	if (!flow_node)
		goto exit_unlock_dp;

	flow = flow_cast(flow_node);
	err = copy_flow_to_user(uodp_flow, dp, flow, flowcmd.total_len,
				((u64)bucket << 32) | obj);

exit_unlock_dp:
	mutex_unlock(&dp->mutex);
exit_free:
	kfree_skb(skb);
exit:
	return err;
}

static const struct nla_policy datapath_policy[ODP_DP_ATTR_MAX + 1] = {
	[ODP_DP_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[ODP_DP_ATTR_IPV4_FRAGS] = { .type = NLA_U32 },
	[ODP_DP_ATTR_SAMPLING] = { .type = NLA_U32 },
};

static int copy_datapath_to_user(void __user *dst, struct datapath *dp, uint32_t total_len)
{
	struct odp_datapath *odp_datapath;
	struct sk_buff *skb;
	struct nlattr *nla;
	int err;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	err = -ENOMEM;
	if (!skb)
		goto exit;

	odp_datapath = (struct odp_datapath*)__skb_put(skb, sizeof(struct odp_datapath));
	odp_datapath->dp_idx = dp->dp_idx;
	odp_datapath->total_len = total_len;

	rcu_read_lock();
	err = nla_put_string(skb, ODP_DP_ATTR_NAME, dp_name(dp));
	rcu_read_unlock();
	if (err)
		goto nla_put_failure;

	nla = nla_reserve(skb, ODP_DP_ATTR_STATS, sizeof(struct odp_stats));
	if (!nla)
		goto nla_put_failure;
	get_dp_stats(dp, nla_data(nla));

	NLA_PUT_U32(skb, ODP_DP_ATTR_IPV4_FRAGS,
		    dp->drop_frags ? ODP_DP_FRAG_DROP : ODP_DP_FRAG_ZERO);

	if (dp->sflow_probability)
		NLA_PUT_U32(skb, ODP_DP_ATTR_SAMPLING, dp->sflow_probability);

	if (skb->len > total_len)
		goto nla_put_failure;

	odp_datapath->len = skb->len;
	err = copy_to_user(dst, skb->data, skb->len) ? -EFAULT : 0;
	goto exit_free_skb;

nla_put_failure:
	err = -EMSGSIZE;
exit_free_skb:
	kfree_skb(skb);
exit:
	return err;
}

static struct sk_buff *copy_datapath_from_user(struct odp_datapath __user *uodp_datapath, struct nlattr *a[ODP_DP_ATTR_MAX + 1])
{
	struct odp_datapath *odp_datapath;
	struct sk_buff *skb;
	u32 len;
	int err;

	if (get_user(len, &uodp_datapath->len))
		return ERR_PTR(-EFAULT);
	if (len < sizeof(struct odp_datapath))
		return ERR_PTR(-EINVAL);

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	err = -EFAULT;
	if (copy_from_user(__skb_put(skb, len), uodp_datapath, len))
		goto error_free_skb;

	odp_datapath = (struct odp_datapath *)skb->data;
	err = -EINVAL;
	if (odp_datapath->len != len)
		goto error_free_skb;

	err = nla_parse(a, ODP_DP_ATTR_MAX,
			(struct nlattr *)(skb->data + sizeof(struct odp_datapath)),
			skb->len - sizeof(struct odp_datapath), datapath_policy);
	if (err)
		goto error_free_skb;

	if (a[ODP_DP_ATTR_IPV4_FRAGS]) {
		u32 frags = nla_get_u32(a[ODP_DP_ATTR_IPV4_FRAGS]);

		err = -EINVAL;
		if (frags != ODP_DP_FRAG_ZERO && frags != ODP_DP_FRAG_DROP)
			goto error_free_skb;
	}

	err = VERIFY_NUL_STRING(a[ODP_DP_ATTR_NAME], IFNAMSIZ - 1);
	if (err)
		goto error_free_skb;

	return skb;

error_free_skb:
	kfree_skb(skb);
	return ERR_PTR(err);
}

/* Called with dp_mutex and optionally with RTNL lock also.
 * Holds the returned datapath's mutex on return.
 */
static struct datapath *lookup_datapath(struct odp_datapath *odp_datapath, struct nlattr *a[ODP_DP_ATTR_MAX + 1])
{
	WARN_ON_ONCE(!mutex_is_locked(&dp_mutex));

	if (!a[ODP_DP_ATTR_NAME]) {
		struct datapath *dp;

		dp = get_dp(odp_datapath->dp_idx);
		if (!dp)
			return ERR_PTR(-ENODEV);
		mutex_lock(&dp->mutex);
		return dp;
	} else {
		struct datapath *dp;
		struct vport *vport;
		int dp_idx;

		rcu_read_lock();
		vport = vport_locate(nla_data(a[ODP_DP_ATTR_NAME]));
		dp_idx = vport && vport->port_no == ODPP_LOCAL ? vport->dp->dp_idx : -1;
		rcu_read_unlock();

		if (dp_idx < 0)
			return ERR_PTR(-ENODEV);

		dp = get_dp(dp_idx);
		mutex_lock(&dp->mutex);
		return dp;
	}
}

static void change_datapath(struct datapath *dp, struct nlattr *a[ODP_DP_ATTR_MAX + 1])
{
	if (a[ODP_DP_ATTR_IPV4_FRAGS])
		dp->drop_frags = nla_get_u32(a[ODP_DP_ATTR_IPV4_FRAGS]) == ODP_DP_FRAG_DROP;
	if (a[ODP_DP_ATTR_SAMPLING])
		dp->sflow_probability = nla_get_u32(a[ODP_DP_ATTR_SAMPLING]);
}

static int new_datapath(struct odp_datapath __user *uodp_datapath)
{
	struct nlattr *a[ODP_DP_ATTR_MAX + 1];
	struct odp_datapath *odp_datapath;
	struct vport_parms parms;
	struct sk_buff *skb;
	struct datapath *dp;
	struct vport *vport;
	int dp_idx;
	int err;
	int i;

	skb = copy_datapath_from_user(uodp_datapath, a);
	err = PTR_ERR(skb);
	if (IS_ERR(skb))
		goto err;
	odp_datapath = (struct odp_datapath *)skb->data;

	err = -EINVAL;
	if (!a[ODP_DP_ATTR_NAME])
		goto err_free_skb;

	rtnl_lock();
	mutex_lock(&dp_mutex);
	err = -ENODEV;
	if (!try_module_get(THIS_MODULE))
		goto err_unlock_dp_mutex;

	dp_idx = odp_datapath->dp_idx;
	if (dp_idx < 0) {
		err = -EFBIG;
		for (dp_idx = 0; dp_idx < ARRAY_SIZE(dps); dp_idx++) {
			if (get_dp(dp_idx))
				continue;
			err = 0;
			break;
		}
	} else if (dp_idx < ARRAY_SIZE(dps))
		err = get_dp(dp_idx) ? -EBUSY : 0;
	else
		err = -EINVAL;
	if (err)
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
	parms.name = nla_data(a[ODP_DP_ATTR_NAME]);
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

	change_datapath(dp, a);

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
err_unlock_dp_mutex:
	mutex_unlock(&dp_mutex);
	rtnl_unlock();
err_free_skb:
	kfree_skb(skb);
err:
	return err;
}

static int del_datapath(struct odp_datapath __user *uodp_datapath)
{
	struct nlattr *a[ODP_DP_ATTR_MAX + 1];
	struct datapath *dp;
	struct sk_buff *skb;
	int err;

	skb = copy_datapath_from_user(uodp_datapath, a);
	err = PTR_ERR(skb);
	if (IS_ERR(skb))
		goto exit;

	rtnl_lock();
	mutex_lock(&dp_mutex);
	dp = lookup_datapath((struct odp_datapath *)skb->data, a);
	err = PTR_ERR(dp);
	if (IS_ERR(dp))
		goto exit_free;

	destroy_dp(dp);
	err = 0;

exit_free:
	kfree_skb(skb);
	mutex_unlock(&dp_mutex);
	rtnl_unlock();
exit:
	return err;
}

static int set_datapath(struct odp_datapath __user *uodp_datapath)
{
	struct nlattr *a[ODP_DP_ATTR_MAX + 1];
	struct datapath *dp;
	struct sk_buff *skb;
	int err;

	skb = copy_datapath_from_user(uodp_datapath, a);
	err = PTR_ERR(skb);
	if (IS_ERR(skb))
		goto exit;

	mutex_lock(&dp_mutex);
	dp = lookup_datapath((struct odp_datapath *)skb->data, a);
	err = PTR_ERR(dp);
	if (IS_ERR(dp))
		goto exit_free;

	change_datapath(dp, a);
	mutex_unlock(&dp->mutex);
	err = 0;

exit_free:
	kfree_skb(skb);
	mutex_unlock(&dp_mutex);
exit:
	return err;
}

static int get_datapath(struct odp_datapath __user *uodp_datapath)
{
	struct nlattr *a[ODP_DP_ATTR_MAX + 1];
	struct odp_datapath *odp_datapath;
	struct datapath *dp;
	struct sk_buff *skb;
	int err;

	skb = copy_datapath_from_user(uodp_datapath, a);
	err = PTR_ERR(skb);
	if (IS_ERR(skb))
		goto exit;
	odp_datapath = (struct odp_datapath *)skb->data;

	mutex_lock(&dp_mutex);
	dp = lookup_datapath(odp_datapath, a);
	mutex_unlock(&dp_mutex);

	err = PTR_ERR(dp);
	if (IS_ERR(dp))
		goto exit_free;

	err = copy_datapath_to_user(uodp_datapath, dp, odp_datapath->total_len);
	mutex_unlock(&dp->mutex);
exit_free:
	kfree_skb(skb);
exit:
	return err;
}

static int dump_datapath(struct odp_datapath __user *uodp_datapath)
{
	struct nlattr *a[ODP_DP_ATTR_MAX + 1];
	struct odp_datapath *odp_datapath;
	struct sk_buff *skb;
	u32 dp_idx;
	int err;

	skb = copy_datapath_from_user(uodp_datapath, a);
	err = PTR_ERR(skb);
	if (IS_ERR(skb))
		goto exit;
	odp_datapath = (struct odp_datapath *)skb->data;

	mutex_lock(&dp_mutex);
	for (dp_idx = odp_datapath->dp_idx; dp_idx < ARRAY_SIZE(dps); dp_idx++) {
		struct datapath *dp = get_dp(dp_idx);
		if (!dp)
			continue;

		mutex_lock(&dp->mutex);
		mutex_unlock(&dp_mutex);
		err = copy_datapath_to_user(uodp_datapath, dp, odp_datapath->total_len);
		mutex_unlock(&dp->mutex);
		goto exit_free;
	}
	mutex_unlock(&dp_mutex);
	err = -ENODEV;

exit_free:
	kfree_skb(skb);
exit:
	return err;
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
		rcu_read_lock();
		vport = vport_locate(nla_data(a[ODP_VPORT_ATTR_NAME]));
		if (!vport) {
			rcu_read_unlock();
			return ERR_PTR(-ENODEV);
		}
		dp_idx = vport->dp->dp_idx;
		port_no = vport->port_no;
		rcu_read_unlock();

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
	int listeners;
	int err;

	/* Handle commands with special locking requirements up front. */
	switch (cmd) {
	case ODP_DP_NEW:
		err = new_datapath((struct odp_datapath __user *)argp);
		goto exit;

	case ODP_DP_GET:
		err = get_datapath((struct odp_datapath __user *)argp);
		goto exit;

	case ODP_DP_DEL:
		err = del_datapath((struct odp_datapath __user *)argp);
		goto exit;

	case ODP_DP_SET:
		err = set_datapath((struct odp_datapath __user *)argp);
		goto exit;

	case ODP_DP_DUMP:
		err = dump_datapath((struct odp_datapath __user *)argp);
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

	case ODP_FLOW_NEW:
	case ODP_FLOW_SET:
		err = new_flow(cmd, (struct odp_flow __user *)argp);
		goto exit;

	case ODP_FLOW_GET:
	case ODP_FLOW_DEL:
		err = get_or_del_flow(cmd, (struct odp_flow __user *)argp);
		goto exit;

	case ODP_FLOW_DUMP:
		err = dump_flow((struct odp_flow __user *)argp);
		goto exit;

	case ODP_EXECUTE:
		err = execute_packet((struct odp_packet __user *)argp);
		goto exit;
	}

	dp = get_dp_locked(dp_idx);
	err = -ENODEV;
	if (!dp)
		goto exit;

	switch (cmd) {
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
static long openvswitch_compat_ioctl(struct file *f, unsigned int cmd, unsigned long argp)
{
	switch (cmd) {
	case ODP_FLOW_FLUSH:
		/* Ioctls that don't need any translation at all. */
		return openvswitch_ioctl(f, cmd, argp);

	case ODP_DP_NEW:
	case ODP_DP_GET:
	case ODP_DP_DEL:
	case ODP_DP_SET:
	case ODP_DP_DUMP:
	case ODP_VPORT_NEW:
	case ODP_VPORT_DEL:
	case ODP_VPORT_GET:
	case ODP_VPORT_SET:
	case ODP_VPORT_DUMP:
	case ODP_FLOW_NEW:
	case ODP_FLOW_DEL:
	case ODP_FLOW_GET:
	case ODP_FLOW_SET:
	case ODP_FLOW_DUMP:
	case ODP_SET_LISTEN_MASK:
	case ODP_GET_LISTEN_MASK:
	case ODP_EXECUTE:
		/* Ioctls that just need their pointer argument extended. */
		return openvswitch_ioctl(f, cmd, (unsigned long)compat_ptr(argp));

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
