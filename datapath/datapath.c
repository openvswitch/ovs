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
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/etherdevice.h>
#include <linux/genetlink.h>
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

#include "openvswitch/datapath-protocol.h"
#include "checksum.h"
#include "datapath.h"
#include "actions.h"
#include "flow.h"
#include "vlan.h"
#include "tunnel.h"
#include "vport-internal_dev.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18) || \
    LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
#error Kernels before 2.6.18 or after 3.0 are not supported by this version of Open vSwitch.
#endif

int (*dp_ioctl_hook)(struct net_device *dev, struct ifreq *rq, int cmd);
EXPORT_SYMBOL(dp_ioctl_hook);

/**
 * DOC: Locking:
 *
 * Writes to device state (add/remove datapath, port, set operations on vports,
 * etc.) are protected by RTNL.
 *
 * Writes to other state (flow table modifications, set miscellaneous datapath
 * parameters such as drop frags, etc.) are protected by genl_mutex.  The RTNL
 * lock nests inside genl_mutex.
 *
 * Reads are protected by RCU.
 *
 * There are a few special cases (mostly stats) that have their own
 * synchronization but they nest under all of above and don't interact with
 * each other.
 */

/* Global list of datapaths to enable dumping them all out.
 * Protected by genl_mutex.
 */
static LIST_HEAD(dps);

static struct vport *new_vport(const struct vport_parms *);
static int queue_userspace_packets(struct datapath *, struct sk_buff *,
				 const struct dp_upcall_info *);

/* Must be called with rcu_read_lock, genl_mutex, or RTNL lock. */
struct datapath *get_dp(int dp_ifindex)
{
	struct datapath *dp = NULL;
	struct net_device *dev;

	rcu_read_lock();
	dev = dev_get_by_index_rcu(&init_net, dp_ifindex);
	if (dev) {
		struct vport *vport = internal_dev_get_vport(dev);
		if (vport)
			dp = vport->dp;
	}
	rcu_read_unlock();

	return dp;
}
EXPORT_SYMBOL_GPL(get_dp);

/* Must be called with genl_mutex. */
static struct flow_table *get_table_protected(struct datapath *dp)
{
	return rcu_dereference_protected(dp->table, lockdep_genl_is_held());
}

/* Must be called with rcu_read_lock or RTNL lock. */
static struct vport *get_vport_protected(struct datapath *dp, u16 port_no)
{
	return rcu_dereference_rtnl(dp->ports[port_no]);
}

/* Must be called with rcu_read_lock or RTNL lock. */
const char *dp_name(const struct datapath *dp)
{
	return vport_get_name(rcu_dereference_rtnl(dp->ports[OVSP_LOCAL]));
}

static int get_dpifindex(struct datapath *dp)
{
	struct vport *local;
	int ifindex;

	rcu_read_lock();

	local = get_vport_protected(dp, OVSP_LOCAL);
	if (local)
		ifindex = vport_get_ifindex(local);
	else
		ifindex = 0;

	rcu_read_unlock();

	return ifindex;
}

static inline size_t br_nlmsg_size(void)
{
	return NLMSG_ALIGN(sizeof(struct ifinfomsg))
	       + nla_total_size(IFNAMSIZ) /* IFLA_IFNAME */
	       + nla_total_size(MAX_ADDR_LEN) /* IFLA_ADDRESS */
	       + nla_total_size(4) /* IFLA_MASTER */
	       + nla_total_size(4) /* IFLA_MTU */
	       + nla_total_size(1); /* IFLA_OPERSTATE */
}

/* Caller must hold RTNL lock. */
static int dp_fill_ifinfo(struct sk_buff *skb,
			  const struct vport *port,
			  int event, unsigned int flags)
{
	struct datapath *dp = port->dp;
	int ifindex = vport_get_ifindex(port);
	struct ifinfomsg *hdr;
	struct nlmsghdr *nlh;

	if (ifindex < 0)
		return ifindex;

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
	NLA_PUT_U32(skb, IFLA_MASTER, get_dpifindex(dp));
	NLA_PUT_U32(skb, IFLA_MTU, vport_get_mtu(port));
#ifdef IFLA_OPERSTATE
	NLA_PUT_U8(skb, IFLA_OPERSTATE,
		   vport_is_running(port)
			? vport_get_operstate(port)
			: IF_OPER_DOWN);
#endif

	NLA_PUT(skb, IFLA_ADDRESS, ETH_ALEN, vport_get_addr(port));

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Caller must hold RTNL lock. */
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

	flow_tbl_destroy(dp->table);
	free_percpu(dp->stats_percpu);
	kobject_put(&dp->ifobj);
}

/* Called with RTNL lock and genl_lock. */
static struct vport *new_vport(const struct vport_parms *parms)
{
	struct vport *vport;

	vport = vport_add(parms);
	if (!IS_ERR(vport)) {
		struct datapath *dp = parms->dp;

		rcu_assign_pointer(dp->ports[parms->port_no], vport);
		list_add(&vport->node, &dp->port_list);

		dp_ifinfo_notify(RTM_NEWLINK, vport);
	}

	return vport;
}

/* Called with RTNL lock. */
void dp_detach_port(struct vport *p)
{
	ASSERT_RTNL();

	if (p->port_no != OVSP_LOCAL)
		dp_sysfs_del_if(p);
	dp_ifinfo_notify(RTM_DELLINK, p);

	/* First drop references to device. */
	list_del(&p->node);
	rcu_assign_pointer(p->dp->ports[p->port_no], NULL);

	/* Then destroy it. */
	vport_del(p);
}

/* Must be called with rcu_read_lock. */
void dp_process_received_packet(struct vport *p, struct sk_buff *skb)
{
	struct datapath *dp = p->dp;
	struct sw_flow *flow;
	struct dp_stats_percpu *stats;
	u64 *stats_counter;
	int error;

	stats = per_cpu_ptr(dp->stats_percpu, smp_processor_id());
	OVS_CB(skb)->vport = p;

	if (!OVS_CB(skb)->flow) {
		struct sw_flow_key key;
		int key_len;
		bool is_frag;

		/* Extract flow from 'skb' into 'key'. */
		error = flow_extract(skb, p->port_no, &key, &key_len, &is_frag);
		if (unlikely(error)) {
			kfree_skb(skb);
			return;
		}

		if (is_frag && dp->drop_frags) {
			consume_skb(skb);
			stats_counter = &stats->n_frags;
			goto out;
		}

		/* Look up flow. */
		flow = flow_tbl_lookup(rcu_dereference(dp->table), &key, key_len);
		if (unlikely(!flow)) {
			struct dp_upcall_info upcall;

			upcall.cmd = OVS_PACKET_CMD_MISS;
			upcall.key = &key;
			upcall.userdata = NULL;
			upcall.pid = p->upcall_pid;
			dp_upcall(dp, skb, &upcall);
			kfree_skb(skb);
			stats_counter = &stats->n_missed;
			goto out;
		}

		OVS_CB(skb)->flow = flow;
	}

	stats_counter = &stats->n_hit;
	flow_used(OVS_CB(skb)->flow, skb);
	execute_actions(dp, skb);

out:
	/* Update datapath statistics. */

	write_seqcount_begin(&stats->seqlock);
	(*stats_counter)++;
	write_seqcount_end(&stats->seqlock);
}

static void copy_and_csum_skb(struct sk_buff *skb, void *to)
{
	u16 csum_start, csum_offset;
	__wsum csum;

	get_skb_csum_pointers(skb, &csum_start, &csum_offset);
	csum_start -= skb_headroom(skb);

	skb_copy_bits(skb, 0, to, csum_start);

	csum = skb_copy_and_csum_bits(skb, csum_start, to + csum_start,
				      skb->len - csum_start, 0);
	*(__sum16 *)(to + csum_start + csum_offset) = csum_fold(csum);
}

static struct genl_family dp_packet_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_PACKET_FAMILY,
	.version = 1,
	.maxattr = OVS_PACKET_ATTR_MAX
};

int dp_upcall(struct datapath *dp, struct sk_buff *skb,
	      const struct dp_upcall_info *upcall_info)
{
	struct sk_buff *segs = NULL;
	struct dp_stats_percpu *stats;
	int err;

	if (upcall_info->pid == 0) {
		err = -ENOTCONN;
		goto err;
	}

	forward_ip_summed(skb, true);

	/* Break apart GSO packets into their component pieces.  Otherwise
	 * userspace may try to stuff a 64kB packet into a 1500-byte MTU. */
	if (skb_is_gso(skb)) {
		segs = skb_gso_segment(skb, NETIF_F_SG | NETIF_F_HW_CSUM);
		
		if (IS_ERR(segs)) {
			err = PTR_ERR(segs);
			goto err;
		}
		skb = segs;
	}

	err = queue_userspace_packets(dp, skb, upcall_info);
	if (segs) {
		struct sk_buff *next;
		/* Free GSO-segments */
		do {
			next = segs->next;
			kfree_skb(segs);
		} while ((segs = next) != NULL);
	}

	if (err)
		goto err;

	return 0;

err:
	stats = per_cpu_ptr(dp->stats_percpu, smp_processor_id());

	write_seqcount_begin(&stats->seqlock);
	stats->n_lost++;
	write_seqcount_end(&stats->seqlock);

	return err;
}

/* Send each packet in the 'skb' list to userspace for 'dp' as directed by
 * 'upcall_info'.  There will be only one packet unless we broke up a GSO
 * packet.
 */
static int queue_userspace_packets(struct datapath *dp, struct sk_buff *skb,
				   const struct dp_upcall_info *upcall_info)
{
	int dp_ifindex;

	dp_ifindex = get_dpifindex(dp);
	if (!dp_ifindex)
		return -ENODEV;

	do {
		struct ovs_header *upcall;
		struct sk_buff *user_skb; /* to be queued to userspace */
		struct nlattr *nla;
		unsigned int len;
		int err;

		err = vlan_deaccel_tag(skb);
		if (unlikely(err))
			return err;

		if (nla_attr_size(skb->len) > USHRT_MAX)
			return -EFBIG;

		len = sizeof(struct ovs_header);
		len += nla_total_size(skb->len);
		len += nla_total_size(FLOW_BUFSIZE);
		if (upcall_info->cmd == OVS_PACKET_CMD_ACTION)
			len += nla_total_size(8);

		user_skb = genlmsg_new(len, GFP_ATOMIC);
		if (!user_skb)
			return -ENOMEM;

		upcall = genlmsg_put(user_skb, 0, 0, &dp_packet_genl_family,
					 0, upcall_info->cmd);
		upcall->dp_ifindex = dp_ifindex;

		nla = nla_nest_start(user_skb, OVS_PACKET_ATTR_KEY);
		flow_to_nlattrs(upcall_info->key, user_skb);
		nla_nest_end(user_skb, nla);

		if (upcall_info->userdata)
			nla_put_u64(user_skb, OVS_PACKET_ATTR_USERDATA,
				    nla_get_u64(upcall_info->userdata));

		nla = __nla_reserve(user_skb, OVS_PACKET_ATTR_PACKET, skb->len);
		if (skb->ip_summed == CHECKSUM_PARTIAL)
			copy_and_csum_skb(skb, nla_data(nla));
		else
			skb_copy_bits(skb, 0, nla_data(nla), skb->len);

		err = genlmsg_unicast(&init_net, user_skb, upcall_info->pid);
		if (err)
			return err;

	} while ((skb = skb->next));

	return 0;
}

/* Called with genl_mutex. */
static int flush_flows(int dp_ifindex)
{
	struct flow_table *old_table;
	struct flow_table *new_table;
	struct datapath *dp;

	dp = get_dp(dp_ifindex);
	if (!dp)
		return -ENODEV;

	old_table = get_table_protected(dp);
	new_table = flow_tbl_alloc(TBL_MIN_BUCKETS);
	if (!new_table)
		return -ENOMEM;

	rcu_assign_pointer(dp->table, new_table);

	flow_tbl_deferred_destroy(old_table);
	return 0;
}

static int validate_actions(const struct nlattr *attr, int depth);

static int validate_sample(const struct nlattr *attr, int depth)
{
	static const struct nla_policy sample_policy[OVS_SAMPLE_ATTR_MAX + 1] =
	{
		[OVS_SAMPLE_ATTR_PROBABILITY] = {.type = NLA_U32 },
		[OVS_SAMPLE_ATTR_ACTIONS] = {.type = NLA_UNSPEC },
	};
	struct nlattr *a[OVS_SAMPLE_ATTR_MAX + 1];
	int error;

	error = nla_parse_nested(a, OVS_SAMPLE_ATTR_MAX, attr, sample_policy);
	if (error)
		return error;

	if (!a[OVS_SAMPLE_ATTR_PROBABILITY])
		return -EINVAL;
	if (!a[OVS_SAMPLE_ATTR_ACTIONS])
		return -EINVAL;

	return validate_actions(a[OVS_SAMPLE_ATTR_ACTIONS], (depth + 1));
}

static int validate_userspace(const struct nlattr *attr)
{
	static const struct nla_policy userspace_policy[OVS_USERSPACE_ATTR_MAX + 1] =
	{
		[OVS_USERSPACE_ATTR_PID] = {.type = NLA_U32 },
		[OVS_USERSPACE_ATTR_USERDATA] = {.type = NLA_U64 },
	};
	struct nlattr *a[OVS_USERSPACE_ATTR_MAX + 1];
	int error;

	error = nla_parse_nested(a, OVS_USERSPACE_ATTR_MAX, attr, userspace_policy);
	if (error)
		return error;

	if (!a[OVS_USERSPACE_ATTR_PID] || !nla_get_u32(a[OVS_USERSPACE_ATTR_PID]))
		return -EINVAL;

	return 0;
}

static int validate_actions(const struct nlattr *attr, int depth)
{
	const struct nlattr *a;
	int rem, err;

	if (depth >= SAMPLE_ACTION_DEPTH)
		return -EOVERFLOW;

	nla_for_each_nested(a, attr, rem) {
		/* Expected argument lengths, (u32)-1 for variable length. */
		static const u32 action_lens[OVS_ACTION_ATTR_MAX + 1] = {
			[OVS_ACTION_ATTR_OUTPUT] = 4,
			[OVS_ACTION_ATTR_USERSPACE] = (u32)-1,
			[OVS_ACTION_ATTR_PUSH_VLAN] = 2,
			[OVS_ACTION_ATTR_POP_VLAN] = 0,
			[OVS_ACTION_ATTR_SET_DL_SRC] = ETH_ALEN,
			[OVS_ACTION_ATTR_SET_DL_DST] = ETH_ALEN,
			[OVS_ACTION_ATTR_SET_NW_SRC] = 4,
			[OVS_ACTION_ATTR_SET_NW_DST] = 4,
			[OVS_ACTION_ATTR_SET_NW_TOS] = 1,
			[OVS_ACTION_ATTR_SET_TP_SRC] = 2,
			[OVS_ACTION_ATTR_SET_TP_DST] = 2,
			[OVS_ACTION_ATTR_SET_TUNNEL] = 8,
			[OVS_ACTION_ATTR_SET_PRIORITY] = 4,
			[OVS_ACTION_ATTR_POP_PRIORITY] = 0,
			[OVS_ACTION_ATTR_SAMPLE] = (u32)-1
		};
		int type = nla_type(a);

		if (type > OVS_ACTION_ATTR_MAX ||
		    (action_lens[type] != nla_len(a) &&
		     action_lens[type] != (u32)-1))
			return -EINVAL;

		switch (type) {
		case OVS_ACTION_ATTR_UNSPEC:
			return -EINVAL;

		case OVS_ACTION_ATTR_POP_VLAN:
		case OVS_ACTION_ATTR_SET_DL_SRC:
		case OVS_ACTION_ATTR_SET_DL_DST:
		case OVS_ACTION_ATTR_SET_NW_SRC:
		case OVS_ACTION_ATTR_SET_NW_DST:
		case OVS_ACTION_ATTR_SET_TP_SRC:
		case OVS_ACTION_ATTR_SET_TP_DST:
		case OVS_ACTION_ATTR_SET_TUNNEL:
		case OVS_ACTION_ATTR_SET_PRIORITY:
		case OVS_ACTION_ATTR_POP_PRIORITY:
			/* No validation needed. */
			break;

		case OVS_ACTION_ATTR_USERSPACE:
			err = validate_userspace(a);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_OUTPUT:
			if (nla_get_u32(a) >= DP_MAX_PORTS)
				return -EINVAL;
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			if (nla_get_be16(a) & htons(VLAN_CFI_MASK))
				return -EINVAL;
			break;

		case OVS_ACTION_ATTR_SET_NW_TOS:
			if (nla_get_u8(a) & INET_ECN_MASK)
				return -EINVAL;
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			err = validate_sample(a, depth);
			if (err)
				return err;
			break;

		default:
			return -EOPNOTSUPP;
		}
	}

	if (rem > 0)
		return -EINVAL;

	return 0;
}
static void clear_stats(struct sw_flow *flow)
{
	flow->used = 0;
	flow->tcp_flags = 0;
	flow->packet_count = 0;
	flow->byte_count = 0;
}

static int ovs_packet_cmd_execute(struct sk_buff *skb, struct genl_info *info)
{
	struct ovs_header *ovs_header = info->userhdr;
	struct nlattr **a = info->attrs;
	struct sw_flow_actions *acts;
	struct sk_buff *packet;
	struct sw_flow *flow;
	struct datapath *dp;
	struct ethhdr *eth;
	bool is_frag;
	int len;
	int err;
	int key_len;

	err = -EINVAL;
	if (!a[OVS_PACKET_ATTR_PACKET] || !a[OVS_PACKET_ATTR_KEY] ||
	    !a[OVS_PACKET_ATTR_ACTIONS] ||
	    nla_len(a[OVS_PACKET_ATTR_PACKET]) < ETH_HLEN)
		goto err;

	err = validate_actions(a[OVS_PACKET_ATTR_ACTIONS], 0);
	if (err)
		goto err;

	len = nla_len(a[OVS_PACKET_ATTR_PACKET]);
	packet = __dev_alloc_skb(NET_IP_ALIGN + len, GFP_KERNEL);
	err = -ENOMEM;
	if (!packet)
		goto err;
	skb_reserve(packet, NET_IP_ALIGN);

	memcpy(__skb_put(packet, len), nla_data(a[OVS_PACKET_ATTR_PACKET]), len);

	skb_reset_mac_header(packet);
	eth = eth_hdr(packet);

	/* Normally, setting the skb 'protocol' field would be handled by a
	 * call to eth_type_trans(), but it assumes there's a sending
	 * device, which we may not have. */
	if (ntohs(eth->h_proto) >= 1536)
		packet->protocol = eth->h_proto;
	else
		packet->protocol = htons(ETH_P_802_2);

	/* Build an sw_flow for sending this packet. */
	flow = flow_alloc();
	err = PTR_ERR(flow);
	if (IS_ERR(flow))
		goto err_kfree_skb;

	err = flow_extract(packet, -1, &flow->key, &key_len, &is_frag);
	if (err)
		goto err_flow_put;

	err = flow_metadata_from_nlattrs(&flow->key.eth.in_port,
					 &flow->key.eth.tun_id,
					 a[OVS_PACKET_ATTR_KEY]);
	if (err)
		goto err_flow_put;

	flow->hash = flow_hash(&flow->key, key_len);

	acts = flow_actions_alloc(a[OVS_PACKET_ATTR_ACTIONS]);
	err = PTR_ERR(acts);
	if (IS_ERR(acts))
		goto err_flow_put;
	rcu_assign_pointer(flow->sf_acts, acts);

	OVS_CB(packet)->flow = flow;

	rcu_read_lock();
	dp = get_dp(ovs_header->dp_ifindex);
	err = -ENODEV;
	if (!dp)
		goto err_unlock;

	if (flow->key.eth.in_port < DP_MAX_PORTS)
		OVS_CB(packet)->vport = get_vport_protected(dp,
							flow->key.eth.in_port);

	local_bh_disable();
	err = execute_actions(dp, packet);
	local_bh_enable();
	rcu_read_unlock();

	flow_put(flow);
	return err;

err_unlock:
	rcu_read_unlock();
err_flow_put:
	flow_put(flow);
err_kfree_skb:
	kfree_skb(packet);
err:
	return err;
}

static const struct nla_policy packet_policy[OVS_PACKET_ATTR_MAX + 1] = {
	[OVS_PACKET_ATTR_PACKET] = { .type = NLA_UNSPEC },
	[OVS_PACKET_ATTR_KEY] = { .type = NLA_NESTED },
	[OVS_PACKET_ATTR_ACTIONS] = { .type = NLA_NESTED },
};

static struct genl_ops dp_packet_genl_ops[] = {
	{ .cmd = OVS_PACKET_CMD_EXECUTE,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = packet_policy,
	  .doit = ovs_packet_cmd_execute
	}
};

static void get_dp_stats(struct datapath *dp, struct ovs_dp_stats *stats)
{
	int i;
	struct flow_table *table = get_table_protected(dp);

	stats->n_flows = flow_tbl_count(table);

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

static const struct nla_policy flow_policy[OVS_FLOW_ATTR_MAX + 1] = {
	[OVS_FLOW_ATTR_KEY] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_ACTIONS] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_CLEAR] = { .type = NLA_FLAG },
};

static struct genl_family dp_flow_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_FLOW_FAMILY,
	.version = 1,
	.maxattr = OVS_FLOW_ATTR_MAX
};

static struct genl_multicast_group dp_flow_multicast_group = {
	.name = OVS_FLOW_MCGROUP
};

/* Called with genl_lock. */
static int ovs_flow_cmd_fill_info(struct sw_flow *flow, struct datapath *dp,
				  struct sk_buff *skb, u32 pid, u32 seq, u32 flags, u8 cmd)
{
	const int skb_orig_len = skb->len;
	const struct sw_flow_actions *sf_acts;
	struct ovs_flow_stats stats;
	struct ovs_header *ovs_header;
	struct nlattr *nla;
	unsigned long used;
	u8 tcp_flags;
	int err;

	sf_acts = rcu_dereference_protected(flow->sf_acts,
					    lockdep_genl_is_held());

	ovs_header = genlmsg_put(skb, pid, seq, &dp_flow_genl_family, flags, cmd);
	if (!ovs_header)
		return -EMSGSIZE;

	ovs_header->dp_ifindex = get_dpifindex(dp);

	nla = nla_nest_start(skb, OVS_FLOW_ATTR_KEY);
	if (!nla)
		goto nla_put_failure;
	err = flow_to_nlattrs(&flow->key, skb);
	if (err)
		goto error;
	nla_nest_end(skb, nla);

	spin_lock_bh(&flow->lock);
	used = flow->used;
	stats.n_packets = flow->packet_count;
	stats.n_bytes = flow->byte_count;
	tcp_flags = flow->tcp_flags;
	spin_unlock_bh(&flow->lock);

	if (used)
		NLA_PUT_U64(skb, OVS_FLOW_ATTR_USED, flow_used_time(used));

	if (stats.n_packets)
		NLA_PUT(skb, OVS_FLOW_ATTR_STATS, sizeof(struct ovs_flow_stats), &stats);

	if (tcp_flags)
		NLA_PUT_U8(skb, OVS_FLOW_ATTR_TCP_FLAGS, tcp_flags);

	/* If OVS_FLOW_ATTR_ACTIONS doesn't fit, skip dumping the actions if
	 * this is the first flow to be dumped into 'skb'.  This is unusual for
	 * Netlink but individual action lists can be longer than
	 * NLMSG_GOODSIZE and thus entirely undumpable if we didn't do this.
	 * The userspace caller can always fetch the actions separately if it
	 * really wants them.  (Most userspace callers in fact don't care.)
	 *
	 * This can only fail for dump operations because the skb is always
	 * properly sized for single flows.
	 */
	err = nla_put(skb, OVS_FLOW_ATTR_ACTIONS, sf_acts->actions_len,
		      sf_acts->actions);
	if (err < 0 && skb_orig_len)
		goto error;

	return genlmsg_end(skb, ovs_header);

nla_put_failure:
	err = -EMSGSIZE;
error:
	genlmsg_cancel(skb, ovs_header);
	return err;
}

static struct sk_buff *ovs_flow_cmd_alloc_info(struct sw_flow *flow)
{
	const struct sw_flow_actions *sf_acts;
	int len;

	sf_acts = rcu_dereference_protected(flow->sf_acts,
					    lockdep_genl_is_held());

	len = nla_total_size(FLOW_BUFSIZE); /* OVS_FLOW_ATTR_KEY */
	len += nla_total_size(sf_acts->actions_len); /* OVS_FLOW_ATTR_ACTIONS */
	len += nla_total_size(sizeof(struct ovs_flow_stats)); /* OVS_FLOW_ATTR_STATS */
	len += nla_total_size(1); /* OVS_FLOW_ATTR_TCP_FLAGS */
	len += nla_total_size(8); /* OVS_FLOW_ATTR_USED */
	return genlmsg_new(NLMSG_ALIGN(sizeof(struct ovs_header)) + len, GFP_KERNEL);
}

static struct sk_buff *ovs_flow_cmd_build_info(struct sw_flow *flow, struct datapath *dp,
					       u32 pid, u32 seq, u8 cmd)
{
	struct sk_buff *skb;
	int retval;

	skb = ovs_flow_cmd_alloc_info(flow);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	retval = ovs_flow_cmd_fill_info(flow, dp, skb, pid, seq, 0, cmd);
	BUG_ON(retval < 0);
	return skb;
}

static int ovs_flow_cmd_new_or_set(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow_key key;
	struct sw_flow *flow;
	struct sk_buff *reply;
	struct datapath *dp;
	struct flow_table *table;
	int error;
	int key_len;

	/* Extract key. */
	error = -EINVAL;
	if (!a[OVS_FLOW_ATTR_KEY])
		goto error;
	error = flow_from_nlattrs(&key, &key_len, a[OVS_FLOW_ATTR_KEY]);
	if (error)
		goto error;

	/* Validate actions. */
	if (a[OVS_FLOW_ATTR_ACTIONS]) {
		error = validate_actions(a[OVS_FLOW_ATTR_ACTIONS], 0);
		if (error)
			goto error;
	} else if (info->genlhdr->cmd == OVS_FLOW_CMD_NEW) {
		error = -EINVAL;
		goto error;
	}

	dp = get_dp(ovs_header->dp_ifindex);
	error = -ENODEV;
	if (!dp)
		goto error;

	table = get_table_protected(dp);
	flow = flow_tbl_lookup(table, &key, key_len);
	if (!flow) {
		struct sw_flow_actions *acts;

		/* Bail out if we're not allowed to create a new flow. */
		error = -ENOENT;
		if (info->genlhdr->cmd == OVS_FLOW_CMD_SET)
			goto error;

		/* Expand table, if necessary, to make room. */
		if (flow_tbl_need_to_expand(table)) {
			struct flow_table *new_table;

			new_table = flow_tbl_expand(table);
			if (!IS_ERR(new_table)) {
				rcu_assign_pointer(dp->table, new_table);
				flow_tbl_deferred_destroy(table);
				table = get_table_protected(dp);
			}
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
		acts = flow_actions_alloc(a[OVS_FLOW_ATTR_ACTIONS]);
		error = PTR_ERR(acts);
		if (IS_ERR(acts))
			goto error_free_flow;
		rcu_assign_pointer(flow->sf_acts, acts);

		/* Put flow in bucket. */
		flow->hash = flow_hash(&key, key_len);
		flow_tbl_insert(table, flow);

		reply = ovs_flow_cmd_build_info(flow, dp, info->snd_pid,
						info->snd_seq, OVS_FLOW_CMD_NEW);
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
		if (info->genlhdr->cmd == OVS_FLOW_CMD_NEW &&
		    info->nlhdr->nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL))
			goto error;

		/* Update actions. */
		old_acts = rcu_dereference_protected(flow->sf_acts,
						     lockdep_genl_is_held());
		if (a[OVS_FLOW_ATTR_ACTIONS] &&
		    (old_acts->actions_len != nla_len(a[OVS_FLOW_ATTR_ACTIONS]) ||
		     memcmp(old_acts->actions, nla_data(a[OVS_FLOW_ATTR_ACTIONS]),
			    old_acts->actions_len))) {
			struct sw_flow_actions *new_acts;

			new_acts = flow_actions_alloc(a[OVS_FLOW_ATTR_ACTIONS]);
			error = PTR_ERR(new_acts);
			if (IS_ERR(new_acts))
				goto error;

			rcu_assign_pointer(flow->sf_acts, new_acts);
			flow_deferred_free_acts(old_acts);
		}

		reply = ovs_flow_cmd_build_info(flow, dp, info->snd_pid,
						info->snd_seq, OVS_FLOW_CMD_NEW);

		/* Clear stats. */
		if (a[OVS_FLOW_ATTR_CLEAR]) {
			spin_lock_bh(&flow->lock);
			clear_stats(flow);
			spin_unlock_bh(&flow->lock);
		}
	}

	if (!IS_ERR(reply))
		genl_notify(reply, genl_info_net(info), info->snd_pid,
			    dp_flow_multicast_group.id, info->nlhdr, GFP_KERNEL);
	else
		netlink_set_err(INIT_NET_GENL_SOCK, 0,
				dp_flow_multicast_group.id, PTR_ERR(reply));
	return 0;

error_free_flow:
	flow_put(flow);
error:
	return error;
}

static int ovs_flow_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow_key key;
	struct sk_buff *reply;
	struct sw_flow *flow;
	struct datapath *dp;
	struct flow_table *table;
	int err;
	int key_len;

	if (!a[OVS_FLOW_ATTR_KEY])
		return -EINVAL;
	err = flow_from_nlattrs(&key, &key_len, a[OVS_FLOW_ATTR_KEY]);
	if (err)
		return err;

	dp = get_dp(ovs_header->dp_ifindex);
	if (!dp)
		return -ENODEV;

	table = get_table_protected(dp);
	flow = flow_tbl_lookup(table, &key, key_len);
	if (!flow)
		return -ENOENT;

	reply = ovs_flow_cmd_build_info(flow, dp, info->snd_pid, info->snd_seq, OVS_FLOW_CMD_NEW);
	if (IS_ERR(reply))
		return PTR_ERR(reply);

	return genlmsg_reply(reply, info);
}

static int ovs_flow_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow_key key;
	struct sk_buff *reply;
	struct sw_flow *flow;
	struct datapath *dp;
	struct flow_table *table;
	int err;
	int key_len;

	if (!a[OVS_FLOW_ATTR_KEY])
		return flush_flows(ovs_header->dp_ifindex);
	err = flow_from_nlattrs(&key, &key_len, a[OVS_FLOW_ATTR_KEY]);
	if (err)
		return err;

	dp = get_dp(ovs_header->dp_ifindex);
	if (!dp)
 		return -ENODEV;

	table = get_table_protected(dp);
	flow = flow_tbl_lookup(table, &key, key_len);
	if (!flow)
		return -ENOENT;

	reply = ovs_flow_cmd_alloc_info(flow);
	if (!reply)
		return -ENOMEM;

	flow_tbl_remove(table, flow);

	err = ovs_flow_cmd_fill_info(flow, dp, reply, info->snd_pid,
				     info->snd_seq, 0, OVS_FLOW_CMD_DEL);
	BUG_ON(err < 0);

	flow_deferred_free(flow);

	genl_notify(reply, genl_info_net(info), info->snd_pid,
		    dp_flow_multicast_group.id, info->nlhdr, GFP_KERNEL);
	return 0;
}

static int ovs_flow_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ovs_header *ovs_header = genlmsg_data(nlmsg_data(cb->nlh));
	struct datapath *dp;

	dp = get_dp(ovs_header->dp_ifindex);
	if (!dp)
		return -ENODEV;

	for (;;) {
		struct sw_flow *flow;
		u32 bucket, obj;

		bucket = cb->args[0];
		obj = cb->args[1];
		flow = flow_tbl_next(get_table_protected(dp), &bucket, &obj);
		if (!flow)
			break;

		if (ovs_flow_cmd_fill_info(flow, dp, skb, NETLINK_CB(cb->skb).pid,
					   cb->nlh->nlmsg_seq, NLM_F_MULTI,
					   OVS_FLOW_CMD_NEW) < 0)
			break;

		cb->args[0] = bucket;
		cb->args[1] = obj;
	}
	return skb->len;
}

static struct genl_ops dp_flow_genl_ops[] = {
	{ .cmd = OVS_FLOW_CMD_NEW,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_new_or_set
	},
	{ .cmd = OVS_FLOW_CMD_DEL,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_del
	},
	{ .cmd = OVS_FLOW_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_get,
	  .dumpit = ovs_flow_cmd_dump
	},
	{ .cmd = OVS_FLOW_CMD_SET,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_new_or_set,
	},
};

static const struct nla_policy datapath_policy[OVS_DP_ATTR_MAX + 1] = {
#ifdef HAVE_NLA_NUL_STRING
	[OVS_DP_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
#endif
	[OVS_DP_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_DP_ATTR_IPV4_FRAGS] = { .type = NLA_U32 },
};

static struct genl_family dp_datapath_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_DATAPATH_FAMILY,
	.version = 1,
	.maxattr = OVS_DP_ATTR_MAX
};

static struct genl_multicast_group dp_datapath_multicast_group = {
	.name = OVS_DATAPATH_MCGROUP
};

static int ovs_dp_cmd_fill_info(struct datapath *dp, struct sk_buff *skb,
				u32 pid, u32 seq, u32 flags, u8 cmd)
{
	struct ovs_header *ovs_header;
	struct nlattr *nla;
	int err;

	ovs_header = genlmsg_put(skb, pid, seq, &dp_datapath_genl_family,
				   flags, cmd);
	if (!ovs_header)
		goto error;

	ovs_header->dp_ifindex = get_dpifindex(dp);

	rcu_read_lock();
	err = nla_put_string(skb, OVS_DP_ATTR_NAME, dp_name(dp));
	rcu_read_unlock();
	if (err)
		goto nla_put_failure;

	nla = nla_reserve(skb, OVS_DP_ATTR_STATS, sizeof(struct ovs_dp_stats));
	if (!nla)
		goto nla_put_failure;
	get_dp_stats(dp, nla_data(nla));

	NLA_PUT_U32(skb, OVS_DP_ATTR_IPV4_FRAGS,
		    dp->drop_frags ? OVS_DP_FRAG_DROP : OVS_DP_FRAG_ZERO);

	return genlmsg_end(skb, ovs_header);

nla_put_failure:
	genlmsg_cancel(skb, ovs_header);
error:
	return -EMSGSIZE;
}

static struct sk_buff *ovs_dp_cmd_build_info(struct datapath *dp, u32 pid,
					     u32 seq, u8 cmd)
{
	struct sk_buff *skb;
	int retval;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	retval = ovs_dp_cmd_fill_info(dp, skb, pid, seq, 0, cmd);
	if (retval < 0) {
		kfree_skb(skb);
		return ERR_PTR(retval);
	}
	return skb;
}

static int ovs_dp_cmd_validate(struct nlattr *a[OVS_DP_ATTR_MAX + 1])
{
	if (a[OVS_DP_ATTR_IPV4_FRAGS]) {
		u32 frags = nla_get_u32(a[OVS_DP_ATTR_IPV4_FRAGS]);

		if (frags != OVS_DP_FRAG_ZERO && frags != OVS_DP_FRAG_DROP)
			return -EINVAL;
	}

	return CHECK_NUL_STRING(a[OVS_DP_ATTR_NAME], IFNAMSIZ - 1);
}

/* Called with genl_mutex and optionally with RTNL lock also. */
static struct datapath *lookup_datapath(struct ovs_header *ovs_header, struct nlattr *a[OVS_DP_ATTR_MAX + 1])
{
	struct datapath *dp;

	if (!a[OVS_DP_ATTR_NAME])
		dp = get_dp(ovs_header->dp_ifindex);
	else {
		struct vport *vport;

		rcu_read_lock();
		vport = vport_locate(nla_data(a[OVS_DP_ATTR_NAME]));
		dp = vport && vport->port_no == OVSP_LOCAL ? vport->dp : NULL;
		rcu_read_unlock();
	}
	return dp ? dp : ERR_PTR(-ENODEV);
}

/* Called with genl_mutex. */
static void change_datapath(struct datapath *dp, struct nlattr *a[OVS_DP_ATTR_MAX + 1])
{
	if (a[OVS_DP_ATTR_IPV4_FRAGS])
		dp->drop_frags = nla_get_u32(a[OVS_DP_ATTR_IPV4_FRAGS]) == OVS_DP_FRAG_DROP;
}

static int ovs_dp_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct vport_parms parms;
	struct sk_buff *reply;
	struct datapath *dp;
	struct vport *vport;
	int err;

	err = -EINVAL;
	if (!a[OVS_DP_ATTR_NAME])
		goto err;

	err = ovs_dp_cmd_validate(a);
	if (err)
		goto err;

	rtnl_lock();
	err = -ENODEV;
	if (!try_module_get(THIS_MODULE))
		goto err_unlock_rtnl;

	err = -ENOMEM;
	dp = kzalloc(sizeof(*dp), GFP_KERNEL);
	if (dp == NULL)
		goto err_put_module;
	INIT_LIST_HEAD(&dp->port_list);

	/* Initialize kobject for bridge.  This will be added as
	 * /sys/class/net/<devname>/brif later, if sysfs is enabled. */
	dp->ifobj.kset = NULL;
	kobject_init(&dp->ifobj, &dp_ktype);

	/* Allocate table. */
	err = -ENOMEM;
	rcu_assign_pointer(dp->table, flow_tbl_alloc(TBL_MIN_BUCKETS));
	if (!dp->table)
		goto err_free_dp;

	dp->drop_frags = 0;
	dp->stats_percpu = alloc_percpu(struct dp_stats_percpu);
	if (!dp->stats_percpu) {
		err = -ENOMEM;
		goto err_destroy_table;
	}

	change_datapath(dp, a);

	/* Set up our datapath device. */
	parms.name = nla_data(a[OVS_DP_ATTR_NAME]);
	parms.type = OVS_VPORT_TYPE_INTERNAL;
	parms.options = NULL;
	parms.dp = dp;
	parms.port_no = OVSP_LOCAL;
	if (a[OVS_DP_ATTR_UPCALL_PID])
		parms.upcall_pid = nla_get_u32(a[OVS_DP_ATTR_UPCALL_PID]);
	else
		parms.upcall_pid = NETLINK_CB(skb).pid;

	vport = new_vport(&parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		if (err == -EBUSY)
			err = -EEXIST;

		goto err_destroy_percpu;
	}

	reply = ovs_dp_cmd_build_info(dp, info->snd_pid, info->snd_seq, OVS_DP_CMD_NEW);
	err = PTR_ERR(reply);
	if (IS_ERR(reply))
		goto err_destroy_local_port;

	list_add_tail(&dp->list_node, &dps);
	dp_sysfs_add_dp(dp);

	rtnl_unlock();

	genl_notify(reply, genl_info_net(info), info->snd_pid,
		    dp_datapath_multicast_group.id, info->nlhdr, GFP_KERNEL);
	return 0;

err_destroy_local_port:
	dp_detach_port(get_vport_protected(dp, OVSP_LOCAL));
err_destroy_percpu:
	free_percpu(dp->stats_percpu);
err_destroy_table:
	flow_tbl_destroy(get_table_protected(dp));
err_free_dp:
	kfree(dp);
err_put_module:
	module_put(THIS_MODULE);
err_unlock_rtnl:
	rtnl_unlock();
err:
	return err;
}

static int ovs_dp_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct vport *vport, *next_vport;
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	err = ovs_dp_cmd_validate(info->attrs);
	if (err)
		goto exit;

	rtnl_lock();
	dp = lookup_datapath(info->userhdr, info->attrs);
	err = PTR_ERR(dp);
	if (IS_ERR(dp))
		goto exit_unlock;

	reply = ovs_dp_cmd_build_info(dp, info->snd_pid, info->snd_seq, OVS_DP_CMD_DEL);
	err = PTR_ERR(reply);
	if (IS_ERR(reply))
		goto exit_unlock;

	list_for_each_entry_safe (vport, next_vport, &dp->port_list, node)
		if (vport->port_no != OVSP_LOCAL)
			dp_detach_port(vport);

	dp_sysfs_del_dp(dp);
	list_del(&dp->list_node);
	dp_detach_port(get_vport_protected(dp, OVSP_LOCAL));

	/* rtnl_unlock() will wait until all the references to devices that
	 * are pending unregistration have been dropped.  We do it here to
	 * ensure that any internal devices (which contain DP pointers) are
	 * fully destroyed before freeing the datapath.
	 */
	rtnl_unlock();

	call_rcu(&dp->rcu, destroy_dp_rcu);
	module_put(THIS_MODULE);

	genl_notify(reply, genl_info_net(info), info->snd_pid,
		    dp_datapath_multicast_group.id, info->nlhdr, GFP_KERNEL);

	return 0;

exit_unlock:
	rtnl_unlock();
exit:
	return err;
}

static int ovs_dp_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	err = ovs_dp_cmd_validate(info->attrs);
	if (err)
		return err;

	dp = lookup_datapath(info->userhdr, info->attrs);
	if (IS_ERR(dp))
		return PTR_ERR(dp);

	change_datapath(dp, info->attrs);

	reply = ovs_dp_cmd_build_info(dp, info->snd_pid, info->snd_seq, OVS_DP_CMD_NEW);
	if (IS_ERR(reply)) {
		err = PTR_ERR(reply);
		netlink_set_err(INIT_NET_GENL_SOCK, 0,
				dp_datapath_multicast_group.id, err);
		return 0;
	}

	genl_notify(reply, genl_info_net(info), info->snd_pid,
		    dp_datapath_multicast_group.id, info->nlhdr, GFP_KERNEL);
	return 0;
}

static int ovs_dp_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	err = ovs_dp_cmd_validate(info->attrs);
	if (err)
		return err;

	dp = lookup_datapath(info->userhdr, info->attrs);
	if (IS_ERR(dp))
		return PTR_ERR(dp);

	reply = ovs_dp_cmd_build_info(dp, info->snd_pid, info->snd_seq, OVS_DP_CMD_NEW);
	if (IS_ERR(reply))
		return PTR_ERR(reply);

	return genlmsg_reply(reply, info);
}

static int ovs_dp_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct datapath *dp;
	int skip = cb->args[0];
	int i = 0;

	list_for_each_entry (dp, &dps, list_node) {
		if (i < skip)
			continue;
		if (ovs_dp_cmd_fill_info(dp, skb, NETLINK_CB(cb->skb).pid,
					 cb->nlh->nlmsg_seq, NLM_F_MULTI,
					 OVS_DP_CMD_NEW) < 0)
			break;
		i++;
	}

	cb->args[0] = i;

	return skb->len;
}

static struct genl_ops dp_datapath_genl_ops[] = {
	{ .cmd = OVS_DP_CMD_NEW,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_new
	},
	{ .cmd = OVS_DP_CMD_DEL,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_del
	},
	{ .cmd = OVS_DP_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_get,
	  .dumpit = ovs_dp_cmd_dump
	},
	{ .cmd = OVS_DP_CMD_SET,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_set,
	},
};

static const struct nla_policy vport_policy[OVS_VPORT_ATTR_MAX + 1] = {
#ifdef HAVE_NLA_NUL_STRING
	[OVS_VPORT_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[OVS_VPORT_ATTR_STATS] = { .len = sizeof(struct ovs_vport_stats) },
	[OVS_VPORT_ATTR_ADDRESS] = { .len = ETH_ALEN },
#else
	[OVS_VPORT_ATTR_STATS] = { .minlen = sizeof(struct ovs_vport_stats) },
	[OVS_VPORT_ATTR_ADDRESS] = { .minlen = ETH_ALEN },
#endif
	[OVS_VPORT_ATTR_PORT_NO] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_TYPE] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_OPTIONS] = { .type = NLA_NESTED },
};

static struct genl_family dp_vport_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_VPORT_FAMILY,
	.version = 1,
	.maxattr = OVS_VPORT_ATTR_MAX
};

struct genl_multicast_group dp_vport_multicast_group = {
	.name = OVS_VPORT_MCGROUP
};

/* Called with RTNL lock or RCU read lock. */
static int ovs_vport_cmd_fill_info(struct vport *vport, struct sk_buff *skb,
				   u32 pid, u32 seq, u32 flags, u8 cmd)
{
	struct ovs_header *ovs_header;
	struct nlattr *nla;
	int err;

	ovs_header = genlmsg_put(skb, pid, seq, &dp_vport_genl_family,
				 flags, cmd);
	if (!ovs_header)
		return -EMSGSIZE;

	ovs_header->dp_ifindex = get_dpifindex(vport->dp);

	NLA_PUT_U32(skb, OVS_VPORT_ATTR_PORT_NO, vport->port_no);
	NLA_PUT_U32(skb, OVS_VPORT_ATTR_TYPE, vport_get_type(vport));
	NLA_PUT_STRING(skb, OVS_VPORT_ATTR_NAME, vport_get_name(vport));
	NLA_PUT_U32(skb, OVS_VPORT_ATTR_UPCALL_PID, vport->upcall_pid);

	nla = nla_reserve(skb, OVS_VPORT_ATTR_STATS, sizeof(struct ovs_vport_stats));
	if (!nla)
		goto nla_put_failure;

	vport_get_stats(vport, nla_data(nla));

	NLA_PUT(skb, OVS_VPORT_ATTR_ADDRESS, ETH_ALEN, vport_get_addr(vport));

	err = vport_get_options(vport, skb);
	if (err == -EMSGSIZE)
		goto error;

	return genlmsg_end(skb, ovs_header);

nla_put_failure:
	err = -EMSGSIZE;
error:
	genlmsg_cancel(skb, ovs_header);
	return err;
}

/* Called with RTNL lock or RCU read lock. */
struct sk_buff *ovs_vport_cmd_build_info(struct vport *vport, u32 pid,
					 u32 seq, u8 cmd)
{
	struct sk_buff *skb;
	int retval;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	retval = ovs_vport_cmd_fill_info(vport, skb, pid, seq, 0, cmd);
	if (retval < 0) {
		kfree_skb(skb);
		return ERR_PTR(retval);
	}
	return skb;
}

static int ovs_vport_cmd_validate(struct nlattr *a[OVS_VPORT_ATTR_MAX + 1])
{
	return CHECK_NUL_STRING(a[OVS_VPORT_ATTR_NAME], IFNAMSIZ - 1);
}

/* Called with RTNL lock or RCU read lock. */
static struct vport *lookup_vport(struct ovs_header *ovs_header,
				  struct nlattr *a[OVS_VPORT_ATTR_MAX + 1])
{
	struct datapath *dp;
	struct vport *vport;

	if (a[OVS_VPORT_ATTR_NAME]) {
		vport = vport_locate(nla_data(a[OVS_VPORT_ATTR_NAME]));
		if (!vport)
			return ERR_PTR(-ENODEV);
		return vport;
	} else if (a[OVS_VPORT_ATTR_PORT_NO]) {
		u32 port_no = nla_get_u32(a[OVS_VPORT_ATTR_PORT_NO]);

		if (port_no >= DP_MAX_PORTS)
			return ERR_PTR(-EFBIG);

		dp = get_dp(ovs_header->dp_ifindex);
		if (!dp)
			return ERR_PTR(-ENODEV);

		vport = get_vport_protected(dp, port_no);
		if (!vport)
			return ERR_PTR(-ENOENT);
		return vport;
	} else
		return ERR_PTR(-EINVAL);
}

/* Called with RTNL lock. */
static int change_vport(struct vport *vport, struct nlattr *a[OVS_VPORT_ATTR_MAX + 1])
{
	int err = 0;

	if (a[OVS_VPORT_ATTR_STATS])
		vport_set_stats(vport, nla_data(a[OVS_VPORT_ATTR_STATS]));

	if (a[OVS_VPORT_ATTR_ADDRESS])
		err = vport_set_addr(vport, nla_data(a[OVS_VPORT_ATTR_ADDRESS]));

	return err;
}

static int ovs_vport_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct vport_parms parms;
	struct sk_buff *reply;
	struct vport *vport;
	struct datapath *dp;
	u32 port_no;
	int err;

	err = -EINVAL;
	if (!a[OVS_VPORT_ATTR_NAME] || !a[OVS_VPORT_ATTR_TYPE])
		goto exit;

	err = ovs_vport_cmd_validate(a);
	if (err)
		goto exit;

	rtnl_lock();
	dp = get_dp(ovs_header->dp_ifindex);
	err = -ENODEV;
	if (!dp)
		goto exit_unlock;

	if (a[OVS_VPORT_ATTR_PORT_NO]) {
		port_no = nla_get_u32(a[OVS_VPORT_ATTR_PORT_NO]);

		err = -EFBIG;
		if (port_no >= DP_MAX_PORTS)
			goto exit_unlock;

		vport = get_vport_protected(dp, port_no);
		err = -EBUSY;
		if (vport)
			goto exit_unlock;
	} else {
		for (port_no = 1; ; port_no++) {
			if (port_no >= DP_MAX_PORTS) {
				err = -EFBIG;
				goto exit_unlock;
			}
			vport = get_vport_protected(dp, port_no);
			if (!vport)
				break;
		}
	}

	parms.name = nla_data(a[OVS_VPORT_ATTR_NAME]);
	parms.type = nla_get_u32(a[OVS_VPORT_ATTR_TYPE]);
	parms.options = a[OVS_VPORT_ATTR_OPTIONS];
	parms.dp = dp;
	parms.port_no = port_no;
	if (a[OVS_VPORT_ATTR_UPCALL_PID])
		parms.upcall_pid = nla_get_u32(a[OVS_VPORT_ATTR_UPCALL_PID]);
	else
		parms.upcall_pid = NETLINK_CB(skb).pid;

	vport = new_vport(&parms);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock;

 	dp_sysfs_add_if(vport);

	err = change_vport(vport, a);
	if (!err) {
		reply = ovs_vport_cmd_build_info(vport, info->snd_pid,
						 info->snd_seq, OVS_VPORT_CMD_NEW);
		if (IS_ERR(reply))
			err = PTR_ERR(reply);
	}
	if (err) {
		dp_detach_port(vport);
		goto exit_unlock;
	}
	genl_notify(reply, genl_info_net(info), info->snd_pid,
		    dp_vport_multicast_group.id, info->nlhdr, GFP_KERNEL);


exit_unlock:
	rtnl_unlock();
exit:
	return err;
}

static int ovs_vport_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct sk_buff *reply;
	struct vport *vport;
	int err;

	err = ovs_vport_cmd_validate(a);
	if (err)
		goto exit;

	rtnl_lock();
	vport = lookup_vport(info->userhdr, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock;

	err = 0;
	if (a[OVS_VPORT_ATTR_OPTIONS])
		err = vport_set_options(vport, a[OVS_VPORT_ATTR_OPTIONS]);
	if (!err)
		err = change_vport(vport, a);
	if (!err && a[OVS_VPORT_ATTR_UPCALL_PID])
		vport->upcall_pid = nla_get_u32(a[OVS_VPORT_ATTR_UPCALL_PID]);

	reply = ovs_vport_cmd_build_info(vport, info->snd_pid, info->snd_seq,
					 OVS_VPORT_CMD_NEW);
	if (IS_ERR(reply)) {
		err = PTR_ERR(reply);
		netlink_set_err(INIT_NET_GENL_SOCK, 0,
				dp_vport_multicast_group.id, err);
		return 0;
	}

	genl_notify(reply, genl_info_net(info), info->snd_pid,
		    dp_vport_multicast_group.id, info->nlhdr, GFP_KERNEL);

exit_unlock:
	rtnl_unlock();
exit:
	return err;
}

static int ovs_vport_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct sk_buff *reply;
	struct vport *vport;
	int err;

	err = ovs_vport_cmd_validate(a);
	if (err)
		goto exit;

	rtnl_lock();
	vport = lookup_vport(info->userhdr, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock;

	if (vport->port_no == OVSP_LOCAL) {
		err = -EINVAL;
		goto exit_unlock;
	}

	reply = ovs_vport_cmd_build_info(vport, info->snd_pid, info->snd_seq,
					 OVS_VPORT_CMD_DEL);
	err = PTR_ERR(reply);
	if (IS_ERR(reply))
		goto exit_unlock;

	dp_detach_port(vport);

	genl_notify(reply, genl_info_net(info), info->snd_pid,
		    dp_vport_multicast_group.id, info->nlhdr, GFP_KERNEL);

exit_unlock:
	rtnl_unlock();
exit:
	return err;
}

static int ovs_vport_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct vport *vport;
	int err;

	err = ovs_vport_cmd_validate(a);
	if (err)
		goto exit;

	rcu_read_lock();
	vport = lookup_vport(ovs_header, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock;

	reply = ovs_vport_cmd_build_info(vport, info->snd_pid, info->snd_seq,
					 OVS_VPORT_CMD_NEW);
	err = PTR_ERR(reply);
	if (IS_ERR(reply))
		goto exit_unlock;

	rcu_read_unlock();

	return genlmsg_reply(reply, info);

exit_unlock:
	rcu_read_unlock();
exit:
	return err;
}

static int ovs_vport_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ovs_header *ovs_header = genlmsg_data(nlmsg_data(cb->nlh));
	struct datapath *dp;
	u32 port_no;
	int retval;

	dp = get_dp(ovs_header->dp_ifindex);
	if (!dp)
		return -ENODEV;

	rcu_read_lock();
	for (port_no = cb->args[0]; port_no < DP_MAX_PORTS; port_no++) {
		struct vport *vport;

		vport = get_vport_protected(dp, port_no);
		if (!vport)
			continue;

		if (ovs_vport_cmd_fill_info(vport, skb, NETLINK_CB(cb->skb).pid,
					    cb->nlh->nlmsg_seq, NLM_F_MULTI,
					    OVS_VPORT_CMD_NEW) < 0)
			break;
	}
	rcu_read_unlock();

	cb->args[0] = port_no;
	retval = skb->len;

	return retval;
}

static struct genl_ops dp_vport_genl_ops[] = {
	{ .cmd = OVS_VPORT_CMD_NEW,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_new
	},
	{ .cmd = OVS_VPORT_CMD_DEL,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_del
	},
	{ .cmd = OVS_VPORT_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_get,
	  .dumpit = ovs_vport_cmd_dump
	},
	{ .cmd = OVS_VPORT_CMD_SET,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_set,
	},
};

struct genl_family_and_ops {
	struct genl_family *family;
	struct genl_ops *ops;
	int n_ops;
	struct genl_multicast_group *group;
};

static const struct genl_family_and_ops dp_genl_families[] = {
	{ &dp_datapath_genl_family,
	  dp_datapath_genl_ops, ARRAY_SIZE(dp_datapath_genl_ops),
	  &dp_datapath_multicast_group },
	{ &dp_vport_genl_family,
	  dp_vport_genl_ops, ARRAY_SIZE(dp_vport_genl_ops),
	  &dp_vport_multicast_group },
	{ &dp_flow_genl_family,
	  dp_flow_genl_ops, ARRAY_SIZE(dp_flow_genl_ops),
	  &dp_flow_multicast_group },
	{ &dp_packet_genl_family,
	  dp_packet_genl_ops, ARRAY_SIZE(dp_packet_genl_ops),
	  NULL },
};

static void dp_unregister_genl(int n_families)
{
	int i;

	for (i = 0; i < n_families; i++)
		genl_unregister_family(dp_genl_families[i].family);
}

static int dp_register_genl(void)
{
	int n_registered;
	int err;
	int i;

	n_registered = 0;
	for (i = 0; i < ARRAY_SIZE(dp_genl_families); i++) {
		const struct genl_family_and_ops *f = &dp_genl_families[i];

		err = genl_register_family_with_ops(f->family, f->ops,
						    f->n_ops);
		if (err)
			goto error;
		n_registered++;

		if (f->group) {
			err = genl_register_mc_group(f->family, f->group);
			if (err)
				goto error;
		}
	}

	return 0;

error:
	dp_unregister_genl(n_registered);
	return err;
}

static int __init dp_init(void)
{
	struct sk_buff *dummy_skb;
	int err;

	BUILD_BUG_ON(sizeof(struct ovs_skb_cb) > sizeof(dummy_skb->cb));

	printk("Open vSwitch %s, built "__DATE__" "__TIME__"\n", VERSION BUILDNR);

	err = tnl_init();
	if (err)
		goto error;

	err = flow_init();
	if (err)
		goto error_tnl_exit;

	err = vport_init();
	if (err)
		goto error_flow_exit;

	err = register_netdevice_notifier(&dp_device_notifier);
	if (err)
		goto error_vport_exit;

	err = dp_register_genl();
	if (err < 0)
		goto error_unreg_notifier;

	return 0;

error_unreg_notifier:
	unregister_netdevice_notifier(&dp_device_notifier);
error_vport_exit:
	vport_exit();
error_flow_exit:
	flow_exit();
error_tnl_exit:
	tnl_exit();
error:
	return err;
}

static void dp_cleanup(void)
{
	rcu_barrier();
	dp_unregister_genl(ARRAY_SIZE(dp_genl_families));
	unregister_netdevice_notifier(&dp_device_notifier);
	vport_exit();
	flow_exit();
	tnl_exit();
}

module_init(dp_init);
module_exit(dp_cleanup);

MODULE_DESCRIPTION("Open vSwitch switching datapath");
MODULE_LICENSE("GPL");
