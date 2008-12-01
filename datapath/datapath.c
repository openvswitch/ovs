/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008 The Board of Trustees of The Leland 
 * Stanford Junior University
 */

/* Functions for managing the dp interface/device. */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <net/genetlink.h>
#include <linux/ip.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/rtnetlink.h>
#include <linux/rcupdate.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/random.h>
#include <asm/system.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/workqueue.h>
#include <linux/dmi.h>

#include "openflow/nicira-ext.h"
#include "openflow/openflow-netlink.h"
#include "datapath.h"
#include "nx_act_snat.h"
#include "table.h"
#include "chain.h"
#include "dp_dev.h"
#include "forward.h"
#include "flow.h"

#include "compat.h"


/* Strings to describe the manufacturer, hardware, and software.  This data 
 * is queriable through the switch description stats message. */
static char mfr_desc[DESC_STR_LEN] = "Nicira Networks, Inc.";
static char hw_desc[DESC_STR_LEN] = "Reference Linux Kernel Module";
static char sw_desc[DESC_STR_LEN] = VERSION BUILDNR;
static char serial_num[SERIAL_NUM_LEN] = "None";

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
module_param_string(mfr_desc, mfr_desc, sizeof mfr_desc, 0444);
module_param_string(hw_desc, hw_desc, sizeof hw_desc, 0444);
module_param_string(sw_desc, sw_desc, sizeof sw_desc, 0444);
module_param_string(serial_num, serial_num, sizeof serial_num, 0444);
#else
MODULE_PARM(mfr_desc, "s");
MODULE_PARM(hw_desc, "s");
MODULE_PARM(sw_desc, "s");
MODULE_PARM(serial_num, "s");
#endif


/* Number of milliseconds between runs of the maintenance thread. */
#define MAINT_SLEEP_MSECS 1000

#define UINT32_MAX			  4294967295U
#define UINT16_MAX			  65535
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))

static struct genl_family dp_genl_family;
static struct genl_multicast_group mc_group;

/* It's hard to imagine wanting more than one datapath, but... */
#define DP_MAX 32

/* Datapaths.  Protected on the read side by rcu_read_lock, on the write side
 * by dp_mutex.  dp_mutex is almost completely redundant with genl_mutex
 * maintained by the Generic Netlink code, but the timeout path needs mutual
 * exclusion too.
 *
 * It is safe to access the datapath and net_bridge_port structures with just
 * dp_mutex.
 */
static struct datapath *dps[DP_MAX];
DEFINE_MUTEX(dp_mutex);
EXPORT_SYMBOL(dp_mutex);

static int dp_maint_func(void *data);
static void init_port_status(struct net_bridge_port *p);
static int dp_genl_openflow_done(struct netlink_callback *);
static struct net_bridge_port *new_nbp(struct datapath *,
				       struct net_device *, int port_no);

/* nla_shrink - reduce amount of space reserved by nla_reserve
 * @skb: socket buffer from which to recover room
 * @nla: netlink attribute to adjust
 * @len: new length of attribute payload
 *
 * Reduces amount of space reserved by a call to nla_reserve.
 *
 * No other attributes may be added between calling nla_reserve and this
 * function, since it will create a hole in the message.
 */
void nla_shrink(struct sk_buff *skb, struct nlattr *nla, int len)
{
	int delta = nla_total_size(len) - nla_total_size(nla_len(nla));
	BUG_ON(delta > 0);
	skb->tail += delta;
	skb->len  += delta;
	nla->nla_len = nla_attr_size(len);
}

/* Puts a set of openflow headers for a message of the given 'type' into 'skb'.
 * If 'sender' is nonnull, then it is used as the message's destination.  'dp'
 * must specify the datapath to use.
 *
 * '*max_openflow_len' receives the maximum number of bytes that are available
 * for the embedded OpenFlow message.  The caller must call
 * resize_openflow_skb() to set the actual size of the message to this number
 * of bytes or less.
 *
 * Returns the openflow header if successful, otherwise (if 'skb' is too small)
 * an error code. */
static void *
put_openflow_headers(struct datapath *dp, struct sk_buff *skb, uint8_t type,
		     const struct sender *sender, int *max_openflow_len)
{
	struct ofp_header *oh;
	struct nlattr *attr;
	int openflow_len;

	/* Assemble the Generic Netlink wrapper. */
	if (!genlmsg_put(skb,
			 sender ? sender->pid : 0,
			 sender ? sender->seq : 0,
			 &dp_genl_family, 0, DP_GENL_C_OPENFLOW))
		return ERR_PTR(-ENOBUFS);
	if (nla_put_u32(skb, DP_GENL_A_DP_IDX, dp->dp_idx) < 0)
		return ERR_PTR(-ENOBUFS);
	openflow_len = (skb_tailroom(skb) - NLA_HDRLEN) & ~(NLA_ALIGNTO - 1);
	if (openflow_len < sizeof *oh)
		return ERR_PTR(-ENOBUFS);
	*max_openflow_len = openflow_len;
	attr = nla_reserve(skb, DP_GENL_A_OPENFLOW, openflow_len);
	BUG_ON(!attr);

	/* Fill in the header.  The caller is responsible for the length. */
	oh = nla_data(attr);
	oh->version = OFP_VERSION;
	oh->type = type;
	oh->xid = sender ? sender->xid : 0;

	return oh;
}

/* Resizes OpenFlow header 'oh', which must be at the tail end of 'skb', to new
 * length 'new_length' (in bytes), adjusting pointers and size values as
 * necessary. */
static void
resize_openflow_skb(struct sk_buff *skb,
		    struct ofp_header *oh, size_t new_length)
{
	struct nlattr *attr = ((void *) oh) - NLA_HDRLEN;
	nla_shrink(skb, attr, new_length);
	oh->length = htons(new_length);
	nlmsg_end(skb, (struct nlmsghdr *) skb->data);
}

/* Allocates a new skb to contain an OpenFlow message 'openflow_len' bytes in
 * length.  Returns a null pointer if memory is unavailable, otherwise returns
 * the OpenFlow header and stores a pointer to the skb in '*pskb'. 
 *
 * 'type' is the OpenFlow message type.  If 'sender' is nonnull, then it is
 * used as the message's destination.  'dp' must specify the datapath to
 * use.  */
static void *
alloc_openflow_skb(struct datapath *dp, size_t openflow_len, uint8_t type,
		   const struct sender *sender, struct sk_buff **pskb) 
{
	struct ofp_header *oh;
	size_t genl_len;
	struct sk_buff *skb;
	int max_openflow_len;

	if ((openflow_len + sizeof(struct ofp_header)) > UINT16_MAX) {
		if (net_ratelimit())
			printk("alloc_openflow_skb: openflow message too large: %zu\n", 
					openflow_len);
		return NULL;
	}

	genl_len = nlmsg_total_size(GENL_HDRLEN + dp_genl_family.hdrsize);
	genl_len += nla_total_size(sizeof(uint32_t)); /* DP_GENL_A_DP_IDX */
	genl_len += nla_total_size(openflow_len);    /* DP_GENL_A_OPENFLOW */
	skb = *pskb = genlmsg_new(genl_len, GFP_ATOMIC);
	if (!skb) {
		if (net_ratelimit())
			printk("alloc_openflow_skb: genlmsg_new failed\n");
		return NULL;
	}

	oh = put_openflow_headers(dp, skb, type, sender, &max_openflow_len);
	BUG_ON(!oh || IS_ERR(oh));
	resize_openflow_skb(skb, oh, openflow_len);

	return oh;
}

/* Sends 'skb' to 'sender' if it is nonnull, otherwise multicasts 'skb' to all
 * listeners. */
static int
send_openflow_skb(struct sk_buff *skb, const struct sender *sender) 
{
	return (sender
		? genlmsg_unicast(skb, sender->pid)
		: genlmsg_multicast(skb, 0, mc_group.id, GFP_ATOMIC));
}

/* Retrieves the datapath id, which is the MAC address of the "of" device. */
static 
uint64_t get_datapath_id(struct net_device *dev)
{
	uint64_t id = 0;
	int i;

	for (i=0; i<ETH_ALEN; i++) 
		id |= (uint64_t)dev->dev_addr[i] << (8*(ETH_ALEN-1 - i));

	return id;
}

/* Creates a new datapath numbered 'dp_idx'.  Returns 0 for success or a
 * negative error code. */
static int new_dp(int dp_idx)
{
	struct datapath *dp;
	int err;

	if (dp_idx < 0 || dp_idx >= DP_MAX)
		return -EINVAL;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	/* Exit early if a datapath with that number already exists. */
	if (dps[dp_idx]) {
		err = -EEXIST;
		goto err_unlock;
	}

	err = -ENOMEM;
	dp = kzalloc(sizeof *dp, GFP_KERNEL);
	if (dp == NULL)
		goto err_unlock;

	/* Setup our "of" device */
	err = dp_dev_setup(dp);
	if (err)
		goto err_free_dp;

	dp->dp_idx = dp_idx;
	dp->chain = chain_create(dp);
	if (dp->chain == NULL)
		goto err_destroy_dp_dev;
	INIT_LIST_HEAD(&dp->port_list);

	dp->local_port = new_nbp(dp, dp->netdev, OFPP_LOCAL);
	if (IS_ERR(dp->local_port)) {
		err = PTR_ERR(dp->local_port);
		goto err_destroy_local_port;
	}

	dp->flags = 0;
	dp->miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;

	dp->dp_task = kthread_run(dp_maint_func, dp, "dp%d", dp_idx);
	if (IS_ERR(dp->dp_task))
		goto err_destroy_chain;

	dps[dp_idx] = dp;

	return 0;

err_destroy_local_port:
	dp_del_switch_port(dp->local_port);
err_destroy_chain:
	chain_destroy(dp->chain);
err_destroy_dp_dev:
	dp_dev_destroy(dp);
err_free_dp:
	kfree(dp);
err_unlock:
	module_put(THIS_MODULE);
		return err;
}

/* Find and return a free port number under 'dp'. */
static int find_portno(struct datapath *dp)
{
	int i;
	for (i = 0; i < DP_MAX_PORTS; i++)
		if (dp->ports[i] == NULL)
			return i;
	return -EXFULL;
}

static struct net_bridge_port *new_nbp(struct datapath *dp,
				       struct net_device *dev, int port_no)
{
	struct net_bridge_port *p;

	if (dev->br_port != NULL)
		return ERR_PTR(-EBUSY);

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (p == NULL)
		return ERR_PTR(-ENOMEM);

	rtnl_lock();
	dev_set_promiscuity(dev, 1);
	rtnl_unlock();
	dev_hold(dev);
	p->dp = dp;
	p->dev = dev;
	p->port_no = port_no;
	spin_lock_init(&p->lock);
	INIT_WORK(&p->port_task, NULL);
	if (port_no != OFPP_LOCAL)
		rcu_assign_pointer(dev->br_port, p);
	if (port_no < DP_MAX_PORTS)
		rcu_assign_pointer(dp->ports[port_no], p); 
	list_add_rcu(&p->node, &dp->port_list);

	return p;
}

int add_switch_port(struct datapath *dp, struct net_device *dev)
{
	struct net_bridge_port *p;
	int port_no;

	if (dev->flags & IFF_LOOPBACK || dev->type != ARPHRD_ETHER
	    || is_dp_dev(dev))
		return -EINVAL;

	port_no = find_portno(dp);
	if (port_no < 0)
		return port_no;

	p = new_nbp(dp, dev, port_no);
	if (IS_ERR(p))
		return PTR_ERR(p);

	init_port_status(p);

	/* Notify the ctlpath that this port has been added */
	dp_send_port_status(p, OFPPR_ADD);

	return 0;
}

/* Delete 'p' from switch. */
int dp_del_switch_port(struct net_bridge_port *p)
{
#ifdef SUPPORT_SNAT
	unsigned long flags;
#endif

	/* First drop references to device. */
	cancel_work_sync(&p->port_task);
	rtnl_lock();
	dev_set_promiscuity(p->dev, -1);
	rtnl_unlock();
	list_del_rcu(&p->node);
	if (p->port_no != OFPP_LOCAL)
		rcu_assign_pointer(p->dp->ports[p->port_no], NULL);
	rcu_assign_pointer(p->dev->br_port, NULL);

	/* Then wait until no one is still using it, and destroy it. */
	synchronize_rcu();

#ifdef SUPPORT_SNAT
	/* Free any SNAT configuration on the port. */
	spin_lock_irqsave(&p->lock, flags);
	snat_free_conf(p);
	spin_unlock_irqrestore(&p->lock, flags);
#endif

	/* Notify the ctlpath that this port no longer exists */
	dp_send_port_status(p, OFPPR_DELETE);

	dev_put(p->dev);
	kfree(p);

	return 0;
}

static void del_dp(struct datapath *dp)
{
	struct net_bridge_port *p, *n;

	kthread_stop(dp->dp_task);

	/* Drop references to DP. */
	list_for_each_entry_safe (p, n, &dp->port_list, node)
		dp_del_switch_port(p);
	rcu_assign_pointer(dps[dp->dp_idx], NULL);

	/* Kill off local_port dev references from buffered packets that have
	 * associated dst entries. */
	synchronize_rcu();
	fwd_discard_all();

	/* Destroy dp->netdev.  (Must follow deleting switch ports since
	 * dp->local_port has a reference to it.) */
	dp_dev_destroy(dp);

	/* Wait until no longer in use, then destroy it. */
	synchronize_rcu();
	chain_destroy(dp->chain);
	kfree(dp);
	module_put(THIS_MODULE);
}

static int dp_maint_func(void *data)
{
	struct datapath *dp = (struct datapath *) data;

	while (!kthread_should_stop()) {
#ifdef SUPPORT_SNAT
		struct net_bridge_port *p;

		/* Expire old SNAT entries */
		rcu_read_lock();
		list_for_each_entry_rcu (p, &dp->port_list, node) 
			snat_maint(p);
		rcu_read_unlock();
#endif

		/* Timeout old entries */
		chain_timeout(dp->chain);
		msleep_interruptible(MAINT_SLEEP_MSECS);
	}
		
	return 0;
}

static void
do_port_input(struct net_bridge_port *p, struct sk_buff *skb) 
{
	/* Make our own copy of the packet.  Otherwise we will mangle the
	 * packet for anyone who came before us (e.g. tcpdump via AF_PACKET).
	 * (No one comes after us, since we tell handle_bridge() that we took
	 * the packet.) */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return;

#ifdef SUPPORT_SNAT
	/* Check if this packet needs early SNAT processing. */
	if (snat_pre_route(skb)) {
		return;
	}
#endif

	/* Push the Ethernet header back on. */
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	fwd_port_input(p->dp->chain, skb, p);
}

/*
 * Used as br_handle_frame_hook.  (Cannot run bridge at the same time, even on
 * different set of devices!)
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
/* Called with rcu_read_lock. */
static struct sk_buff *dp_frame_hook(struct net_bridge_port *p,
					 struct sk_buff *skb)
{
	do_port_input(p, skb);
	return NULL;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static int dp_frame_hook(struct net_bridge_port *p, struct sk_buff **pskb)
{
	do_port_input(p, *pskb);
	return 1;
}
#else
/* NB: This has only been tested on 2.4.35 */
static void dp_frame_hook(struct sk_buff *skb)
{
	struct net_bridge_port *p = skb->dev->br_port;
	if (p) {
		rcu_read_lock();
		do_port_input(p, skb);
		rcu_read_unlock();
	} else
		kfree_skb(skb);
}
#endif

/* Forwarding output path.
 * Based on net/bridge/br_forward.c. */

static inline unsigned packet_length(const struct sk_buff *skb)
{
	int length = skb->len - ETH_HLEN;
	if (skb->protocol == htons(ETH_P_8021Q))
		length -= VLAN_HLEN;
	return length;
}

/* Send packets out all the ports except the originating one.  If the
 * "flood" argument is set, only send along the minimum spanning tree.
 */
static int
output_all(struct datapath *dp, struct sk_buff *skb, int flood)
{
	u32 disable = flood ? OFPPC_NO_FLOOD : 0;
	struct net_bridge_port *p;
	int prev_port = -1;

	list_for_each_entry_rcu (p, &dp->port_list, node) {
		if (skb->dev == p->dev || p->config & disable)
			continue;
		if (prev_port != -1) {
			struct sk_buff *clone = skb_clone(skb, GFP_ATOMIC);
			if (!clone) {
				kfree_skb(skb);
				return -ENOMEM;
			}
			dp_output_port(dp, clone, prev_port, 0); 
		}
		prev_port = p->port_no;
	}
	if (prev_port != -1)
		dp_output_port(dp, skb, prev_port, 0);
	else
		kfree_skb(skb);

	return 0;
}

/* Marks 'skb' as having originated from 'in_port' in 'dp'.
   FIXME: how are devices reference counted? */
void dp_set_origin(struct datapath *dp, uint16_t in_port,
			   struct sk_buff *skb)
{
	struct net_bridge_port *p;
	p = (in_port < DP_MAX_PORTS ? dp->ports[in_port]
	     : in_port == OFPP_LOCAL ? dp->local_port
	     : NULL);
	if (p) 
		skb->dev = p->dev;
	 else 
		skb->dev = NULL;
}

int 
dp_xmit_skb(struct sk_buff *skb)
{
	int len = skb->len;
	if (packet_length(skb) > skb->dev->mtu) {
		printk("dropped over-mtu packet: %d > %d\n",
			   packet_length(skb), skb->dev->mtu);
		kfree_skb(skb);
		return -E2BIG;
	}

	dev_queue_xmit(skb);

	return len;
}

/* Takes ownership of 'skb' and transmits it to 'out_port' on 'dp'.
 */
int dp_output_port(struct datapath *dp, struct sk_buff *skb, int out_port,
		   int ignore_no_fwd)
{
	BUG_ON(!skb);
	switch (out_port){
	case OFPP_IN_PORT:
		/* Send it out the port it came in on, which is already set in
		 * the skb. */
		if (!skb->dev) {
			if (net_ratelimit())
				printk("skb device not set forwarding to in_port\n");
			kfree_skb(skb);
			return -ESRCH;
		}
		return dp_xmit_skb(skb);
		
	case OFPP_TABLE: {
		int retval = run_flow_through_tables(dp->chain, skb,
						     skb->dev->br_port);
		if (retval)
			kfree_skb(skb);
		return retval;
	}

	case OFPP_FLOOD:
		return output_all(dp, skb, 1);

	case OFPP_ALL:
		return output_all(dp, skb, 0);

	case OFPP_CONTROLLER:
		return dp_output_control(dp, skb, fwd_save_skb(skb), 0,
						  OFPR_ACTION);

	case OFPP_LOCAL: {
		struct net_device *dev = dp->netdev;
#ifdef SUPPORT_SNAT
		snat_local_in(skb);
#endif
		return dev ? dp_dev_recv(dev, skb) : -ESRCH;
	}

	case 0 ... DP_MAX_PORTS - 1: {
		struct net_bridge_port *p = dp->ports[out_port];
		if (p == NULL)
			goto bad_port;
		if (p->dev == skb->dev) {
			/* To send to the input port, must use OFPP_IN_PORT */
			kfree_skb(skb);
			if (net_ratelimit())
				printk("can't directly forward to input port\n");
			return -EINVAL;
		}
		if (p->config & OFPPC_NO_FWD && !ignore_no_fwd) {
			kfree_skb(skb);
			return 0;
		}
		skb->dev = p->dev; 
		return dp_xmit_skb(skb);
	}

	default:
		goto bad_port;
	}

bad_port:
	kfree_skb(skb);
	if (net_ratelimit())
		printk("can't forward to bad port %d\n", out_port);
	return -ENOENT;
}

/* Takes ownership of 'skb' and transmits it to 'dp''s control path.  If
 * 'buffer_id' != -1, then only the first 64 bytes of 'skb' are sent;
 * otherwise, all of 'skb' is sent.  'reason' indicates why 'skb' is being
 * sent. 'max_len' sets the maximum number of bytes that the caller
 * wants to be sent; a value of 0 indicates the entire packet should be
 * sent. */
int
dp_output_control(struct datapath *dp, struct sk_buff *skb,
			   uint32_t buffer_id, size_t max_len, int reason)
{
	/* FIXME?  Can we avoid creating a new skbuff in the case where we
	 * forward the whole packet? */
	struct sk_buff *f_skb;
	struct ofp_packet_in *opi;
	size_t fwd_len, opi_len;
	int err;

	fwd_len = skb->len;
	if ((buffer_id != (uint32_t) -1) && max_len)
		fwd_len = min(fwd_len, max_len);

	opi_len = offsetof(struct ofp_packet_in, data) + fwd_len;
	opi = alloc_openflow_skb(dp, opi_len, OFPT_PACKET_IN, NULL, &f_skb);
	if (!opi) {
		err = -ENOMEM;
		goto out;
	}
	opi->buffer_id      = htonl(buffer_id);
	opi->total_len      = htons(skb->len);
	opi->in_port        = htons(skb->dev && skb->dev->br_port
				    ? skb->dev->br_port->port_no
				    : OFPP_LOCAL);
	opi->reason         = reason;
	opi->pad            = 0;
	skb_copy_bits(skb, 0, opi->data, fwd_len);
	err = send_openflow_skb(f_skb, NULL);

out:
	kfree_skb(skb);
	return err;
}

static void fill_port_desc(struct net_bridge_port *p, struct ofp_phy_port *desc)
{
	unsigned long flags;
	desc->port_no = htons(p->port_no);
	strncpy(desc->name, p->dev->name, OFP_MAX_PORT_NAME_LEN);
	desc->name[OFP_MAX_PORT_NAME_LEN-1] = '\0';
	memcpy(desc->hw_addr, p->dev->dev_addr, ETH_ALEN);
	desc->curr = 0;
	desc->supported = 0;
	desc->advertised = 0;
	desc->peer = 0;

	spin_lock_irqsave(&p->lock, flags);
	desc->config = htonl(p->config);
	desc->state = htonl(p->state);
	spin_unlock_irqrestore(&p->lock, flags);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,24)
	if (p->dev->ethtool_ops && p->dev->ethtool_ops->get_settings) {
		struct ethtool_cmd ecmd = { .cmd = ETHTOOL_GSET };

		if (!p->dev->ethtool_ops->get_settings(p->dev, &ecmd)) {
			/* Set the supported features */
			if (ecmd.supported & SUPPORTED_10baseT_Half) 
				desc->supported |= OFPPF_10MB_HD;
			if (ecmd.supported & SUPPORTED_10baseT_Full)
				desc->supported |= OFPPF_10MB_FD;
			if (ecmd.supported & SUPPORTED_100baseT_Half) 
				desc->supported |= OFPPF_100MB_HD;
			if (ecmd.supported & SUPPORTED_100baseT_Full)
				desc->supported |= OFPPF_100MB_FD;
			if (ecmd.supported & SUPPORTED_1000baseT_Half)
				desc->supported |= OFPPF_1GB_HD;
			if (ecmd.supported & SUPPORTED_1000baseT_Full)
				desc->supported |= OFPPF_1GB_FD;
			if (ecmd.supported & SUPPORTED_10000baseT_Full)
				desc->supported |= OFPPF_10GB_FD;
			if (ecmd.supported & SUPPORTED_TP)
				desc->supported |= OFPPF_COPPER;
			if (ecmd.supported & SUPPORTED_FIBRE)
				desc->supported |= OFPPF_FIBER;
			if (ecmd.supported & SUPPORTED_Autoneg)
				desc->supported |= OFPPF_AUTONEG;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
			if (ecmd.supported & SUPPORTED_Pause)
				desc->supported |= OFPPF_PAUSE;
			if (ecmd.supported & SUPPORTED_Asym_Pause)
				desc->supported |= OFPPF_PAUSE_ASYM;
#endif /* kernel >= 2.6.14 */

			/* Set the advertised features */
			if (ecmd.advertising & ADVERTISED_10baseT_Half) 
				desc->advertised |= OFPPF_10MB_HD;
			if (ecmd.advertising & ADVERTISED_10baseT_Full)
				desc->advertised |= OFPPF_10MB_FD;
			if (ecmd.advertising & ADVERTISED_100baseT_Half) 
				desc->advertised |= OFPPF_100MB_HD;
			if (ecmd.advertising & ADVERTISED_100baseT_Full)
				desc->advertised |= OFPPF_100MB_FD;
			if (ecmd.advertising & ADVERTISED_1000baseT_Half)
				desc->advertised |= OFPPF_1GB_HD;
			if (ecmd.advertising & ADVERTISED_1000baseT_Full)
				desc->advertised |= OFPPF_1GB_FD;
			if (ecmd.advertising & ADVERTISED_10000baseT_Full)
				desc->advertised |= OFPPF_10GB_FD;
			if (ecmd.advertising & ADVERTISED_TP)
				desc->advertised |= OFPPF_COPPER;
			if (ecmd.advertising & ADVERTISED_FIBRE)
				desc->advertised |= OFPPF_FIBER;
			if (ecmd.advertising & ADVERTISED_Autoneg)
				desc->advertised |= OFPPF_AUTONEG;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
			if (ecmd.advertising & ADVERTISED_Pause)
				desc->advertised |= OFPPF_PAUSE;
			if (ecmd.advertising & ADVERTISED_Asym_Pause)
				desc->advertised |= OFPPF_PAUSE_ASYM;
#endif /* kernel >= 2.6.14 */

			/* Set the current features */
			if (ecmd.speed == SPEED_10)
				desc->curr = (ecmd.duplex) ? OFPPF_10MB_FD : OFPPF_10MB_HD;
			else if (ecmd.speed == SPEED_100)
				desc->curr = (ecmd.duplex) ? OFPPF_100MB_FD : OFPPF_100MB_HD;
			else if (ecmd.speed == SPEED_1000)
				desc->curr = (ecmd.duplex) ? OFPPF_1GB_FD : OFPPF_1GB_HD;
			else if (ecmd.speed == SPEED_10000)
				desc->curr = OFPPF_10GB_FD;

			if (ecmd.port == PORT_TP) 
				desc->curr |= OFPPF_COPPER;
			else if (ecmd.port == PORT_FIBRE) 
				desc->curr |= OFPPF_FIBER;

			if (ecmd.autoneg)
				desc->curr |= OFPPF_AUTONEG;
		}
	}
#endif
	desc->curr = htonl(desc->curr);
	desc->supported = htonl(desc->supported);
	desc->advertised = htonl(desc->advertised);
	desc->peer = htonl(desc->peer);
}

static int 
fill_features_reply(struct datapath *dp, struct ofp_switch_features *ofr)
{
	struct net_bridge_port *p;
	uint64_t dpid = get_datapath_id(dp->netdev);
	int port_count = 0;

	ofr->datapath_id  = cpu_to_be64(dpid);

	ofr->n_buffers    = htonl(N_PKT_BUFFERS);
	ofr->n_tables     = dp->chain->n_tables;
	ofr->capabilities = htonl(OFP_SUPPORTED_CAPABILITIES);
	ofr->actions      = htonl(OFP_SUPPORTED_ACTIONS);
	memset(ofr->pad, 0, sizeof ofr->pad);

	list_for_each_entry_rcu (p, &dp->port_list, node) {
		fill_port_desc(p, &ofr->ports[port_count]);
		port_count++;
	}

	return port_count;
}

int
dp_send_features_reply(struct datapath *dp, const struct sender *sender)
{
	struct sk_buff *skb;
	struct ofp_switch_features *ofr;
	size_t ofr_len, port_max_len;
	int port_count;

	/* Overallocate. */
	port_max_len = sizeof(struct ofp_phy_port) * DP_MAX_PORTS;
	ofr = alloc_openflow_skb(dp, sizeof(*ofr) + port_max_len,
				 OFPT_FEATURES_REPLY, sender, &skb);
	if (!ofr)
		return -ENOMEM;

	/* Fill. */
	port_count = fill_features_reply(dp, ofr);

	/* Shrink to fit. */
	ofr_len = sizeof(*ofr) + (sizeof(struct ofp_phy_port) * port_count);
	resize_openflow_skb(skb, &ofr->header, ofr_len);
	return send_openflow_skb(skb, sender);
}

int
dp_send_config_reply(struct datapath *dp, const struct sender *sender)
{
	struct sk_buff *skb;
	struct ofp_switch_config *osc;

	osc = alloc_openflow_skb(dp, sizeof *osc, OFPT_GET_CONFIG_REPLY, sender,
				 &skb);
	if (!osc)
		return -ENOMEM;

	osc->flags = htons(dp->flags);
	osc->miss_send_len = htons(dp->miss_send_len);

	return send_openflow_skb(skb, sender);
}

int
dp_send_hello(struct datapath *dp, const struct sender *sender,
	      const struct ofp_header *request)
{
	if (request->version < OFP_VERSION) {
		char err[64];
		sprintf(err, "Only version 0x%02x supported", OFP_VERSION);
		dp_send_error_msg(dp, sender, OFPET_HELLO_FAILED,
				  OFPHFC_INCOMPATIBLE, err, strlen(err));
		return -EINVAL;
	} else {
		struct sk_buff *skb;
		struct ofp_header *reply;

		reply = alloc_openflow_skb(dp, sizeof *reply,
					   OFPT_HELLO, sender, &skb);
		if (!reply)
			return -ENOMEM;

		return send_openflow_skb(skb, sender);
	}
}

/* Callback function for a workqueue to disable an interface */
static void
down_port_cb(struct work_struct *work)
{
	struct net_bridge_port *p = container_of(work, struct net_bridge_port, 
			port_task);

	rtnl_lock();
	if (dev_change_flags(p->dev, p->dev->flags & ~IFF_UP) < 0)
		if (net_ratelimit())
			printk("problem bringing up port %s\n", p->dev->name);
	rtnl_unlock();
	p->config |= OFPPC_PORT_DOWN;
}

/* Callback function for a workqueue to enable an interface */
static void
up_port_cb(struct work_struct *work)
{
	struct net_bridge_port *p = container_of(work, struct net_bridge_port, 
			port_task);

	rtnl_lock();
	if (dev_change_flags(p->dev, p->dev->flags | IFF_UP) < 0)
		if (net_ratelimit())
			printk("problem bringing down port %s\n", p->dev->name);
	rtnl_unlock();
	p->config &= ~OFPPC_PORT_DOWN;
}

int
dp_update_port_flags(struct datapath *dp, const struct ofp_port_mod *opm)
{
	unsigned long int flags;
	int port_no = ntohs(opm->port_no);
	struct net_bridge_port *p;
	p = (port_no < DP_MAX_PORTS ? dp->ports[port_no]
	     : port_no == OFPP_LOCAL ? dp->local_port
	     : NULL);

	/* Make sure the port id hasn't changed since this was sent */
	if (!p || memcmp(opm->hw_addr, p->dev->dev_addr, ETH_ALEN))
		return -1;

	spin_lock_irqsave(&p->lock, flags);
	if (opm->mask) {
		uint32_t config_mask = ntohl(opm->mask);
		p->config &= ~config_mask;
		p->config |= ntohl(opm->config) & config_mask;
	}

	/* Modifying the status of an interface requires taking a lock
	 * that cannot be done from here.  For this reason, we use a shared 
	 * workqueue, which will cause it to be executed from a safer 
	 * context. */
	if (opm->mask & htonl(OFPPC_PORT_DOWN)) {
		if ((opm->config & htonl(OFPPC_PORT_DOWN))
		    && (p->config & OFPPC_PORT_DOWN) == 0) {
			PREPARE_WORK(&p->port_task, down_port_cb);
			schedule_work(&p->port_task);
		} else if ((opm->config & htonl(OFPPC_PORT_DOWN)) == 0
			   && (p->config & OFPPC_PORT_DOWN)) {
			PREPARE_WORK(&p->port_task, up_port_cb);
			schedule_work(&p->port_task);
		}
	}
	spin_unlock_irqrestore(&p->lock, flags);

	return 0;
}

/* Initialize the port status field of the bridge port. */
static void
init_port_status(struct net_bridge_port *p)
{
	unsigned long int flags;

	spin_lock_irqsave(&p->lock, flags);

	if (p->dev->flags & IFF_UP) 
		p->config &= ~OFPPC_PORT_DOWN;
	else
		p->config |= OFPPC_PORT_DOWN;

	if (netif_carrier_ok(p->dev))
		p->state &= ~OFPPS_LINK_DOWN;
	else
		p->state |= OFPPS_LINK_DOWN;

	spin_unlock_irqrestore(&p->lock, flags);
}

int
dp_send_port_status(struct net_bridge_port *p, uint8_t status)
{
	struct sk_buff *skb;
	struct ofp_port_status *ops;

	ops = alloc_openflow_skb(p->dp, sizeof *ops, OFPT_PORT_STATUS, NULL,
				 &skb);
	if (!ops)
		return -ENOMEM;
	ops->reason = status;
	memset(ops->pad, 0, sizeof ops->pad);
	fill_port_desc(p, &ops->desc);

	return send_openflow_skb(skb, NULL);
}

int 
dp_send_flow_expired(struct datapath *dp, struct sw_flow *flow,
		     enum ofp_flow_expired_reason reason)
{
	struct sk_buff *skb;
	struct ofp_flow_expired *ofe;

	if (!(dp->flags & OFPC_SEND_FLOW_EXP))
		return 0;

	ofe = alloc_openflow_skb(dp, sizeof *ofe, OFPT_FLOW_EXPIRED, 0, &skb);
	if (!ofe)
		return -ENOMEM;

	flow_fill_match(&ofe->match, &flow->key);

	ofe->priority = htons(flow->priority);
	ofe->reason = reason;
	memset(ofe->pad, 0, sizeof ofe->pad);

	ofe->duration     = htonl((jiffies - flow->init_time) / HZ);
	memset(ofe->pad2, 0, sizeof ofe->pad2);
	ofe->packet_count = cpu_to_be64(flow->packet_count);
	ofe->byte_count   = cpu_to_be64(flow->byte_count);

	return send_openflow_skb(skb, NULL);
}
EXPORT_SYMBOL(dp_send_flow_expired);

int
dp_send_error_msg(struct datapath *dp, const struct sender *sender, 
		uint16_t type, uint16_t code, const void *data, size_t len)
{
	struct sk_buff *skb;
	struct ofp_error_msg *oem;


	oem = alloc_openflow_skb(dp, sizeof(*oem)+len, OFPT_ERROR, 
			sender, &skb);
	if (!oem)
		return -ENOMEM;

	oem->type = htons(type);
	oem->code = htons(code);
	memcpy(oem->data, data, len);

	return send_openflow_skb(skb, sender);
}

int
dp_send_echo_reply(struct datapath *dp, const struct sender *sender,
		   const struct ofp_header *rq)
{
	struct sk_buff *skb;
	struct ofp_header *reply;

	reply = alloc_openflow_skb(dp, ntohs(rq->length), OFPT_ECHO_REPLY,
				   sender, &skb);
	if (!reply)
		return -ENOMEM;

	memcpy(reply + 1, rq + 1, ntohs(rq->length) - sizeof *rq);
	return send_openflow_skb(skb, sender);
}

/* Generic Netlink interface.
 *
 * See netlink(7) for an introduction to netlink.  See
 * http://linux-net.osdl.org/index.php/Netlink for more information and
 * pointers on how to work with netlink and Generic Netlink in the kernel and
 * in userspace. */

static struct genl_family dp_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = DP_GENL_FAMILY_NAME,
	.version = 1,
	.maxattr = DP_GENL_A_MAX,
};

/* Attribute policy: what each attribute may contain.  */
static struct nla_policy dp_genl_policy[DP_GENL_A_MAX + 1] = {
	[DP_GENL_A_DP_IDX] = { .type = NLA_U32 },
	[DP_GENL_A_MC_GROUP] = { .type = NLA_U32 },
	[DP_GENL_A_PORTNAME] = { .type = NLA_STRING }
};

static int dp_genl_add(struct sk_buff *skb, struct genl_info *info)
{
	if (!info->attrs[DP_GENL_A_DP_IDX])
		return -EINVAL;

	return new_dp(nla_get_u32(info->attrs[DP_GENL_A_DP_IDX]));
}

static struct genl_ops dp_genl_ops_add_dp = {
	.cmd = DP_GENL_C_ADD_DP,
	.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	.policy = dp_genl_policy,
	.doit = dp_genl_add,
	.dumpit = NULL,
};

struct datapath *dp_get(int dp_idx)
{
	if (dp_idx < 0 || dp_idx > DP_MAX)
		return NULL;
	return rcu_dereference(dps[dp_idx]);
}

static int dp_genl_del(struct sk_buff *skb, struct genl_info *info)
{
	struct datapath *dp;
	int err;

	if (!info->attrs[DP_GENL_A_DP_IDX])
		return -EINVAL;

	dp = dp_get(nla_get_u32((info->attrs[DP_GENL_A_DP_IDX])));
	if (!dp)
		err = -ENOENT;
	else {
		del_dp(dp);
		err = 0;
	}
	return err;
}

static struct genl_ops dp_genl_ops_del_dp = {
	.cmd = DP_GENL_C_DEL_DP,
	.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	.policy = dp_genl_policy,
	.doit = dp_genl_del,
	.dumpit = NULL,
};

/* Queries a datapath for related information.  Currently the only relevant
 * information is the datapath's multicast group ID.  Really we want one
 * multicast group per datapath, but because of locking issues[*] we can't
 * easily get one.  Thus, every datapath will currently return the same
 * global multicast group ID, but in the future it would be nice to fix that.
 *
 * [*] dp_genl_add, to add a new datapath, is called under the genl_lock
 *	 mutex, and genl_register_mc_group, called to acquire a new multicast
 *	 group ID, also acquires genl_lock, thus deadlock.
 */
static int dp_genl_query(struct sk_buff *skb, struct genl_info *info)
{
	struct datapath *dp;
	struct sk_buff *ans_skb = NULL;
	int dp_idx;
	int err = -ENOMEM;

	if (!info->attrs[DP_GENL_A_DP_IDX])
		return -EINVAL;

	rcu_read_lock();
	dp_idx = nla_get_u32((info->attrs[DP_GENL_A_DP_IDX]));
	dp = dp_get(dp_idx);
	if (!dp)
		err = -ENOENT;
	else {
		void *data;
		ans_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
		if (!ans_skb) {
			err = -ENOMEM;
			goto err;
		}
		data = genlmsg_put_reply(ans_skb, info, &dp_genl_family,
					 0, DP_GENL_C_QUERY_DP);
		if (data == NULL) {
			err = -ENOMEM;
			goto err;
		}
		NLA_PUT_U32(ans_skb, DP_GENL_A_DP_IDX, dp_idx);
		NLA_PUT_U32(ans_skb, DP_GENL_A_MC_GROUP, mc_group.id);

		genlmsg_end(ans_skb, data);
		err = genlmsg_reply(ans_skb, info);
		ans_skb = NULL;
	}
err:
nla_put_failure:
	kfree_skb(ans_skb);
	rcu_read_unlock();
	return err;
}

static struct genl_ops dp_genl_ops_query_dp = {
	.cmd = DP_GENL_C_QUERY_DP,
	.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	.policy = dp_genl_policy,
	.doit = dp_genl_query,
	.dumpit = NULL,
};

static int dp_genl_add_del_port(struct sk_buff *skb, struct genl_info *info)
{
	struct datapath *dp;
	struct net_device *port;
	int err;

	if (!info->attrs[DP_GENL_A_DP_IDX] || !info->attrs[DP_GENL_A_PORTNAME])
		return -EINVAL;

	/* Get datapath. */
	dp = dp_get(nla_get_u32(info->attrs[DP_GENL_A_DP_IDX]));
	if (!dp) {
		err = -ENOENT;
		goto out;
	}

	/* Get interface to add/remove. */
	port = dev_get_by_name(&init_net, 
			nla_data(info->attrs[DP_GENL_A_PORTNAME]));
	if (!port) {
		err = -ENOENT;
		goto out;
	}

	/* Execute operation. */
	if (info->genlhdr->cmd == DP_GENL_C_ADD_PORT)
		err = add_switch_port(dp, port);
	else {
		if (port->br_port == NULL || port->br_port->dp != dp) {
			err = -ENOENT;
			goto out_put;
		}
		err = dp_del_switch_port(port->br_port);
	}

out_put:
	dev_put(port);
out:
	return err;
}

static struct genl_ops dp_genl_ops_add_port = {
	.cmd = DP_GENL_C_ADD_PORT,
	.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	.policy = dp_genl_policy,
	.doit = dp_genl_add_del_port,
	.dumpit = NULL,
};

static struct genl_ops dp_genl_ops_del_port = {
	.cmd = DP_GENL_C_DEL_PORT,
	.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	.policy = dp_genl_policy,
	.doit = dp_genl_add_del_port,
	.dumpit = NULL,
};

static int dp_genl_openflow(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *va = info->attrs[DP_GENL_A_OPENFLOW];
	struct datapath *dp;
	struct ofp_header *oh;
	struct sender sender;
	int err;

	if (!info->attrs[DP_GENL_A_DP_IDX] || !va)
		return -EINVAL;

	dp = dp_get(nla_get_u32(info->attrs[DP_GENL_A_DP_IDX]));
	if (!dp)
		return -ENOENT;

	if (nla_len(va) < sizeof(struct ofp_header))
		return -EINVAL;
	oh = nla_data(va);

	sender.xid = oh->xid;
	sender.pid = info->snd_pid;
	sender.seq = info->snd_seq;

	mutex_lock(&dp_mutex);
	err = fwd_control_input(dp->chain, &sender,
				nla_data(va), nla_len(va));
	mutex_unlock(&dp_mutex);
	return err;
}

static struct nla_policy dp_genl_openflow_policy[DP_GENL_A_MAX + 1] = {
	[DP_GENL_A_DP_IDX] = { .type = NLA_U32 },
};

static int desc_stats_dump(struct datapath *dp, void *state,
			    void *body, int *body_len)
{
	struct ofp_desc_stats *ods = body;
	int n_bytes = sizeof *ods;

	if (n_bytes > *body_len) {
		return -ENOBUFS;
	}
	*body_len = n_bytes;

	strncpy(ods->mfr_desc, mfr_desc, sizeof ods->mfr_desc);
	strncpy(ods->hw_desc, hw_desc, sizeof ods->hw_desc);
	strncpy(ods->sw_desc, sw_desc, sizeof ods->sw_desc);
	strncpy(ods->serial_num, serial_num, sizeof ods->serial_num);

	return 0;
}

struct flow_stats_state {
	int table_idx;
	struct sw_table_position position;
	const struct ofp_flow_stats_request *rq;

	void *body;
	int bytes_used, bytes_allocated;
};

static int flow_stats_init(struct datapath *dp, const void *body, int body_len,
			   void **state)
{
	const struct ofp_flow_stats_request *fsr = body;
	struct flow_stats_state *s = kmalloc(sizeof *s, GFP_ATOMIC);
	if (!s)
		return -ENOMEM;
	s->table_idx = fsr->table_id == 0xff ? 0 : fsr->table_id;
	memset(&s->position, 0, sizeof s->position);
	s->rq = fsr;
	*state = s;
	return 0;
}

static int flow_stats_dump_callback(struct sw_flow *flow, void *private)
{
	struct sw_flow_actions *sf_acts = rcu_dereference(flow->sf_acts);
	struct flow_stats_state *s = private;
	struct ofp_flow_stats *ofs;
	int length;

	length = sizeof *ofs + sf_acts->actions_len;
	if (length + s->bytes_used > s->bytes_allocated)
		return 1;

	ofs = s->body + s->bytes_used;
	ofs->length          = htons(length);
	ofs->table_id        = s->table_idx;
	ofs->pad             = 0;
	ofs->match.wildcards = htonl(flow->key.wildcards);
	ofs->match.in_port   = flow->key.in_port;
	memcpy(ofs->match.dl_src, flow->key.dl_src, ETH_ALEN);
	memcpy(ofs->match.dl_dst, flow->key.dl_dst, ETH_ALEN);
	ofs->match.dl_vlan   = flow->key.dl_vlan;
	ofs->match.dl_type   = flow->key.dl_type;
	ofs->match.nw_src    = flow->key.nw_src;
	ofs->match.nw_dst    = flow->key.nw_dst;
	ofs->match.nw_proto  = flow->key.nw_proto;
	ofs->match.pad       = 0;
	ofs->match.tp_src    = flow->key.tp_src;
	ofs->match.tp_dst    = flow->key.tp_dst;
	ofs->duration        = htonl((jiffies - flow->init_time) / HZ);
	ofs->priority        = htons(flow->priority);
	ofs->idle_timeout    = htons(flow->idle_timeout);
	ofs->hard_timeout    = htons(flow->hard_timeout);
	memset(ofs->pad2, 0, sizeof ofs->pad2);
	ofs->packet_count    = cpu_to_be64(flow->packet_count);
	ofs->byte_count      = cpu_to_be64(flow->byte_count);
	memcpy(ofs->actions, sf_acts->actions, sf_acts->actions_len);

	s->bytes_used += length;
	return 0;
}

static int flow_stats_dump(struct datapath *dp, void *state,
			   void *body, int *body_len)
{
	struct flow_stats_state *s = state;
	struct sw_flow_key match_key;
	int error = 0;

	s->bytes_used = 0;
	s->bytes_allocated = *body_len;
	s->body = body;

	flow_extract_match(&match_key, &s->rq->match);
	while (s->table_idx < dp->chain->n_tables
	       && (s->rq->table_id == 0xff || s->rq->table_id == s->table_idx))
	{
		struct sw_table *table = dp->chain->tables[s->table_idx];

		error = table->iterate(table, &match_key, s->rq->out_port, 
				&s->position, flow_stats_dump_callback, s);
		if (error)
			break;

		s->table_idx++;
		memset(&s->position, 0, sizeof s->position);
	}
	*body_len = s->bytes_used;

	/* If error is 0, we're done.
	 * Otherwise, if some bytes were used, there are more flows to come.
	 * Otherwise, we were not able to fit even a single flow in the body,
	 * which indicates that we have a single flow with too many actions to
	 * fit.  We won't ever make any progress at that rate, so give up. */
	return !error ? 0 : s->bytes_used ? 1 : -ENOMEM;
}

static void flow_stats_done(void *state)
{
	kfree(state);
}

static int aggregate_stats_init(struct datapath *dp,
				const void *body, int body_len,
				void **state)
{
	*state = (void *)body;
	return 0;
}

static int aggregate_stats_dump_callback(struct sw_flow *flow, void *private)
{
	struct ofp_aggregate_stats_reply *rpy = private;
	rpy->packet_count += flow->packet_count;
	rpy->byte_count += flow->byte_count;
	rpy->flow_count++;
	return 0;
}

static int aggregate_stats_dump(struct datapath *dp, void *state,
				void *body, int *body_len)
{
	struct ofp_aggregate_stats_request *rq = state;
	struct ofp_aggregate_stats_reply *rpy;
	struct sw_table_position position;
	struct sw_flow_key match_key;
	int table_idx;

	if (*body_len < sizeof *rpy)
		return -ENOBUFS;
	rpy = body;
	*body_len = sizeof *rpy;

	memset(rpy, 0, sizeof *rpy);

	flow_extract_match(&match_key, &rq->match);
	table_idx = rq->table_id == 0xff ? 0 : rq->table_id;
	memset(&position, 0, sizeof position);
	while (table_idx < dp->chain->n_tables
	       && (rq->table_id == 0xff || rq->table_id == table_idx))
	{
		struct sw_table *table = dp->chain->tables[table_idx];
		int error;

		error = table->iterate(table, &match_key, rq->out_port, &position,
				       aggregate_stats_dump_callback, rpy);
		if (error)
			return error;

		table_idx++;
		memset(&position, 0, sizeof position);
	}

	rpy->packet_count = cpu_to_be64(rpy->packet_count);
	rpy->byte_count = cpu_to_be64(rpy->byte_count);
	rpy->flow_count = htonl(rpy->flow_count);
	return 0;
}

static int table_stats_dump(struct datapath *dp, void *state,
			    void *body, int *body_len)
{
	struct ofp_table_stats *ots;
	int n_bytes = dp->chain->n_tables * sizeof *ots;
	int i;
	if (n_bytes > *body_len)
		return -ENOBUFS;
	*body_len = n_bytes;
	for (i = 0, ots = body; i < dp->chain->n_tables; i++, ots++) {
		struct sw_table_stats stats;
		dp->chain->tables[i]->stats(dp->chain->tables[i], &stats);
		strncpy(ots->name, stats.name, sizeof ots->name);
		ots->table_id = i;
		ots->wildcards = htonl(stats.wildcards);
		memset(ots->pad, 0, sizeof ots->pad);
		ots->max_entries = htonl(stats.max_flows);
		ots->active_count = htonl(stats.n_flows);
		ots->lookup_count = cpu_to_be64(stats.n_lookup);
		ots->matched_count = cpu_to_be64(stats.n_matched);
	}
	return 0;
}

struct port_stats_state {
	int port;
};

static int port_stats_init(struct datapath *dp, const void *body, int body_len,
			   void **state)
{
	struct port_stats_state *s = kmalloc(sizeof *s, GFP_ATOMIC);
	if (!s)
		return -ENOMEM;
	s->port = 0;
	*state = s;
	return 0;
}

static int port_stats_dump(struct datapath *dp, void *state,
			   void *body, int *body_len)
{
	struct port_stats_state *s = state;
	struct ofp_port_stats *ops;
	int n_ports, max_ports;
	int i;

	max_ports = *body_len / sizeof *ops;
	if (!max_ports)
		return -ENOMEM;
	ops = body;

	n_ports = 0;
	for (i = s->port; i < DP_MAX_PORTS && n_ports < max_ports; i++) {
		struct net_bridge_port *p = dp->ports[i];
		struct net_device_stats *stats;
		if (!p)
			continue;
		stats = p->dev->get_stats(p->dev);
		ops->port_no = htons(p->port_no);
		memset(ops->pad, 0, sizeof ops->pad);
		ops->rx_packets   = cpu_to_be64(stats->rx_packets);
		ops->tx_packets   = cpu_to_be64(stats->tx_packets);
		ops->rx_bytes     = cpu_to_be64(stats->rx_bytes);
		ops->tx_bytes     = cpu_to_be64(stats->tx_bytes);
		ops->rx_dropped   = cpu_to_be64(stats->rx_dropped);
		ops->tx_dropped   = cpu_to_be64(stats->tx_dropped);
		ops->rx_errors    = cpu_to_be64(stats->rx_errors);
		ops->tx_errors    = cpu_to_be64(stats->tx_errors);
		ops->rx_frame_err = cpu_to_be64(stats->rx_frame_errors);
		ops->rx_over_err  = cpu_to_be64(stats->rx_over_errors);
		ops->rx_crc_err   = cpu_to_be64(stats->rx_crc_errors);
		ops->collisions   = cpu_to_be64(stats->collisions);
		n_ports++;
		ops++;
	}
	s->port = i;
	*body_len = n_ports * sizeof *ops;
	return n_ports >= max_ports;
}

static void port_stats_done(void *state)
{
	kfree(state);
}

struct stats_type {
	/* Minimum and maximum acceptable number of bytes in body member of
	 * struct ofp_stats_request. */
	size_t min_body, max_body;

	/* Prepares to dump some kind of statistics on 'dp'.  'body' and
	 * 'body_len' are the 'body' member of the struct ofp_stats_request.
	 * Returns zero if successful, otherwise a negative error code.
	 * May initialize '*state' to state information.  May be null if no
	 * initialization is required.*/
	int (*init)(struct datapath *dp, const void *body, int body_len,
		    void **state);

	/* Dumps statistics for 'dp' into the '*body_len' bytes at 'body', and
	 * modifies '*body_len' to reflect the number of bytes actually used.
	 * ('body' will be transmitted as the 'body' member of struct
	 * ofp_stats_reply.) */
	int (*dump)(struct datapath *dp, void *state,
		    void *body, int *body_len);

	/* Cleans any state created by the init or dump functions.  May be null
	 * if no cleanup is required. */
	void (*done)(void *state);
};

static const struct stats_type stats[] = {
	[OFPST_DESC] = {
		0,
		0,
		NULL,
		desc_stats_dump,
		NULL
	},
	[OFPST_FLOW] = {
		sizeof(struct ofp_flow_stats_request),
		sizeof(struct ofp_flow_stats_request),
		flow_stats_init,
		flow_stats_dump,
		flow_stats_done
	},
	[OFPST_AGGREGATE] = {
		sizeof(struct ofp_aggregate_stats_request),
		sizeof(struct ofp_aggregate_stats_request),
		aggregate_stats_init,
		aggregate_stats_dump,
		NULL
	},
	[OFPST_TABLE] = {
		0,
		0,
		NULL,
		table_stats_dump,
		NULL
	},
	[OFPST_PORT] = {
		0,
		0,
		port_stats_init,
		port_stats_dump,
		port_stats_done
	},
};

static int
dp_genl_openflow_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct datapath *dp;
	struct sender sender;
	const struct stats_type *s;
	struct ofp_stats_reply *osr;
	int dp_idx;
	int max_openflow_len, body_len;
	void *body;
	int err;

	/* Set up the cleanup function for this dump.  Linux 2.6.20 and later
	 * support setting up cleanup functions via the .doneit member of
	 * struct genl_ops.  This kluge supports earlier versions also. */
	cb->done = dp_genl_openflow_done;

	sender.pid = NETLINK_CB(cb->skb).pid;
	sender.seq = cb->nlh->nlmsg_seq;
	if (!cb->args[0]) {
		struct nlattr *attrs[DP_GENL_A_MAX + 1];
		struct ofp_stats_request *rq;
		struct nlattr *va;
		size_t len, body_len;
		int type;

		err = nlmsg_parse(cb->nlh, GENL_HDRLEN, attrs, DP_GENL_A_MAX,
				  dp_genl_openflow_policy);
		if (err < 0)
			return err;

		if (!attrs[DP_GENL_A_DP_IDX])
			return -EINVAL;
		dp_idx = nla_get_u16(attrs[DP_GENL_A_DP_IDX]);
		dp = dp_get(dp_idx);
		if (!dp)
			return -ENOENT;

		va = attrs[DP_GENL_A_OPENFLOW];
		len = nla_len(va);
		if (!va || len < sizeof *rq)
			return -EINVAL;

		rq = nla_data(va);
		sender.xid = rq->header.xid;
		type = ntohs(rq->type);
		if (rq->header.version != OFP_VERSION) {
			dp_send_error_msg(dp, &sender, OFPET_BAD_REQUEST,
					  OFPBRC_BAD_VERSION, rq, len);
			return -EINVAL;
		}
		if (rq->header.type != OFPT_STATS_REQUEST
		    || ntohs(rq->header.length) != len)
			return -EINVAL;

		if (type >= ARRAY_SIZE(stats) || !stats[type].dump) {
			dp_send_error_msg(dp, &sender, OFPET_BAD_REQUEST,
					  OFPBRC_BAD_STAT, rq, len);
			return -EINVAL;
		}

		s = &stats[type];
		body_len = len - offsetof(struct ofp_stats_request, body);
		if (body_len < s->min_body || body_len > s->max_body)
			return -EINVAL;

		cb->args[0] = 1;
		cb->args[1] = dp_idx;
		cb->args[2] = type;
		cb->args[3] = rq->header.xid;
		if (s->init) {
			void *state;
			err = s->init(dp, rq->body, body_len, &state);
			if (err)
				return err;
			cb->args[4] = (long) state;
		}
	} else if (cb->args[0] == 1) {
		sender.xid = cb->args[3];
		dp_idx = cb->args[1];
		s = &stats[cb->args[2]];

		dp = dp_get(dp_idx);
		if (!dp)
			return -ENOENT;
	} else {
		return 0;
	}

	osr = put_openflow_headers(dp, skb, OFPT_STATS_REPLY, &sender,
				   &max_openflow_len);
	if (IS_ERR(osr))
		return PTR_ERR(osr);
	osr->type = htons(s - stats);
	osr->flags = 0;
	resize_openflow_skb(skb, &osr->header, max_openflow_len);
	body = osr->body;
	body_len = max_openflow_len - offsetof(struct ofp_stats_reply, body);

	err = s->dump(dp, (void *) cb->args[4], body, &body_len);
	if (err >= 0) {
		if (!err)
			cb->args[0] = 2;
		else
			osr->flags = ntohs(OFPSF_REPLY_MORE);
		resize_openflow_skb(skb, &osr->header,
				    (offsetof(struct ofp_stats_reply, body)
				     + body_len));
		err = skb->len;
	}

	return err;
}

static int
dp_genl_openflow_done(struct netlink_callback *cb)
{
	if (cb->args[0]) {
		const struct stats_type *s = &stats[cb->args[2]];
		if (s->done)
			s->done((void *) cb->args[4]);
	}
	return 0;
}

static struct genl_ops dp_genl_ops_openflow = {
	.cmd = DP_GENL_C_OPENFLOW,
	.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	.policy = dp_genl_openflow_policy,
	.doit = dp_genl_openflow,
	.dumpit = dp_genl_openflow_dumpit,
};

static struct genl_ops *dp_genl_all_ops[] = {
	/* Keep this operation first.  Generic Netlink dispatching
	 * looks up operations with linear search, so we want it at the
	 * front. */
	&dp_genl_ops_openflow,

	&dp_genl_ops_add_dp,
	&dp_genl_ops_del_dp,
	&dp_genl_ops_query_dp,
	&dp_genl_ops_add_port,
	&dp_genl_ops_del_port,
};

static int dp_init_netlink(void)
{
	int err;
	int i;

	err = genl_register_family(&dp_genl_family);
	if (err)
		return err;

	for (i = 0; i < ARRAY_SIZE(dp_genl_all_ops); i++) {
		err = genl_register_ops(&dp_genl_family, dp_genl_all_ops[i]);
		if (err)
			goto err_unregister;
	}

	strcpy(mc_group.name, "openflow");
	err = genl_register_mc_group(&dp_genl_family, &mc_group);
	if (err < 0)
		goto err_unregister;

	return 0;

err_unregister:
	genl_unregister_family(&dp_genl_family);
		return err;
}

static void dp_uninit_netlink(void)
{
	genl_unregister_family(&dp_genl_family);
}

/* Set the description strings if appropriate values are available from
 * the DMI. */
static void set_desc(void)
{
	const char *uuid = dmi_get_system_info(DMI_PRODUCT_UUID);
	const char *uptr = uuid + 24;

	if (!uuid || *uuid == '\0' || strlen(uuid) != 36) 
		return;

	/* We are only interested version 1 UUIDs, since the last six bytes
	 * are an IEEE 802 MAC address. */
	if (uuid[14] != '1') 
		return;

	/* Only set if the UUID is from Nicira. */
	if (strncmp(uptr, NICIRA_OUI_STR, strlen(NICIRA_OUI_STR)))
		return;

	strlcpy(mfr_desc, dmi_get_system_info(DMI_SYS_VENDOR), sizeof(mfr_desc));
	snprintf(hw_desc, sizeof(hw_desc), "%s %s", 
			dmi_get_system_info(DMI_PRODUCT_NAME), 
			dmi_get_system_info(DMI_PRODUCT_VERSION));
	strlcpy(serial_num, dmi_get_system_info(DMI_PRODUCT_SERIAL), 
			sizeof(serial_num));
}

static int __init dp_init(void)
{
	int err;

	printk("OpenFlow %s, built "__DATE__" "__TIME__", "
	       "protocol 0x%02x\n", VERSION BUILDNR, OFP_VERSION);

	err = flow_init();
	if (err)
		goto error;

	err = register_netdevice_notifier(&dp_device_notifier);
	if (err)
		goto error_flow_exit;

	err = dp_init_netlink();
	if (err)
		goto error_unreg_notifier;

	/* Check if better descriptions of the switch are available than the
	 * defaults. */
	set_desc();

	/* Hook into callback used by the bridge to intercept packets.
	 * Parasites we are. */
	if (br_handle_frame_hook)
		printk("openflow: hijacking bridge hook\n");
	br_handle_frame_hook = dp_frame_hook;

	return 0;

error_unreg_notifier:
	unregister_netdevice_notifier(&dp_device_notifier);
error_flow_exit:
	flow_exit();
error:
	printk(KERN_EMERG "openflow: failed to install!");
	return err;
}

static void dp_cleanup(void)
{
	fwd_exit();
	dp_uninit_netlink();
	unregister_netdevice_notifier(&dp_device_notifier);
	flow_exit();
	br_handle_frame_hook = NULL;
}

module_init(dp_init);
module_exit(dp_cleanup);

MODULE_DESCRIPTION("OpenFlow switching datapath");
MODULE_AUTHOR("Copyright (c) 2007, 2008 The Board of Trustees of The Leland Stanford Junior University");
MODULE_LICENSE("GPL");
