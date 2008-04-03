/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008 The Board of Trustees of The Leland 
 * Stanford Junior University
 */

/* Functions for managing the dp interface/device. */

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
#include <linux/inetdevice.h>
#include <linux/list.h>

#include "openflow-netlink.h"
#include "datapath.h"
#include "table.h"
#include "chain.h"
#include "forward.h"
#include "flow.h"
#include "datapath_t.h"

#include "compat.h"


/* Number of milliseconds between runs of the maintenance thread. */
#define MAINT_SLEEP_MSECS 1000

#define BRIDGE_PORT_NO_FLOOD	0x00000001 

#define UINT32_MAX			  4294967295U
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))

struct net_bridge_port {
	u16	port_no;
	u32 flags;
	struct datapath	*dp;
	struct net_device *dev;
	struct list_head node; /* Element in datapath.ports. */
};

static struct genl_family dp_genl_family;
static struct genl_multicast_group mc_group;

int dp_dev_setup(struct net_device *dev);  

/* It's hard to imagine wanting more than one datapath, but... */
#define DP_MAX 32

/* datapaths.  Protected on the read side by rcu_read_lock, on the write side
 * by dp_mutex.
 *
 * It is safe to access the datapath and net_bridge_port structures with just
 * the dp_mutex, but to access the chain you need to take the rcu_read_lock
 * also (because dp_mutex doesn't prevent flows from being destroyed).
 */
static struct datapath *dps[DP_MAX];
static DEFINE_MUTEX(dp_mutex);

static int dp_maint_func(void *data);
static int send_port_status(struct net_bridge_port *p, uint8_t status);


/* nla_unreserve - reduce amount of space reserved by nla_reserve  
 * @skb: socket buffer from which to recover room
 * @nla: netlink attribute to adjust
 * @len: amount by which to reduce attribute payload
 *
 * Reduces amount of space reserved by a call to nla_reserve.
 *
 * No other attributes may be added between calling nla_reserve and this
 * function, since it will create a hole in the message.
 */
void nla_unreserve(struct sk_buff *skb, struct nlattr *nla, int len)
{
	skb->tail -= len;
	skb->len  -= len;

	nla->nla_len -= len;
}

static void *
alloc_openflow_skb(struct datapath *dp, size_t openflow_len, uint8_t type,
		   const struct sender *sender, struct sk_buff **pskb) 
{
	size_t genl_len;
	struct sk_buff *skb;
	struct nlattr *attr;
	struct ofp_header *oh;

	genl_len = nla_total_size(sizeof(uint32_t)); /* DP_GENL_A_DP_IDX */
	genl_len += nla_total_size(openflow_len);    /* DP_GENL_A_OPENFLOW */
	skb = *pskb = genlmsg_new(genl_len, GFP_ATOMIC);
	if (!skb) {
		if (net_ratelimit())
			printk("alloc_openflow_skb: genlmsg_new failed\n");
		return NULL;
	}

	/* Assemble the Generic Netlink wrapper. */
	if (!genlmsg_put(skb,
			 sender ? sender->pid : 0,
			 sender ? sender->seq : 0,
			 &dp_genl_family, 0, DP_GENL_C_OPENFLOW))
		BUG();
	if (nla_put_u32(skb, DP_GENL_A_DP_IDX, dp->dp_idx) < 0)
		BUG();
	attr = nla_reserve(skb, DP_GENL_A_OPENFLOW, openflow_len);
	BUG_ON(!attr);
	nlmsg_end(skb, (struct nlmsghdr *) skb->data);

	/* Fill in the header. */
	oh = nla_data(attr);
	oh->version = OFP_VERSION;
	oh->type = type;
	oh->length = htons(openflow_len);
	oh->xid = sender ? sender->xid : 0;

	return oh;
}

static void
resize_openflow_skb(struct sk_buff *skb,
		    struct ofp_header *oh, size_t new_length)
{
	struct nlattr *attr;

	BUG_ON(new_length > ntohs(oh->length));
	attr = ((void *) oh) - NLA_HDRLEN;
	nla_unreserve(skb, attr, ntohs(oh->length) - new_length);
	oh->length = htons(new_length);
	nlmsg_end(skb, (struct nlmsghdr *) skb->data);
}

static int
send_openflow_skb(struct sk_buff *skb, const struct sender *sender) 
{
	int err = (sender
		   ? genlmsg_unicast(skb, sender->pid)
		   : genlmsg_multicast(skb, 0, mc_group.id, GFP_ATOMIC));
	if (err && net_ratelimit())
		printk(KERN_WARNING "send_openflow_skb: send failed: %d\n",
		       err);
	return err;
}

/* Generates a unique datapath id.  It incorporates the datapath index
 * and a hardware address, if available.  If not, it generates a random
 * one.
 */
static 
uint64_t gen_datapath_id(uint16_t dp_idx)
{
	uint64_t id;
	int i;
	struct net_device *dev;

	/* The top 16 bits are used to identify the datapath.  The lower 48 bits
	 * use an interface address.  */
	id = (uint64_t)dp_idx << 48;
	if ((dev = dev_get_by_name(&init_net, "ctl0")) 
			|| (dev = dev_get_by_name(&init_net, "eth0"))) {
		for (i=0; i<ETH_ALEN; i++) {
			id |= (uint64_t)dev->dev_addr[i] << (8*(ETH_ALEN-1 - i));
		}
		dev_put(dev);
	} else {
		/* Randomly choose the lower 48 bits if we cannot find an
		 * address and mark the most significant bit to indicate that
		 * this was randomly generated. */
		uint8_t rand[ETH_ALEN];
		get_random_bytes(rand, ETH_ALEN);
		id |= (uint64_t)1 << 63;
		for (i=0; i<ETH_ALEN; i++) {
			id |= (uint64_t)rand[i] << (8*(ETH_ALEN-1 - i));
		}
	}

	return id;
}

/* Creates a new datapath numbered 'dp_idx'.  Returns 0 for success or a
 * negative error code.
 *
 * Not called with any locks. */
static int new_dp(int dp_idx)
{
	struct datapath *dp;
	int err;

	if (dp_idx < 0 || dp_idx >= DP_MAX)
		return -EINVAL;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	mutex_lock(&dp_mutex);
	dp = rcu_dereference(dps[dp_idx]);
	if (dp != NULL) {
		err = -EEXIST;
		goto err_unlock;
	}

	err = -ENOMEM;
	dp = kzalloc(sizeof *dp, GFP_KERNEL);
	if (dp == NULL)
		goto err_unlock;

	dp->dp_idx = dp_idx;
	dp->id = gen_datapath_id(dp_idx);
	dp->chain = chain_create(dp);
	if (dp->chain == NULL)
		goto err_free_dp;
	INIT_LIST_HEAD(&dp->port_list);

#if 0
	/* Setup our "of" device */
	dp->dev.priv = dp;
	rtnl_lock();
	err = dp_dev_setup(&dp->dev);
	rtnl_unlock();
	if (err != 0) 
		printk("datapath: problem setting up 'of' device\n");
#endif

	dp->config.flags = 0;
	dp->config.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;

	dp->dp_task = kthread_run(dp_maint_func, dp, "dp%d", dp_idx);
	if (IS_ERR(dp->dp_task))
		goto err_free_dp;

	rcu_assign_pointer(dps[dp_idx], dp);
	mutex_unlock(&dp_mutex);

	return 0;

err_free_dp:
	kfree(dp);
err_unlock:
	mutex_unlock(&dp_mutex);
	module_put(THIS_MODULE);
		return err;
}

/* Find and return a free port number under 'dp'.  Called under dp_mutex. */
static int find_portno(struct datapath *dp)
{
	int i;
	for (i = 0; i < OFPP_MAX; i++)
		if (dp->ports[i] == NULL)
			return i;
	return -EXFULL;
}

static struct net_bridge_port *new_nbp(struct datapath *dp,
									   struct net_device *dev)
{
	struct net_bridge_port *p;
	int port_no;

	port_no = find_portno(dp);
	if (port_no < 0)
		return ERR_PTR(port_no);

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (p == NULL)
		return ERR_PTR(-ENOMEM);

	p->dp = dp;
	dev_hold(dev);
	p->dev = dev;
	p->port_no = port_no;

	return p;
}

/* Called with dp_mutex. */
int add_switch_port(struct datapath *dp, struct net_device *dev)
{
	struct net_bridge_port *p;

	if (dev->flags & IFF_LOOPBACK || dev->type != ARPHRD_ETHER)
		return -EINVAL;

	if (dev->br_port != NULL)
		return -EBUSY;

	p = new_nbp(dp, dev);
	if (IS_ERR(p))
		return PTR_ERR(p);

	dev_hold(dev);
	rcu_assign_pointer(dev->br_port, p);
	rtnl_lock();
	dev_set_promiscuity(dev, 1);
	rtnl_unlock();

	rcu_assign_pointer(dp->ports[p->port_no], p);
	list_add_rcu(&p->node, &dp->port_list);

	/* Notify the ctlpath that this port has been added */
	send_port_status(p, OFPPR_ADD);

	return 0;
}

/* Delete 'p' from switch.
 * Called with dp_mutex. */
static int del_switch_port(struct net_bridge_port *p)
{
	/* First drop references to device. */
	rtnl_lock();
	dev_set_promiscuity(p->dev, -1);
	rtnl_unlock();
	list_del_rcu(&p->node);
	rcu_assign_pointer(p->dp->ports[p->port_no], NULL);
	rcu_assign_pointer(p->dev->br_port, NULL);

	/* Then wait until no one is still using it, and destroy it. */
	synchronize_rcu();

	/* Notify the ctlpath that this port no longer exists */
	send_port_status(p, OFPPR_DELETE);

	dev_put(p->dev);
	kfree(p);

	return 0;
}

/* Called with dp_mutex. */
static void del_dp(struct datapath *dp)
{
	struct net_bridge_port *p, *n;

#if 0
	/* Unregister the "of" device of this dp */
	rtnl_lock();
	unregister_netdevice(&dp->dev);
	rtnl_unlock();
#endif

	kthread_stop(dp->dp_task);

	/* Drop references to DP. */
	list_for_each_entry_safe (p, n, &dp->port_list, node)
		del_switch_port(p);
	rcu_assign_pointer(dps[dp->dp_idx], NULL);

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
#if 1
		chain_timeout(dp->chain);
#else
		int count = chain_timeout(dp->chain);
		chain_print_stats(dp->chain);
		if (count)
			printk("%d flows timed out\n", count);
#endif
		msleep_interruptible(MAINT_SLEEP_MSECS);
	}
		
	return 0;
}

/*
 * Used as br_handle_frame_hook.  (Cannot run bridge at the same time, even on
 * different set of devices!)  Returns 0 if *pskb should be processed further,
 * 1 if *pskb is handled. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
/* Called with rcu_read_lock. */
static struct sk_buff *dp_frame_hook(struct net_bridge_port *p,
					 struct sk_buff *skb)
{
	struct ethhdr *eh = eth_hdr(skb);
	struct sk_buff *skb_local = NULL;


	if (compare_ether_addr(eh->h_dest, skb->dev->dev_addr) == 0) 
		return skb;

	if (is_broadcast_ether_addr(eh->h_dest)
				|| is_multicast_ether_addr(eh->h_dest)
				|| is_local_ether_addr(eh->h_dest)) 
		skb_local = skb_clone(skb, GFP_ATOMIC);

	/* Push the Ethernet header back on. */
	if (skb->protocol == htons(ETH_P_8021Q))
		skb_push(skb, VLAN_ETH_HLEN);
	else
		skb_push(skb, ETH_HLEN);

	fwd_port_input(p->dp->chain, skb, p->port_no);

	return skb_local;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static int dp_frame_hook(struct net_bridge_port *p, struct sk_buff **pskb)
{
	/* Push the Ethernet header back on. */
	if ((*pskb)->protocol == htons(ETH_P_8021Q))
		skb_push(*pskb, VLAN_ETH_HLEN);
	else
		skb_push(*pskb, ETH_HLEN);

	fwd_port_input(p->dp->chain, *pskb, p->port_no);
	return 1;
}
#else 
/* NB: This has only been tested on 2.4.35 */

/* Called without any locks (?) */
static void dp_frame_hook(struct sk_buff *skb)
{
	struct net_bridge_port *p = skb->dev->br_port;

	/* Push the Ethernet header back on. */
	if (skb->protocol == htons(ETH_P_8021Q))
		skb_push(skb, VLAN_ETH_HLEN);
	else
		skb_push(skb, ETH_HLEN);

	if (p) {
		rcu_read_lock();
		fwd_port_input(p->dp->chain, skb, p->port_no);
		rcu_read_unlock();
	} else
		kfree_skb(skb);
}
#endif

/* Forwarding output path.
 * Based on net/bridge/br_forward.c. */

/* Don't forward packets to originating port or with flooding disabled */
static inline int should_deliver(const struct net_bridge_port *p,
			const struct sk_buff *skb)
{
	if ((skb->dev == p->dev) || (p->flags & BRIDGE_PORT_NO_FLOOD)) {
		return 0;
	} 

	return 1;
}

static inline unsigned packet_length(const struct sk_buff *skb)
{
	int length = skb->len - ETH_HLEN;
	if (skb->protocol == htons(ETH_P_8021Q))
		length -= VLAN_HLEN;
	return length;
}

static int
flood(struct datapath *dp, struct sk_buff *skb)
{
	struct net_bridge_port *p;
	int prev_port;

	prev_port = -1;
	list_for_each_entry_rcu (p, &dp->port_list, node) {
		if (!should_deliver(p, skb))
			continue;
		if (prev_port != -1) {
			struct sk_buff *clone = skb_clone(skb, GFP_ATOMIC);
			if (!clone) {
				kfree_skb(skb);
				return -ENOMEM;
			}
			dp_output_port(dp, clone, prev_port); 
		}
		prev_port = p->port_no;
	}
	if (prev_port != -1)
		dp_output_port(dp, skb, prev_port);
	else
		kfree_skb(skb);

	return 0;
}

/* Marks 'skb' as having originated from 'in_port' in 'dp'.
   FIXME: how are devices reference counted? */
int dp_set_origin(struct datapath *dp, uint16_t in_port,
			   struct sk_buff *skb)
{
	if (in_port < OFPP_MAX && dp->ports[in_port]) {
		skb->dev = dp->ports[in_port]->dev;
		return 0;
	}
	return -ENOENT;
}

/* Takes ownership of 'skb' and transmits it to 'out_port' on 'dp'.
 */
int dp_output_port(struct datapath *dp, struct sk_buff *skb, int out_port)
{
	struct net_bridge_port *p;
	int len = skb->len;

	BUG_ON(!skb);
	if (out_port == OFPP_FLOOD)
		return flood(dp, skb);
	else if (out_port == OFPP_CONTROLLER)
		return dp_output_control(dp, skb, fwd_save_skb(skb), 0,
						  OFPR_ACTION);
	else if (out_port >= OFPP_MAX)
		goto bad_port;

	p = dp->ports[out_port];
	if (p == NULL)
		goto bad_port;

	skb->dev = p->dev;
	if (packet_length(skb) > skb->dev->mtu) {
		printk("dropped over-mtu packet: %d > %d\n",
					packet_length(skb), skb->dev->mtu);
		kfree_skb(skb);
		return -E2BIG;
	}

	dev_queue_xmit(skb);

	return len;

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
	opi->buffer_id      = htonl(buffer_id);
	opi->total_len      = htons(skb->len);
	opi->in_port        = htons(skb->dev->br_port->port_no);
	opi->reason         = reason;
	opi->pad            = 0;
	memcpy(opi->data, skb_mac_header(skb), fwd_len);
	err = send_openflow_skb(f_skb, NULL);

	kfree_skb(skb);

	return err;
}

static void fill_port_desc(struct net_bridge_port *p, struct ofp_phy_port *desc)
{
	desc->port_no = htons(p->port_no);
	strncpy(desc->name, p->dev->name, OFP_MAX_PORT_NAME_LEN);
	desc->name[OFP_MAX_PORT_NAME_LEN-1] = '\0';
	memcpy(desc->hw_addr, p->dev->dev_addr, ETH_ALEN);
	desc->flags = htonl(p->flags);
	desc->features = 0;
	desc->speed = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,24)
	if (p->dev->ethtool_ops && p->dev->ethtool_ops->get_settings) {
		struct ethtool_cmd ecmd = { .cmd = ETHTOOL_GSET };

		if (!p->dev->ethtool_ops->get_settings(p->dev, &ecmd)) {
			if (ecmd.supported & SUPPORTED_10baseT_Half) 
				desc->features |= OFPPF_10MB_HD;
			if (ecmd.supported & SUPPORTED_10baseT_Full)
				desc->features |= OFPPF_10MB_FD;
			if (ecmd.supported & SUPPORTED_100baseT_Half) 
				desc->features |= OFPPF_100MB_HD;
			if (ecmd.supported & SUPPORTED_100baseT_Full)
				desc->features |= OFPPF_100MB_FD;
			if (ecmd.supported & SUPPORTED_1000baseT_Half)
				desc->features |= OFPPF_1GB_HD;
			if (ecmd.supported & SUPPORTED_1000baseT_Full)
				desc->features |= OFPPF_1GB_FD;
			/* 10Gbps half-duplex doesn't exist... */
			if (ecmd.supported & SUPPORTED_10000baseT_Full)
				desc->features |= OFPPF_10GB_FD;

			desc->features = htonl(desc->features);
			desc->speed = htonl(ecmd.speed);
		}
	}
#endif
}

static int 
fill_features_reply(struct datapath *dp, struct ofp_switch_features *ofr)
{
	struct net_bridge_port *p;
	int port_count = 0;

	ofr->datapath_id    = cpu_to_be64(dp->id); 

	ofr->n_exact        = htonl(2 * TABLE_HASH_MAX_FLOWS);
	ofr->n_mac_only     = htonl(TABLE_MAC_MAX_FLOWS);
	ofr->n_compression  = 0;					   /* Not supported */
	ofr->n_general      = htonl(TABLE_LINEAR_MAX_FLOWS);
	ofr->buffer_mb      = htonl(UINT32_MAX);
	ofr->n_buffers      = htonl(N_PKT_BUFFERS);
	ofr->capabilities   = htonl(OFP_SUPPORTED_CAPABILITIES);
	ofr->actions        = htonl(OFP_SUPPORTED_ACTIONS);

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
	port_max_len = sizeof(struct ofp_phy_port) * OFPP_MAX;
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

	osc = alloc_openflow_skb(dp, sizeof *osc, OFPT_PORT_STATUS, sender,
				 &skb);
	if (!osc)
		return -ENOMEM;
	memcpy(((char *)osc) + sizeof osc->header,
	       ((char *)&dp->config) + sizeof dp->config.header,
	       sizeof dp->config - sizeof dp->config.header);
	return send_openflow_skb(skb, sender);
}

int
dp_update_port_flags(struct datapath *dp, const struct ofp_phy_port *opp)
{
	struct net_bridge_port *p;

	p = dp->ports[htons(opp->port_no)];

	/* Make sure the port id hasn't changed since this was sent */
	if (!p || memcmp(opp->hw_addr, p->dev->dev_addr, ETH_ALEN) != 0) 
		return -1;
	
	p->flags = htonl(opp->flags);

	return 0;
}


static int
send_port_status(struct net_bridge_port *p, uint8_t status)
{
	struct sk_buff *skb;
	struct ofp_port_status *ops;

	ops = alloc_openflow_skb(p->dp, sizeof *ops, OFPT_PORT_STATUS, NULL,
				 &skb);
	if (!ops)
		return -ENOMEM;
	ops->reason = status;
	fill_port_desc(p, &ops->desc);

	return send_openflow_skb(skb, NULL);
}

int 
dp_send_flow_expired(struct datapath *dp, struct sw_flow *flow)
{
	struct sk_buff *skb;
	struct ofp_flow_expired *ofe;
	unsigned long duration_j;

	ofe = alloc_openflow_skb(dp, sizeof *ofe, OFPT_FLOW_EXPIRED, 0, &skb);
	if (!ofe)
		return -ENOMEM;

	flow_fill_match(&ofe->match, &flow->key);
	duration_j = (flow->timeout - HZ * flow->max_idle) - flow->init_time;
	ofe->duration   = htonl(duration_j / HZ);
	ofe->packet_count   = cpu_to_be64(flow->packet_count);
	ofe->byte_count     = cpu_to_be64(flow->byte_count);
	return send_openflow_skb(skb, NULL);
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

	mutex_lock(&dp_mutex);
	dp = dp_get(nla_get_u32((info->attrs[DP_GENL_A_DP_IDX])));
	if (!dp)
		err = -ENOENT;
	else {
		del_dp(dp);
		err = 0;
	}
	mutex_unlock(&dp_mutex);
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
		ans_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
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
		if (!err)
			ans_skb = NULL;
	}
err:
nla_put_failure:
	if (ans_skb)
		kfree_skb(ans_skb);
	rcu_read_unlock();
	return err;
}

/*
 * Fill flow entry for nl flow query.  Called with rcu_lock  
 *
 */
static
int
dp_fill_flow(struct ofp_flow_mod* ofm, struct swt_iterator* iter)
{
	ofm->header.version  = OFP_VERSION;
	ofm->header.type     = OFPT_FLOW_MOD;
	ofm->header.length   = htons(sizeof(struct ofp_flow_mod) 
				+ sizeof(ofm->actions[0]));
	ofm->header.xid      = htonl(0);

	ofm->match.wildcards = htons(iter->flow->key.wildcards);
	ofm->match.in_port   = iter->flow->key.in_port;
	ofm->match.dl_vlan   = iter->flow->key.dl_vlan;
	memcpy(ofm->match.dl_src, iter->flow->key.dl_src, ETH_ALEN);
	memcpy(ofm->match.dl_dst, iter->flow->key.dl_dst, ETH_ALEN);
	ofm->match.dl_type   = iter->flow->key.dl_type;
	ofm->match.nw_src    = iter->flow->key.nw_src;
	ofm->match.nw_dst    = iter->flow->key.nw_dst;
	ofm->match.nw_proto  = iter->flow->key.nw_proto;
	ofm->match.tp_src    = iter->flow->key.tp_src;
	ofm->match.tp_dst    = iter->flow->key.tp_dst;
	ofm->group_id        = iter->flow->group_id;
	ofm->max_idle        = iter->flow->max_idle;
	/* TODO support multiple actions  */
	ofm->actions[0]      = iter->flow->actions[0];

	return 0;
}

/* Convenience function */
static
void* 
dp_init_nl_flow_msg(uint32_t dp_idx, uint16_t table_idx, 
		struct genl_info *info, struct sk_buff* skb)
{
	void* data;

	data = genlmsg_put_reply(skb, info, &dp_genl_family, 0, 
				DP_GENL_C_QUERY_FLOW);
	if (data == NULL)
		return NULL;
	NLA_PUT_U32(skb, DP_GENL_A_DP_IDX,   dp_idx);
	NLA_PUT_U16(skb, DP_GENL_A_TABLEIDX, table_idx);

	return data;

nla_put_failure:
	return NULL;
}

/*  Iterate through the specified table and send all flow entries over
 *  netlink to userspace.  Each flow message has the following format:
 *
 *  32bit dpix
 *  16bit tabletype
 *  32bit number of flows
 *  openflow-flow-entries
 *
 *  The full table may require multiple messages.  A message with 0 flows
 *  signifies end-of message.
 */

static 
int 
dp_dump_table(struct datapath *dp, uint16_t table_idx, struct genl_info *info, struct ofp_flow_mod* matchme) 
{ 
	struct sk_buff  *skb = 0; 
	struct sw_table *table = 0;
	struct swt_iterator iter;
	struct sw_flow_key in_flow; 
	struct nlattr   *attr;
	int count = 0, sum_count = 0;
	void *data; 
	uint8_t* ofm_ptr = 0;
	struct nlattr   *num_attr; 
	int err = -ENOMEM;

	table = dp->chain->tables[table_idx]; 
	if ( table == NULL ) {
		dprintk("dp::dp_dump_table error, non-existant table at position %d\n", table_idx);
		return -EINVAL;
	}

	if (!table->iterator(table, &iter)) {
		dprintk("dp::dp_dump_table couldn't initialize empty table iterator\n");
		return -ENOMEM;
	}

	while (iter.flow) {

		/* verify that we can fit all NL_FLOWS_PER_MESSAGE in a single
		 * sk_buf */
		if( (sizeof(dp_genl_family) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint32_t) + 
					(NL_FLOWS_PER_MESSAGE * sizeof(struct ofp_flow_mod))) > (8192 - 64)){
			dprintk("dp::dp_dump_table NL_FLOWS_PER_MESSAGE may cause overrun in skbuf\n");
			return -ENOMEM;
		}

		skb = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
		if (skb == NULL) {
			return -ENOMEM;
		}

		data = dp_init_nl_flow_msg(dp->dp_idx, table_idx, info, skb);
		if (data == NULL){
			err= -ENOMEM;	
			goto error_free_skb;
		} 

		/* reserve space to put the number of flows for this message, to
		 * be filled after the loop*/
		num_attr = nla_reserve(skb, DP_GENL_A_NUMFLOWS, sizeof(uint32_t));
		if(!num_attr){
			err = -ENOMEM;
			goto error_free_skb;
		}

		/* Only load NL_FLOWS_PER_MESSAGE flows at a time */
		attr = nla_reserve(skb, DP_GENL_A_FLOW, 
				(sizeof(struct ofp_flow_mod) + sizeof(struct ofp_action)) * NL_FLOWS_PER_MESSAGE);
		if (!attr){
			err = -ENOMEM;
			goto error_free_skb;
		}

		/* internal loop to fill NL_FLOWS_PER_MESSAGE flows */
		ofm_ptr = nla_data(attr);
		flow_extract_match(&in_flow, &matchme->match);
		while (iter.flow && count < NL_FLOWS_PER_MESSAGE) {
			if(flow_matches(&in_flow, &iter.flow->key)){
				if((err = dp_fill_flow((struct ofp_flow_mod*)ofm_ptr, &iter))) 
					goto error_free_skb;
				count++; 
				/* TODO support multiple actions  */
				ofm_ptr += sizeof(struct ofp_flow_mod) + sizeof(struct ofp_action);
			}
			table->iterator_next(&iter);
		}

		*((uint32_t*)nla_data(num_attr)) = count;
		genlmsg_end(skb, data); 

		sum_count += count; 
		count = 0;

		err = genlmsg_unicast(skb, info->snd_pid); 
		skb = 0;
	}

	/* send a sentinal message saying we're done */
	skb = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (skb == NULL) {
		return -ENOMEM;
	}
	data = dp_init_nl_flow_msg(dp->dp_idx, table_idx, info, skb);
	if (data == NULL){
		err= -ENOMEM;	
		goto error_free_skb;
	} 

	NLA_PUT_U32(skb, DP_GENL_A_NUMFLOWS,   0);
	/* dummy flow so nl doesn't complain */
	attr = nla_reserve(skb, DP_GENL_A_FLOW, sizeof(struct ofp_flow_mod));
	if (!attr){
		err = -ENOMEM;
		goto error_free_skb;
	}
	genlmsg_end(skb, data); 
	err = genlmsg_reply(skb, info); skb = 0;

nla_put_failure:
error_free_skb:
	if(skb)
		kfree_skb(skb);
	return err;
}

/* Helper function to query_table which creates and sends a message packed with
 * table stats.  Message form is:
 *
 * u32 DP_IDX
 * u32 NUM_TABLES
 * OFP_TABLE (list of OFP_TABLES)
 *
 */

static 
int 
dp_dump_table_stats(struct datapath *dp, int dp_idx, struct genl_info *info) 
{ 
	struct sk_buff   *skb = 0; 
	struct ofp_table *ot = 0;
	struct nlattr   *attr;
	struct sw_table_stats stats; 
	size_t len;
	void *data; 
	int err = -ENOMEM;
	int i = 0;
	int nt = dp->chain->n_tables;

	len = 4 + 4 + (sizeof(struct ofp_table) * nt);

	/* u32 IDX, u32 NUMTABLES, list-of-tables */
	skb = nlmsg_new(MAX(len, NLMSG_GOODSIZE), GFP_ATOMIC);
	if (skb == NULL) {
		return -ENOMEM;
	}
	
	data = genlmsg_put_reply(skb, info, &dp_genl_family, 0, 
				DP_GENL_C_QUERY_TABLE);
	if (data == NULL){
		return -ENOMEM;
	} 

	NLA_PUT_U32(skb, DP_GENL_A_DP_IDX,	dp_idx);
	NLA_PUT_U32(skb, DP_GENL_A_NUMTABLES, nt);

	/* ... we assume that all tables can fit in a single message.
	 * Probably a reasonable assumption seeing that we only have
	 * 3 atm */
	attr = nla_reserve(skb, DP_GENL_A_TABLE, (sizeof(struct ofp_table) * nt));
	if (!attr){
		err = -ENOMEM;
		goto error_free_skb;
	}

	ot = nla_data(attr);

	for (i = 0; i < nt; ++i) {
		dp->chain->tables[i]->stats(dp->chain->tables[i], &stats);
		ot->header.version = OFP_VERSION;
		ot->header.type    = OFPT_TABLE;
		ot->header.length  = htons(sizeof(struct ofp_table));
		ot->header.xid     = htonl(0);

		strncpy(ot->name, stats.name, OFP_MAX_TABLE_NAME_LEN); 
		ot->table_id  = htons(i);
		ot->n_flows   = htonl(stats.n_flows);
		ot->max_flows = htonl(stats.max_flows);
		ot++;
	}

	genlmsg_end(skb, data); 
	err = genlmsg_reply(skb, info); skb = 0;

nla_put_failure:
error_free_skb:
	if(skb)
		kfree_skb(skb);
	return err;
}

/* 
 * Queries a datapath for flow-table statistics 
 */


static int dp_genl_table_query(struct sk_buff *skb, struct genl_info *info)
{
	struct   datapath* dp;
	int	  err = 0;

	if (!info->attrs[DP_GENL_A_DP_IDX]) {
		dprintk("dp::dp_genl_table_query received message with missing attributes\n");
		return -EINVAL;
	}

	rcu_read_lock();
	dp = dp_get(nla_get_u32(info->attrs[DP_GENL_A_DP_IDX]));
	if (!dp) {
		err = -ENOENT;
		goto err_out;
	}

	err = dp_dump_table_stats(dp, nla_get_u32(info->attrs[DP_GENL_A_DP_IDX]), info); 

err_out:
	rcu_read_unlock();
	return err;
}

/* 
 * Queries a datapath for flow-table entries.
 */

static int dp_genl_flow_query(struct sk_buff *skb, struct genl_info *info)
{
	struct datapath* dp;
	struct ofp_flow_mod*  ofm;
	u16	table_idx;
	int	err = 0;

	if (!info->attrs[DP_GENL_A_DP_IDX]
				|| !info->attrs[DP_GENL_A_TABLEIDX]
				|| !info->attrs[DP_GENL_A_FLOW]) {
		dprintk("dp::dp_genl_flow_query received message with missing attributes\n");
		return -EINVAL;
	}

	rcu_read_lock();
	dp = dp_get(nla_get_u32(info->attrs[DP_GENL_A_DP_IDX]));
	if (!dp) {
		err = -ENOENT;
		goto err_out;
	}

	table_idx = nla_get_u16(info->attrs[DP_GENL_A_TABLEIDX]);

	if (dp->chain->n_tables <= table_idx){
		printk("table index %d invalid (dp has %d tables)\n",
				table_idx, dp->chain->n_tables);
	err = -EINVAL;
		goto err_out;
	}

	ofm = nla_data(info->attrs[DP_GENL_A_FLOW]);
	err = dp_dump_table(dp, table_idx, info, ofm); 

err_out:
	rcu_read_unlock();
	return err;
}

static struct nla_policy dp_genl_flow_policy[DP_GENL_A_MAX + 1] = {
	[DP_GENL_A_DP_IDX]	= { .type = NLA_U32 },
	[DP_GENL_A_TABLEIDX] = { .type = NLA_U16 },
	[DP_GENL_A_NUMFLOWS]  = { .type = NLA_U32 },
};

static struct genl_ops dp_genl_ops_query_flow = {
	.cmd	= DP_GENL_C_QUERY_FLOW,
	.flags  = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	.policy = dp_genl_flow_policy,
	.doit   = dp_genl_flow_query,
	.dumpit = NULL,
};

static struct nla_policy dp_genl_table_policy[DP_GENL_A_MAX + 1] = {
	[DP_GENL_A_DP_IDX]	= { .type = NLA_U32 },
};

static struct genl_ops dp_genl_ops_query_table = {
	.cmd	= DP_GENL_C_QUERY_TABLE,
	.flags  = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	.policy = dp_genl_table_policy,
	.doit   = dp_genl_table_query,
	.dumpit = NULL,
};


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
	mutex_lock(&dp_mutex);
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
		err = del_switch_port(port->br_port);
	}

out_put:
	dev_put(port);
out:
	mutex_unlock(&dp_mutex);
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

	rcu_read_lock();
	dp = dp_get(nla_get_u32(info->attrs[DP_GENL_A_DP_IDX]));
	if (!dp) {
		err = -ENOENT;
		goto out;
	}

	va = info->attrs[DP_GENL_A_OPENFLOW];
	if (nla_len(va) < sizeof(struct ofp_header)) {
		err = -EINVAL;
		goto out;
	}
	oh = nla_data(va);

	sender.xid = oh->xid;
	sender.pid = info->snd_pid;
	sender.seq = info->snd_seq;
	err = fwd_control_input(dp->chain, &sender, nla_data(va), nla_len(va));

out:
	rcu_read_unlock();
	return err;
}

static struct nla_policy dp_genl_openflow_policy[DP_GENL_A_MAX + 1] = {
	[DP_GENL_A_DP_IDX] = { .type = NLA_U32 },
};

static struct genl_ops dp_genl_ops_openflow = {
	.cmd = DP_GENL_C_OPENFLOW,
	.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	.policy = dp_genl_openflow_policy,
	.doit = dp_genl_openflow,
	.dumpit = NULL,
};

static struct nla_policy dp_genl_benchmark_policy[DP_GENL_A_MAX + 1] = {
	[DP_GENL_A_DP_IDX] = { .type = NLA_U32 },
	[DP_GENL_A_NPACKETS] = { .type = NLA_U32 },
	[DP_GENL_A_PSIZE] = { .type = NLA_U32 },
};

static struct genl_ops dp_genl_ops_benchmark_nl = {
	.cmd = DP_GENL_C_BENCHMARK_NL,
	.flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	.policy = dp_genl_benchmark_policy,
	.doit = dp_genl_benchmark_nl,
	.dumpit = NULL,
};

static struct genl_ops *dp_genl_all_ops[] = {
	/* Keep this operation first.  Generic Netlink dispatching
	 * looks up operations with linear search, so we want it at the
	 * front. */
	&dp_genl_ops_openflow,

	&dp_genl_ops_query_flow,
	&dp_genl_ops_query_table,
	&dp_genl_ops_add_dp,
	&dp_genl_ops_del_dp,
	&dp_genl_ops_query_dp,
	&dp_genl_ops_add_port,
	&dp_genl_ops_del_port,
	&dp_genl_ops_benchmark_nl,
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

#define DRV_NAME		"openflow"
#define DRV_VERSION	 VERSION
#define DRV_DESCRIPTION "OpenFlow switching datapath implementation"
#define DRV_COPYRIGHT   "Copyright (c) 2007, 2008 The Board of Trustees of The Leland Stanford Junior University"


static int __init dp_init(void)
{
	int err;

	printk(KERN_INFO DRV_NAME ": " DRV_DESCRIPTION "\n");
	printk(KERN_INFO DRV_NAME ": " VERSION" built on "__DATE__" "__TIME__"\n");
	printk(KERN_INFO DRV_NAME ": " DRV_COPYRIGHT "\n");

	err = flow_init();
	if (err)
		goto error;

	err = dp_init_netlink();
	if (err)
		goto error_flow_exit;

	/* Hook into callback used by the bridge to intercept packets.
	 * Parasites we are. */
	if (br_handle_frame_hook)
		printk("openflow: hijacking bridge hook\n");
	br_handle_frame_hook = dp_frame_hook;

	return 0;

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
	flow_exit();
	br_handle_frame_hook = NULL;
}

module_init(dp_init);
module_exit(dp_cleanup);

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
