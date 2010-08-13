/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008, 2009, 2010 Nicira Networks.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#include "flow.h"
#include "datapath.h"
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <net/llc_pdu.h>
#include <linux/kernel.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/llc.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/rcupdate.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/inet_ecn.h>
#include <net/ip.h>

#include "compat.h"

struct kmem_cache *flow_cache;
static unsigned int hash_seed;

struct arp_eth_header
{
	__be16      ar_hrd;	/* format of hardware address   */
	__be16      ar_pro;	/* format of protocol address   */
	unsigned char   ar_hln;	/* length of hardware address   */
	unsigned char   ar_pln;	/* length of protocol address   */
	__be16      ar_op;	/* ARP opcode (command)     */

	/* Ethernet+IPv4 specific members. */
	unsigned char       ar_sha[ETH_ALEN];	/* sender hardware address  */
	unsigned char       ar_sip[4];		/* sender IP address        */
	unsigned char       ar_tha[ETH_ALEN];	/* target hardware address  */
	unsigned char       ar_tip[4];		/* target IP address        */
} __attribute__((packed));

static inline int arphdr_ok(struct sk_buff *skb)
{
	int nh_ofs = skb_network_offset(skb);
	return pskb_may_pull(skb, nh_ofs + sizeof(struct arp_eth_header));
}

static inline int iphdr_ok(struct sk_buff *skb)
{
	int nh_ofs = skb_network_offset(skb);
	if (skb->len >= nh_ofs + sizeof(struct iphdr)) {
		int ip_len = ip_hdrlen(skb);
		return (ip_len >= sizeof(struct iphdr)
			&& pskb_may_pull(skb, nh_ofs + ip_len));
	}
	return 0;
}

static inline int tcphdr_ok(struct sk_buff *skb)
{
	int th_ofs = skb_transport_offset(skb);
	if (pskb_may_pull(skb, th_ofs + sizeof(struct tcphdr))) {
		int tcp_len = tcp_hdrlen(skb);
		return (tcp_len >= sizeof(struct tcphdr)
			&& skb->len >= th_ofs + tcp_len);
	}
	return 0;
}

static inline int udphdr_ok(struct sk_buff *skb)
{
	int th_ofs = skb_transport_offset(skb);
	return pskb_may_pull(skb, th_ofs + sizeof(struct udphdr));
}

static inline int icmphdr_ok(struct sk_buff *skb)
{
	int th_ofs = skb_transport_offset(skb);
	return pskb_may_pull(skb, th_ofs + sizeof(struct icmphdr));
}

#define TCP_FLAGS_OFFSET 13
#define TCP_FLAG_MASK 0x3f

void flow_used(struct sw_flow *flow, struct sk_buff *skb)
{
	u8 tcp_flags = 0;

	if (flow->key.dl_type == htons(ETH_P_IP) &&
	    flow->key.nw_proto == IPPROTO_TCP) {
		u8 *tcp = (u8 *)tcp_hdr(skb);
		tcp_flags = *(tcp + TCP_FLAGS_OFFSET) & TCP_FLAG_MASK;
	}

	spin_lock_bh(&flow->lock);
	flow->used = jiffies;
	flow->packet_count++;
	flow->byte_count += skb->len;
	flow->tcp_flags |= tcp_flags;
	spin_unlock_bh(&flow->lock);
}

struct sw_flow_actions *flow_actions_alloc(size_t n_actions)
{
	struct sw_flow_actions *sfa;

	if (n_actions > (PAGE_SIZE - sizeof *sfa) / sizeof(union odp_action))
		return ERR_PTR(-EINVAL);

	sfa = kmalloc(sizeof *sfa + n_actions * sizeof(union odp_action),
		      GFP_KERNEL);
	if (!sfa)
		return ERR_PTR(-ENOMEM);

	sfa->n_actions = n_actions;
	return sfa;
}


/* Frees 'flow' immediately. */
static void flow_free(struct sw_flow *flow)
{
	if (unlikely(!flow))
		return;
	kfree(flow->sf_acts);
	kmem_cache_free(flow_cache, flow);
}

void flow_free_tbl(struct tbl_node *node)
{
	struct sw_flow *flow = flow_cast(node);
	flow_free(flow);
}

/* RCU callback used by flow_deferred_free. */
static void rcu_free_flow_callback(struct rcu_head *rcu)
{
	struct sw_flow *flow = container_of(rcu, struct sw_flow, rcu);
	flow_free(flow);
}

/* Schedules 'flow' to be freed after the next RCU grace period.
 * The caller must hold rcu_read_lock for this to be sensible. */
void flow_deferred_free(struct sw_flow *flow)
{
	call_rcu(&flow->rcu, rcu_free_flow_callback);
}

/* RCU callback used by flow_deferred_free_acts. */
static void rcu_free_acts_callback(struct rcu_head *rcu)
{
	struct sw_flow_actions *sf_acts = container_of(rcu, 
			struct sw_flow_actions, rcu);
	kfree(sf_acts);
}

/* Schedules 'sf_acts' to be freed after the next RCU grace period.
 * The caller must hold rcu_read_lock for this to be sensible. */
void flow_deferred_free_acts(struct sw_flow_actions *sf_acts)
{
	call_rcu(&sf_acts->rcu, rcu_free_acts_callback);
}

static void parse_vlan(struct sk_buff *skb, struct odp_flow_key *key)
{
	struct qtag_prefix {
		__be16 eth_type; /* ETH_P_8021Q */
		__be16 tci;
	};
	struct qtag_prefix *qp;

	if (skb->len < sizeof(struct qtag_prefix) + sizeof(__be16))
		return;

	qp = (struct qtag_prefix *) skb->data;
	key->dl_vlan = qp->tci & htons(VLAN_VID_MASK);
	key->dl_vlan_pcp = (ntohs(qp->tci) & VLAN_PCP_MASK) >> VLAN_PCP_SHIFT;
	__skb_pull(skb, sizeof(struct qtag_prefix));
}

static __be16 parse_ethertype(struct sk_buff *skb)
{
	struct llc_snap_hdr {
		u8  dsap;  /* Always 0xAA */
		u8  ssap;  /* Always 0xAA */
		u8  ctrl;
		u8  oui[3];
		u16 ethertype;
	};
	struct llc_snap_hdr *llc;
	__be16 proto;

	proto = *(__be16 *) skb->data;
	__skb_pull(skb, sizeof(__be16));

	if (ntohs(proto) >= ODP_DL_TYPE_ETH2_CUTOFF)
		return proto;

	if (unlikely(skb->len < sizeof(struct llc_snap_hdr)))
		return htons(ODP_DL_TYPE_NOT_ETH_TYPE);

	llc = (struct llc_snap_hdr *) skb->data;
	if (llc->dsap != LLC_SAP_SNAP ||
	    llc->ssap != LLC_SAP_SNAP ||
	    (llc->oui[0] | llc->oui[1] | llc->oui[2]) != 0)
		return htons(ODP_DL_TYPE_NOT_ETH_TYPE);

	__skb_pull(skb, sizeof(struct llc_snap_hdr));
	return llc->ethertype;
}

/* Parses the Ethernet frame in 'skb', which was received on 'in_port',
 * and initializes 'key' to match.  Returns 1 if 'skb' contains an IP
 * fragment, 0 otherwise. */
int flow_extract(struct sk_buff *skb, u16 in_port, struct odp_flow_key *key)
{
	struct ethhdr *eth;
	int retval = 0;

	memset(key, 0, sizeof *key);
	key->tun_id = OVS_CB(skb)->tun_id;
	key->in_port = in_port;
	key->dl_vlan = htons(ODP_VLAN_NONE);

	if (skb->len < sizeof *eth)
		return 0;
	if (!pskb_may_pull(skb, min(skb->len, 64u)))
		return 0;

	skb_reset_mac_header(skb);

	/* Link layer. */
	eth = eth_hdr(skb);
	memcpy(key->dl_src, eth->h_source, ETH_ALEN);
	memcpy(key->dl_dst, eth->h_dest, ETH_ALEN);

	/* dl_type, dl_vlan, dl_vlan_pcp. */
	__skb_pull(skb, 2 * ETH_ALEN);
	if (eth->h_proto == htons(ETH_P_8021Q))
		parse_vlan(skb, key);
	key->dl_type = parse_ethertype(skb);
	skb_reset_network_header(skb);
	__skb_push(skb, skb->data - (unsigned char *)eth);

	/* Network layer. */
	if (key->dl_type == htons(ETH_P_IP) && iphdr_ok(skb)) {
		struct iphdr *nh = ip_hdr(skb);
		int th_ofs = skb_network_offset(skb) + nh->ihl * 4;
		key->nw_src = nh->saddr;
		key->nw_dst = nh->daddr;
		key->nw_tos = nh->tos & ~INET_ECN_MASK;
		key->nw_proto = nh->protocol;
		skb_set_transport_header(skb, th_ofs);

		/* Transport layer. */
		if (!(nh->frag_off & htons(IP_MF | IP_OFFSET))) {
			if (key->nw_proto == IPPROTO_TCP) {
				if (tcphdr_ok(skb)) {
					struct tcphdr *tcp = tcp_hdr(skb);
					key->tp_src = tcp->source;
					key->tp_dst = tcp->dest;
				} else {
					/* Avoid tricking other code into
					 * thinking that this packet has an L4
					 * header. */
					key->nw_proto = 0;
				}
			} else if (key->nw_proto == IPPROTO_UDP) {
				if (udphdr_ok(skb)) {
					struct udphdr *udp = udp_hdr(skb);
					key->tp_src = udp->source;
					key->tp_dst = udp->dest;
				} else {
					/* Avoid tricking other code into
					 * thinking that this packet has an L4
					 * header. */
					key->nw_proto = 0;
				}
			} else if (key->nw_proto == IPPROTO_ICMP) {
				if (icmphdr_ok(skb)) {
					struct icmphdr *icmp = icmp_hdr(skb);
					/* The ICMP type and code fields use the 16-bit
					 * transport port fields, so we need to store them
					 * in 16-bit network byte order. */
					key->tp_src = htons(icmp->type);
					key->tp_dst = htons(icmp->code);
				} else {
					/* Avoid tricking other code into
					 * thinking that this packet has an L4
					 * header. */
					key->nw_proto = 0;
				}
			}
		} else {
			retval = 1;
		}
	} else if (key->dl_type == htons(ETH_P_ARP) && arphdr_ok(skb)) {
		struct arp_eth_header *arp;

		arp = (struct arp_eth_header *)skb_network_header(skb);

		if (arp->ar_hrd == htons(ARPHRD_ETHER)
				&& arp->ar_pro == htons(ETH_P_IP)
				&& arp->ar_hln == ETH_ALEN
				&& arp->ar_pln == 4) {

			/* We only match on the lower 8 bits of the opcode. */
			if (ntohs(arp->ar_op) <= 0xff) {
				key->nw_proto = ntohs(arp->ar_op);
			}

			if (key->nw_proto == ARPOP_REQUEST 
					|| key->nw_proto == ARPOP_REPLY) {
				memcpy(&key->nw_src, arp->ar_sip, sizeof(key->nw_src));
				memcpy(&key->nw_dst, arp->ar_tip, sizeof(key->nw_dst));
			}
		}
	} else {
		skb_reset_transport_header(skb);
	}
	return retval;
}

u32 flow_hash(const struct odp_flow_key *key)
{
	return jhash2((u32*)key, sizeof *key / sizeof(u32), hash_seed);
}

int flow_cmp(const struct tbl_node *node, void *key2_)
{
	const struct odp_flow_key *key1 = &flow_cast(node)->key;
	const struct odp_flow_key *key2 = key2_;

	return !memcmp(key1, key2, sizeof(struct odp_flow_key));
}

/* Initializes the flow module.
 * Returns zero if successful or a negative error code. */
int flow_init(void)
{
	flow_cache = kmem_cache_create("sw_flow", sizeof(struct sw_flow), 0,
					0, NULL);
	if (flow_cache == NULL)
		return -ENOMEM;

	get_random_bytes(&hash_seed, sizeof hash_seed);

	return 0;
}

/* Uninitializes the flow module. */
void flow_exit(void)
{
	kmem_cache_destroy(flow_cache);
}
