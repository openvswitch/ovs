/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008, 2009, 2010 Nicira Networks.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#include "flow.h"
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <net/llc_pdu.h>
#include <linux/kernel.h>
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
#include <net/ip.h>

#include "compat.h"

struct kmem_cache *flow_cache;

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

static inline struct ovs_tcphdr *ovs_tcp_hdr(const struct sk_buff *skb)
{
	return (struct ovs_tcphdr *)skb_transport_header(skb);
}

void flow_used(struct sw_flow *flow, struct sk_buff *skb)
{
	unsigned long flags;
	u8 tcp_flags = 0;

	if (flow->key.dl_type == htons(ETH_P_IP) && iphdr_ok(skb)) {
		struct iphdr *nh = ip_hdr(skb);
		flow->ip_tos = nh->tos;
		if (flow->key.nw_proto == IPPROTO_TCP && tcphdr_ok(skb)) {
			u8 *tcp = (u8 *)tcp_hdr(skb);
			tcp_flags = *(tcp + TCP_FLAGS_OFFSET) & TCP_FLAG_MASK;
		}
	}

	spin_lock_irqsave(&flow->lock, flags);
	getnstimeofday(&flow->used);
	flow->packet_count++;
	flow->byte_count += skb->len;
	flow->tcp_flags |= tcp_flags;
	spin_unlock_irqrestore(&flow->lock, flags);
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
void flow_free(struct sw_flow *flow)
{
	if (unlikely(!flow))
		return;
	kfree(flow->sf_acts);
	kmem_cache_free(flow_cache, flow);
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

#define SNAP_OUI_LEN 3

struct eth_snap_hdr
{
	struct ethhdr eth;
	u8  dsap;  /* Always 0xAA */
	u8  ssap;  /* Always 0xAA */
	u8  ctrl;
	u8  oui[SNAP_OUI_LEN];
	u16 ethertype;
} __attribute__ ((packed));

static int is_snap(const struct eth_snap_hdr *esh)
{
	return (esh->dsap == LLC_SAP_SNAP
		&& esh->ssap == LLC_SAP_SNAP
		&& !memcmp(esh->oui, "\0\0\0", 3));
}

/* Parses the Ethernet frame in 'skb', which was received on 'in_port',
 * and initializes 'key' to match.  Returns 1 if 'skb' contains an IP
 * fragment, 0 otherwise. */
int flow_extract(struct sk_buff *skb, u16 in_port, struct odp_flow_key *key)
{
	struct ethhdr *eth;
	struct eth_snap_hdr *esh;
	int retval = 0;
	int nh_ofs;

	memset(key, 0, sizeof *key);
	key->dl_vlan = htons(ODP_VLAN_NONE);
	key->in_port = in_port;

	if (skb->len < sizeof *eth)
		return 0;
	if (!pskb_may_pull(skb, skb->len >= 64 ? 64 : skb->len)) {
		return 0;
	}

	skb_reset_mac_header(skb);
	eth = eth_hdr(skb);
	esh = (struct eth_snap_hdr *) eth;
	nh_ofs = sizeof *eth;
	if (likely(ntohs(eth->h_proto) >= ODP_DL_TYPE_ETH2_CUTOFF))
		key->dl_type = eth->h_proto;
	else if (skb->len >= sizeof *esh && is_snap(esh)) {
		key->dl_type = esh->ethertype;
		nh_ofs = sizeof *esh;
	} else {
		key->dl_type = htons(ODP_DL_TYPE_NOT_ETH_TYPE);
		if (skb->len >= nh_ofs + sizeof(struct llc_pdu_un)) {
			nh_ofs += sizeof(struct llc_pdu_un); 
		}
	}

	/* Check for a VLAN tag */
	if (key->dl_type == htons(ETH_P_8021Q) &&
	    skb->len >= nh_ofs + sizeof(struct vlan_hdr)) {
		struct vlan_hdr *vh = (struct vlan_hdr*)(skb->data + nh_ofs);
		key->dl_type = vh->h_vlan_encapsulated_proto;
		key->dl_vlan = vh->h_vlan_TCI & htons(VLAN_VID_MASK);
		key->dl_vlan_pcp = (ntohs(vh->h_vlan_TCI) & 0xe000) >> 13;
		nh_ofs += sizeof(struct vlan_hdr);
	}
	memcpy(key->dl_src, eth->h_source, ETH_ALEN);
	memcpy(key->dl_dst, eth->h_dest, ETH_ALEN);
	skb_set_network_header(skb, nh_ofs);

	/* Network layer. */
	if (key->dl_type == htons(ETH_P_IP) && iphdr_ok(skb)) {
		struct iphdr *nh = ip_hdr(skb);
		int th_ofs = nh_ofs + nh->ihl * 4;
		key->nw_src = nh->saddr;
		key->nw_dst = nh->daddr;
		key->nw_tos = nh->tos & 0xfc;
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

		if (arp->ar_hrd == htons(1)
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

/* Initializes the flow module.
 * Returns zero if successful or a negative error code. */
int flow_init(void)
{
	flow_cache = kmem_cache_create("sw_flow", sizeof(struct sw_flow), 0,
					0, NULL);
	if (flow_cache == NULL)
		return -ENOMEM;

	return 0;
}

/* Uninitializes the flow module. */
void flow_exit(void)
{
	kmem_cache_destroy(flow_cache);
}
