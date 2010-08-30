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

static inline bool arphdr_ok(struct sk_buff *skb)
{
	return skb->len >= skb_network_offset(skb) + sizeof(struct arp_eth_header);
}

static inline int check_iphdr(struct sk_buff *skb)
{
	unsigned int nh_ofs = skb_network_offset(skb);
	unsigned int ip_len;

	if (skb->len < nh_ofs + sizeof(struct iphdr))
		return -EINVAL;

	ip_len = ip_hdrlen(skb);
	if (ip_len < sizeof(struct iphdr) || skb->len < nh_ofs + ip_len)
		return -EINVAL;

	/*
	 * Pull enough header bytes to account for the IP header plus the
	 * longest transport header that we parse, currently 20 bytes for TCP.
	 */
	if (!pskb_may_pull(skb, min(nh_ofs + ip_len + 20, skb->len)))
		return -ENOMEM;

	skb_set_transport_header(skb, nh_ofs + ip_len);
	return 0;
}

static inline bool tcphdr_ok(struct sk_buff *skb)
{
	int th_ofs = skb_transport_offset(skb);
	if (skb->len >= th_ofs + sizeof(struct tcphdr)) {
		int tcp_len = tcp_hdrlen(skb);
		return (tcp_len >= sizeof(struct tcphdr)
			&& skb->len >= th_ofs + tcp_len);
	}
	return false;
}

static inline bool udphdr_ok(struct sk_buff *skb)
{
	return skb->len >= skb_transport_offset(skb) + sizeof(struct udphdr);
}

static inline bool icmphdr_ok(struct sk_buff *skb)
{
	return skb->len >= skb_transport_offset(skb) + sizeof(struct icmphdr);
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

/**
 * flow_extract - extracts a flow key from an Ethernet frame.
 * @skb: sk_buff that contains the frame, with skb->data pointing to the
 * Ethernet header
 * @in_port: port number on which @skb was received.
 * @key: output flow key
 *
 * The caller must ensure that skb->len >= ETH_HLEN.
 *
 * Returns 0 if successful, otherwise a negative errno value.
 *
 * Initializes @skb header pointers as follows:
 *
 *    - skb->mac_header: the Ethernet header.
 *
 *    - skb->network_header: just past the Ethernet header, or just past the
 *      VLAN header, to the first byte of the Ethernet payload.
 *
 *    - skb->transport_header: If key->dl_type is ETH_P_IP on output, then just
 *      past the IPv4 header, if one is present and of a correct length,
 *      otherwise the same as skb->network_header.  For other key->dl_type
 *      values it is left untouched.
 *
 * Sets OVS_CB(skb)->is_frag to %true if @skb is an IPv4 fragment, otherwise to
 * %false.
 */
int flow_extract(struct sk_buff *skb, u16 in_port, struct odp_flow_key *key)
{
	struct ethhdr *eth;

	memset(key, 0, sizeof *key);
	key->tun_id = OVS_CB(skb)->tun_id;
	key->in_port = in_port;
	key->dl_vlan = htons(ODP_VLAN_NONE);
	OVS_CB(skb)->is_frag = false;

	/*
	 * We would really like to pull as many bytes as we could possibly
	 * want to parse into the linear data area.  Currently that is:
	 *
	 *    14     Ethernet header
	 *     4     VLAN header
	 *    60     max IP header with options
	 *    20     max TCP/UDP/ICMP header (don't care about options)
	 *    --
	 *    98
	 *
	 * But Xen only allocates 64 or 72 bytes for the linear data area in
	 * netback, which means that we would reallocate and copy the skb's
	 * linear data on every packet if we did that.  So instead just pull 64
	 * bytes, which is always sufficient without IP options, and then check
	 * whether we need to pull more later when we look at the IP header.
	 */
	if (!pskb_may_pull(skb, min(skb->len, 64u)))
		return -ENOMEM;

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
	if (key->dl_type == htons(ETH_P_IP)) {
		struct iphdr *nh;
		int error;

		error = check_iphdr(skb);
		if (unlikely(error)) {
			if (error == -EINVAL) {
				skb->transport_header = skb->network_header;
				return 0;
			}
			return error;
		}

		nh = ip_hdr(skb);
		key->nw_src = nh->saddr;
		key->nw_dst = nh->daddr;
		key->nw_tos = nh->tos & ~INET_ECN_MASK;
		key->nw_proto = nh->protocol;

		/* Transport layer. */
		if (!(nh->frag_off & htons(IP_MF | IP_OFFSET))) {
			if (key->nw_proto == IPPROTO_TCP) {
				if (tcphdr_ok(skb)) {
					struct tcphdr *tcp = tcp_hdr(skb);
					key->tp_src = tcp->source;
					key->tp_dst = tcp->dest;
				}
			} else if (key->nw_proto == IPPROTO_UDP) {
				if (udphdr_ok(skb)) {
					struct udphdr *udp = udp_hdr(skb);
					key->tp_src = udp->source;
					key->tp_dst = udp->dest;
				}
			} else if (key->nw_proto == IPPROTO_ICMP) {
				if (icmphdr_ok(skb)) {
					struct icmphdr *icmp = icmp_hdr(skb);
					/* The ICMP type and code fields use the 16-bit
					 * transport port fields, so we need to store them
					 * in 16-bit network byte order. */
					key->tp_src = htons(icmp->type);
					key->tp_dst = htons(icmp->code);
				}
			}
		} else {
			OVS_CB(skb)->is_frag = true;
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
	}
	return 0;
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
