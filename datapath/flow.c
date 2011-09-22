/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008, 2009, 2010, 2011 Nicira Networks.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#include "flow.h"
#include "datapath.h"
#include <asm/uaccess.h>
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
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ndisc.h>

#include "vlan.h"

static struct kmem_cache *flow_cache;
static unsigned int hash_seed __read_mostly;

static int check_header(struct sk_buff *skb, int len)
{
	if (unlikely(skb->len < len))
		return -EINVAL;
	if (unlikely(!pskb_may_pull(skb, len)))
		return -ENOMEM;
	return 0;
}

static inline bool arphdr_ok(struct sk_buff *skb)
{
	return pskb_may_pull(skb, skb_network_offset(skb) +
				  sizeof(struct arp_eth_header));
}

static inline int check_iphdr(struct sk_buff *skb)
{
	unsigned int nh_ofs = skb_network_offset(skb);
	unsigned int ip_len;
	int err;

	err = check_header(skb, nh_ofs + sizeof(struct iphdr));
	if (unlikely(err))
		return err;

	ip_len = ip_hdrlen(skb);
	if (unlikely(ip_len < sizeof(struct iphdr) ||
		     skb->len < nh_ofs + ip_len))
		return -EINVAL;

	skb_set_transport_header(skb, nh_ofs + ip_len);
	return 0;
}

static inline bool tcphdr_ok(struct sk_buff *skb)
{
	int th_ofs = skb_transport_offset(skb);
	int tcp_len;

	if (unlikely(!pskb_may_pull(skb, th_ofs + sizeof(struct tcphdr))))
		return false;

	tcp_len = tcp_hdrlen(skb);
	if (unlikely(tcp_len < sizeof(struct tcphdr) ||
		     skb->len < th_ofs + tcp_len))
		return false;

	return true;
}

static inline bool udphdr_ok(struct sk_buff *skb)
{
	return pskb_may_pull(skb, skb_transport_offset(skb) +
				  sizeof(struct udphdr));
}

static inline bool icmphdr_ok(struct sk_buff *skb)
{
	return pskb_may_pull(skb, skb_transport_offset(skb) +
				  sizeof(struct icmphdr));
}

u64 flow_used_time(unsigned long flow_jiffies)
{
	struct timespec cur_ts;
	u64 cur_ms, idle_ms;

	ktime_get_ts(&cur_ts);
	idle_ms = jiffies_to_msecs(jiffies - flow_jiffies);
	cur_ms = (u64)cur_ts.tv_sec * MSEC_PER_SEC +
		 cur_ts.tv_nsec / NSEC_PER_MSEC;

	return cur_ms - idle_ms;
}

#define SW_FLOW_KEY_OFFSET(field)		\
	offsetof(struct sw_flow_key, field) +	\
	FIELD_SIZEOF(struct sw_flow_key, field)

static int parse_ipv6hdr(struct sk_buff *skb, struct sw_flow_key *key,
			 int *key_lenp)
{
	unsigned int nh_ofs = skb_network_offset(skb);
	unsigned int nh_len;
	int payload_ofs;
	struct ipv6hdr *nh;
	uint8_t nexthdr;
	int err;

	*key_lenp = SW_FLOW_KEY_OFFSET(ipv6.addr);

	err = check_header(skb, nh_ofs + sizeof(*nh));
	if (unlikely(err))
		return err;

	nh = ipv6_hdr(skb);
	nexthdr = nh->nexthdr;
	payload_ofs = (u8 *)(nh + 1) - skb->data;

	key->ip.proto = NEXTHDR_NONE;
	key->ip.tos = ipv6_get_dsfield(nh) & ~INET_ECN_MASK;
	ipv6_addr_copy(&key->ipv6.addr.src, &nh->saddr);
	ipv6_addr_copy(&key->ipv6.addr.dst, &nh->daddr);

	payload_ofs = ipv6_skip_exthdr(skb, payload_ofs, &nexthdr);
	if (unlikely(payload_ofs < 0))
		return -EINVAL;

	nh_len = payload_ofs - nh_ofs;
	skb_set_transport_header(skb, nh_ofs + nh_len);
	key->ip.proto = nexthdr;
	return nh_len;
}

static bool icmp6hdr_ok(struct sk_buff *skb)
{
	return pskb_may_pull(skb, skb_transport_offset(skb) +
				  sizeof(struct icmp6hdr));
}

#define TCP_FLAGS_OFFSET 13
#define TCP_FLAG_MASK 0x3f

void flow_used(struct sw_flow *flow, struct sk_buff *skb)
{
	u8 tcp_flags = 0;

	if (flow->key.eth.type == htons(ETH_P_IP) &&
	    flow->key.ip.proto == IPPROTO_TCP) {
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

struct sw_flow_actions *flow_actions_alloc(const struct nlattr *actions)
{
	int actions_len = nla_len(actions);
	struct sw_flow_actions *sfa;

	/* At least DP_MAX_PORTS actions are required to be able to flood a
	 * packet to every port.  Factor of 2 allows for setting VLAN tags,
	 * etc. */
	if (actions_len > 2 * DP_MAX_PORTS * nla_total_size(4))
		return ERR_PTR(-EINVAL);

	sfa = kmalloc(sizeof(*sfa) + actions_len, GFP_KERNEL);
	if (!sfa)
		return ERR_PTR(-ENOMEM);

	sfa->actions_len = actions_len;
	memcpy(sfa->actions, nla_data(actions), actions_len);
	return sfa;
}

struct sw_flow *flow_alloc(void)
{
	struct sw_flow *flow;

	flow = kmem_cache_alloc(flow_cache, GFP_KERNEL);
	if (!flow)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&flow->lock);
	atomic_set(&flow->refcnt, 1);
	flow->sf_acts = NULL;
	flow->dead = false;

	return flow;
}

void flow_free_tbl(struct tbl_node *node)
{
	struct sw_flow *flow = flow_cast(node);

	flow->dead = true;
	flow_put(flow);
}

/* RCU callback used by flow_deferred_free. */
static void rcu_free_flow_callback(struct rcu_head *rcu)
{
	struct sw_flow *flow = container_of(rcu, struct sw_flow, rcu);

	flow->dead = true;
	flow_put(flow);
}

/* Schedules 'flow' to be freed after the next RCU grace period.
 * The caller must hold rcu_read_lock for this to be sensible. */
void flow_deferred_free(struct sw_flow *flow)
{
	call_rcu(&flow->rcu, rcu_free_flow_callback);
}

void flow_hold(struct sw_flow *flow)
{
	atomic_inc(&flow->refcnt);
}

void flow_put(struct sw_flow *flow)
{
	if (unlikely(!flow))
		return;

	if (atomic_dec_and_test(&flow->refcnt)) {
		kfree((struct sf_flow_acts __force *)flow->sf_acts);
		kmem_cache_free(flow_cache, flow);
	}
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

static int parse_vlan(struct sk_buff *skb, struct sw_flow_key *key)
{
	struct qtag_prefix {
		__be16 eth_type; /* ETH_P_8021Q */
		__be16 tci;
	};
	struct qtag_prefix *qp;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct qtag_prefix) +
					 sizeof(__be16))))
		return -ENOMEM;

	qp = (struct qtag_prefix *) skb->data;
	key->eth.tci = qp->tci | htons(VLAN_TAG_PRESENT);
	__skb_pull(skb, sizeof(struct qtag_prefix));

	return 0;
}

static __be16 parse_ethertype(struct sk_buff *skb)
{
	struct llc_snap_hdr {
		u8  dsap;  /* Always 0xAA */
		u8  ssap;  /* Always 0xAA */
		u8  ctrl;
		u8  oui[3];
		__be16 ethertype;
	};
	struct llc_snap_hdr *llc;
	__be16 proto;

	proto = *(__be16 *) skb->data;
	__skb_pull(skb, sizeof(__be16));

	if (ntohs(proto) >= 1536)
		return proto;

	if (skb->len < sizeof(struct llc_snap_hdr))
		return htons(ETH_P_802_2);

	if (unlikely(!pskb_may_pull(skb, sizeof(struct llc_snap_hdr))))
		return htons(0);

	llc = (struct llc_snap_hdr *) skb->data;
	if (llc->dsap != LLC_SAP_SNAP ||
	    llc->ssap != LLC_SAP_SNAP ||
	    (llc->oui[0] | llc->oui[1] | llc->oui[2]) != 0)
		return htons(ETH_P_802_2);

	__skb_pull(skb, sizeof(struct llc_snap_hdr));
	return llc->ethertype;
}

static int parse_icmpv6(struct sk_buff *skb, struct sw_flow_key *key,
			int *key_lenp, int nh_len)
{
	struct icmp6hdr *icmp = icmp6_hdr(skb);
	int error = 0;
	int key_len;

	/* The ICMPv6 type and code fields use the 16-bit transport port
	 * fields, so we need to store them in 16-bit network byte order.
	 */
	key->ipv6.tp.src = htons(icmp->icmp6_type);
	key->ipv6.tp.dst = htons(icmp->icmp6_code);
	key_len = SW_FLOW_KEY_OFFSET(ipv6.tp);

	if (icmp->icmp6_code == 0 &&
	    (icmp->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION ||
	     icmp->icmp6_type == NDISC_NEIGHBOUR_ADVERTISEMENT)) {
		int icmp_len = skb->len - skb_transport_offset(skb);
		struct nd_msg *nd;
		int offset;

		key_len = SW_FLOW_KEY_OFFSET(ipv6.nd);

		/* In order to process neighbor discovery options, we need the
		 * entire packet.
		 */
		if (unlikely(icmp_len < sizeof(*nd)))
			goto out;
		if (unlikely(skb_linearize(skb))) {
			error = -ENOMEM;
			goto out;
		}

		nd = (struct nd_msg *)skb_transport_header(skb);
		ipv6_addr_copy(&key->ipv6.nd.target, &nd->target);
		key_len = SW_FLOW_KEY_OFFSET(ipv6.nd);

		icmp_len -= sizeof(*nd);
		offset = 0;
		while (icmp_len >= 8) {
			struct nd_opt_hdr *nd_opt = (struct nd_opt_hdr *)(nd->opt + offset);
			int opt_len = nd_opt->nd_opt_len * 8;

			if (unlikely(!opt_len || opt_len > icmp_len))
				goto invalid;

			/* Store the link layer address if the appropriate
			 * option is provided.  It is considered an error if
			 * the same link layer option is specified twice.
			 */
			if (nd_opt->nd_opt_type == ND_OPT_SOURCE_LL_ADDR
			    && opt_len == 8) {
				if (unlikely(!is_zero_ether_addr(key->ipv6.nd.sll)))
					goto invalid;
				memcpy(key->ipv6.nd.sll,
				    &nd->opt[offset+sizeof(*nd_opt)], ETH_ALEN);
			} else if (nd_opt->nd_opt_type == ND_OPT_TARGET_LL_ADDR
				   && opt_len == 8) {
				if (unlikely(!is_zero_ether_addr(key->ipv6.nd.tll)))
					goto invalid;
				memcpy(key->ipv6.nd.tll,
				    &nd->opt[offset+sizeof(*nd_opt)], ETH_ALEN);
			}

			icmp_len -= opt_len;
			offset += opt_len;
		}
	}

	goto out;

invalid:
	memset(&key->ipv6.nd.target, 0, sizeof(key->ipv6.nd.target));
	memset(key->ipv6.nd.sll, 0, sizeof(key->ipv6.nd.sll));
	memset(key->ipv6.nd.tll, 0, sizeof(key->ipv6.nd.tll));

out:
	*key_lenp = key_len;
	return error;
}

/**
 * flow_extract - extracts a flow key from an Ethernet frame.
 * @skb: sk_buff that contains the frame, with skb->data pointing to the
 * Ethernet header
 * @in_port: port number on which @skb was received.
 * @key: output flow key
 * @key_lenp: length of output flow key
 * @is_frag: set to 1 if @skb contains an IPv4 fragment, or to 0 if @skb does
 * not contain an IPv4 packet or if it is not a fragment.
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
 *    - skb->transport_header: If key->dl_type is ETH_P_IP or ETH_P_IPV6
 *      on output, then just past the IP header, if one is present and
 *      of a correct length, otherwise the same as skb->network_header.
 *      For other key->dl_type values it is left untouched.
 */
int flow_extract(struct sk_buff *skb, u16 in_port, struct sw_flow_key *key,
		 int *key_lenp, bool *is_frag)
{
	int error = 0;
	int key_len = SW_FLOW_KEY_OFFSET(eth);
	struct ethhdr *eth;

	memset(key, 0, sizeof(*key));
	key->eth.tun_id = OVS_CB(skb)->tun_id;
	key->eth.in_port = in_port;
	*is_frag = false;

	skb_reset_mac_header(skb);

	/* Link layer.  We are guaranteed to have at least the 14 byte Ethernet
	 * header in the linear data area.
	 */
	eth = eth_hdr(skb);
	memcpy(key->eth.src, eth->h_source, ETH_ALEN);
	memcpy(key->eth.dst, eth->h_dest, ETH_ALEN);

	__skb_pull(skb, 2 * ETH_ALEN);

	if (vlan_tx_tag_present(skb))
		key->eth.tci = htons(vlan_get_tci(skb));
	else if (eth->h_proto == htons(ETH_P_8021Q))
		if (unlikely(parse_vlan(skb, key)))
			return -ENOMEM;

	key->eth.type = parse_ethertype(skb);
	if (unlikely(key->eth.type == htons(0)))
		return -ENOMEM;

	skb_reset_network_header(skb);
	__skb_push(skb, skb->data - skb_mac_header(skb));

	/* Network layer. */
	if (key->eth.type == htons(ETH_P_IP)) {
		struct iphdr *nh;

		key_len = SW_FLOW_KEY_OFFSET(ipv4.addr);

		error = check_iphdr(skb);
		if (unlikely(error)) {
			if (error == -EINVAL) {
				skb->transport_header = skb->network_header;
				error = 0;
			}
			goto out;
		}

		nh = ip_hdr(skb);
		key->ipv4.addr.src = nh->saddr;
		key->ipv4.addr.dst = nh->daddr;
		key->ip.tos = nh->tos & ~INET_ECN_MASK;
		key->ip.proto = nh->protocol;

		/* Transport layer. */
		if ((nh->frag_off & htons(IP_MF | IP_OFFSET)) ||
		    (skb_shinfo(skb)->gso_type & SKB_GSO_UDP))
			*is_frag = true;

		if (key->ip.proto == IPPROTO_TCP) {
			key_len = SW_FLOW_KEY_OFFSET(ipv4.tp);
			if (!*is_frag && tcphdr_ok(skb)) {
				struct tcphdr *tcp = tcp_hdr(skb);
				key->ipv4.tp.src = tcp->source;
				key->ipv4.tp.dst = tcp->dest;
			}
		} else if (key->ip.proto == IPPROTO_UDP) {
			key_len = SW_FLOW_KEY_OFFSET(ipv4.tp);
			if (!*is_frag && udphdr_ok(skb)) {
				struct udphdr *udp = udp_hdr(skb);
				key->ipv4.tp.src = udp->source;
				key->ipv4.tp.dst = udp->dest;
			}
		} else if (key->ip.proto == IPPROTO_ICMP) {
			key_len = SW_FLOW_KEY_OFFSET(ipv4.tp);
			if (!*is_frag && icmphdr_ok(skb)) {
				struct icmphdr *icmp = icmp_hdr(skb);
				/* The ICMP type and code fields use the 16-bit
				 * transport port fields, so we need to store them
				 * in 16-bit network byte order. */
				key->ipv4.tp.src = htons(icmp->type);
				key->ipv4.tp.dst = htons(icmp->code);
			}
		}

	} else if (key->eth.type == htons(ETH_P_ARP) && arphdr_ok(skb)) {
		struct arp_eth_header *arp;

		arp = (struct arp_eth_header *)skb_network_header(skb);

		if (arp->ar_hrd == htons(ARPHRD_ETHER)
				&& arp->ar_pro == htons(ETH_P_IP)
				&& arp->ar_hln == ETH_ALEN
				&& arp->ar_pln == 4) {

			/* We only match on the lower 8 bits of the opcode. */
			if (ntohs(arp->ar_op) <= 0xff)
				key->ip.proto = ntohs(arp->ar_op);

			if (key->ip.proto == ARPOP_REQUEST
					|| key->ip.proto == ARPOP_REPLY) {
				memcpy(&key->ipv4.addr.src, arp->ar_sip, sizeof(key->ipv4.addr.src));
				memcpy(&key->ipv4.addr.dst, arp->ar_tip, sizeof(key->ipv4.addr.dst));
				memcpy(key->ipv4.arp.sha, arp->ar_sha, ETH_ALEN);
				memcpy(key->ipv4.arp.tha, arp->ar_tha, ETH_ALEN);
				key_len = SW_FLOW_KEY_OFFSET(ipv4.arp);
			}
		}
	} else if (key->eth.type == htons(ETH_P_IPV6)) {
		int nh_len;             /* IPv6 Header + Extensions */

		nh_len = parse_ipv6hdr(skb, key, &key_len);
		if (unlikely(nh_len < 0)) {
			if (nh_len == -EINVAL)
				skb->transport_header = skb->network_header;
			else
				error = nh_len;
			goto out;
		}

		/* Transport layer. */
		if (key->ip.proto == NEXTHDR_TCP) {
			key_len = SW_FLOW_KEY_OFFSET(ipv6.tp);
			if (tcphdr_ok(skb)) {
				struct tcphdr *tcp = tcp_hdr(skb);
				key->ipv6.tp.src = tcp->source;
				key->ipv6.tp.dst = tcp->dest;
			}
		} else if (key->ip.proto == NEXTHDR_UDP) {
			key_len = SW_FLOW_KEY_OFFSET(ipv6.tp);
			if (udphdr_ok(skb)) {
				struct udphdr *udp = udp_hdr(skb);
				key->ipv6.tp.src = udp->source;
				key->ipv6.tp.dst = udp->dest;
			}
		} else if (key->ip.proto == NEXTHDR_ICMP) {
			key_len = SW_FLOW_KEY_OFFSET(ipv6.tp);
			if (icmp6hdr_ok(skb)) {
				error = parse_icmpv6(skb, key, &key_len, nh_len);
				if (error < 0)
					goto out;
			}
		}
	}

out:
	*key_lenp = key_len;
	return error;
}

u32 flow_hash(const struct sw_flow_key *key, int key_len)
{
	return jhash2((u32*)key, DIV_ROUND_UP(key_len, sizeof(u32)), hash_seed);
}

int flow_cmp(const struct tbl_node *node, void *key2_, int len)
{
	const struct sw_flow_key *key1 = &flow_cast(node)->key;
	const struct sw_flow_key *key2 = key2_;

	return !memcmp(key1, key2, len);
}

/* The size of the argument for each %ODP_KEY_ATTR_* Netlink attribute.  */
static const u32 key_lens[ODP_KEY_ATTR_MAX + 1] = {
	[ODP_KEY_ATTR_TUN_ID] = 8,
	[ODP_KEY_ATTR_IN_PORT] = 4,
	[ODP_KEY_ATTR_ETHERNET] = sizeof(struct odp_key_ethernet),
	[ODP_KEY_ATTR_8021Q] = sizeof(struct odp_key_8021q),
	[ODP_KEY_ATTR_ETHERTYPE] = 2,
	[ODP_KEY_ATTR_IPV4] = sizeof(struct odp_key_ipv4),
	[ODP_KEY_ATTR_IPV6] = sizeof(struct odp_key_ipv6),
	[ODP_KEY_ATTR_TCP] = sizeof(struct odp_key_tcp),
	[ODP_KEY_ATTR_UDP] = sizeof(struct odp_key_udp),
	[ODP_KEY_ATTR_ICMP] = sizeof(struct odp_key_icmp),
	[ODP_KEY_ATTR_ICMPV6] = sizeof(struct odp_key_icmpv6),
	[ODP_KEY_ATTR_ARP] = sizeof(struct odp_key_arp),
	[ODP_KEY_ATTR_ND] = sizeof(struct odp_key_nd),
};

/**
 * flow_from_nlattrs - parses Netlink attributes into a flow key.
 * @swkey: receives the extracted flow key.
 * @key_lenp: number of bytes used in @swkey.
 * @attr: Netlink attribute holding nested %ODP_KEY_ATTR_* Netlink attribute
 * sequence.
 *
 * This state machine accepts the following forms, with [] for optional
 * elements and | for alternatives:
 *
 * [tun_id] [in_port] ethernet [8021q] [ethertype \
 *              [IPv4 [TCP|UDP|ICMP] | IPv6 [TCP|UDP|ICMPv6 [ND]] | ARP]]
 */
int flow_from_nlattrs(struct sw_flow_key *swkey, int *key_lenp,
		      const struct nlattr *attr)
{
	int error = 0;
	const struct nlattr *nla;
	u16 prev_type;
	int rem;
	int key_len;

	memset(swkey, 0, sizeof(*swkey));
	swkey->eth.in_port = USHRT_MAX;
	swkey->eth.type = htons(ETH_P_802_2);
	key_len = SW_FLOW_KEY_OFFSET(eth);

	prev_type = ODP_KEY_ATTR_UNSPEC;
	nla_for_each_nested(nla, attr, rem) {
		const struct odp_key_ethernet *eth_key;
		const struct odp_key_8021q *q_key;
		const struct odp_key_ipv4 *ipv4_key;
		const struct odp_key_ipv6 *ipv6_key;
		const struct odp_key_tcp *tcp_key;
		const struct odp_key_udp *udp_key;
		const struct odp_key_icmp *icmp_key;
		const struct odp_key_icmpv6 *icmpv6_key;
		const struct odp_key_arp *arp_key;
		const struct odp_key_nd *nd_key;

                int type = nla_type(nla);

                if (type > ODP_KEY_ATTR_MAX || nla_len(nla) != key_lens[type])
                        goto invalid;

#define TRANSITION(PREV_TYPE, TYPE) (((PREV_TYPE) << 16) | (TYPE))
		switch (TRANSITION(prev_type, type)) {
		case TRANSITION(ODP_KEY_ATTR_UNSPEC, ODP_KEY_ATTR_TUN_ID):
			swkey->eth.tun_id = nla_get_be64(nla);
			break;

		case TRANSITION(ODP_KEY_ATTR_UNSPEC, ODP_KEY_ATTR_IN_PORT):
		case TRANSITION(ODP_KEY_ATTR_TUN_ID, ODP_KEY_ATTR_IN_PORT):
			if (nla_get_u32(nla) >= DP_MAX_PORTS)
				goto invalid;
			swkey->eth.in_port = nla_get_u32(nla);
			break;

		case TRANSITION(ODP_KEY_ATTR_UNSPEC, ODP_KEY_ATTR_ETHERNET):
		case TRANSITION(ODP_KEY_ATTR_TUN_ID, ODP_KEY_ATTR_ETHERNET):
		case TRANSITION(ODP_KEY_ATTR_IN_PORT, ODP_KEY_ATTR_ETHERNET):
			eth_key = nla_data(nla);
			memcpy(swkey->eth.src, eth_key->eth_src, ETH_ALEN);
			memcpy(swkey->eth.dst, eth_key->eth_dst, ETH_ALEN);
			break;

		case TRANSITION(ODP_KEY_ATTR_ETHERNET, ODP_KEY_ATTR_8021Q):
			q_key = nla_data(nla);
			/* Only standard 0x8100 VLANs currently supported. */
			if (q_key->q_tpid != htons(ETH_P_8021Q))
				goto invalid;
			if (q_key->q_tci & htons(VLAN_TAG_PRESENT))
				goto invalid;
			swkey->eth.tci = q_key->q_tci | htons(VLAN_TAG_PRESENT);
			break;

		case TRANSITION(ODP_KEY_ATTR_8021Q, ODP_KEY_ATTR_ETHERTYPE):
		case TRANSITION(ODP_KEY_ATTR_ETHERNET, ODP_KEY_ATTR_ETHERTYPE):
			swkey->eth.type = nla_get_be16(nla);
			if (ntohs(swkey->eth.type) < 1536)
				goto invalid;
			break;

		case TRANSITION(ODP_KEY_ATTR_ETHERTYPE, ODP_KEY_ATTR_IPV4):
			key_len = SW_FLOW_KEY_OFFSET(ipv4.addr);
			if (swkey->eth.type != htons(ETH_P_IP))
				goto invalid;
			ipv4_key = nla_data(nla);
			swkey->ip.proto = ipv4_key->ipv4_proto;
			swkey->ip.tos = ipv4_key->ipv4_tos;
			swkey->ipv4.addr.src = ipv4_key->ipv4_src;
			swkey->ipv4.addr.dst = ipv4_key->ipv4_dst;
			if (swkey->ip.tos & INET_ECN_MASK)
				goto invalid;
			break;

		case TRANSITION(ODP_KEY_ATTR_ETHERTYPE, ODP_KEY_ATTR_IPV6):
			key_len = SW_FLOW_KEY_OFFSET(ipv6.addr);
			if (swkey->eth.type != htons(ETH_P_IPV6))
				goto invalid;
			ipv6_key = nla_data(nla);
			swkey->ip.proto = ipv6_key->ipv6_proto;
			swkey->ip.tos = ipv6_key->ipv6_tos;
			memcpy(&swkey->ipv6.addr.src, ipv6_key->ipv6_src,
					sizeof(swkey->ipv6.addr.src));
			memcpy(&swkey->ipv6.addr.dst, ipv6_key->ipv6_dst,
					sizeof(swkey->ipv6.addr.dst));
			if (swkey->ip.tos & INET_ECN_MASK)
				goto invalid;
			break;

		case TRANSITION(ODP_KEY_ATTR_IPV4, ODP_KEY_ATTR_TCP):
			key_len = SW_FLOW_KEY_OFFSET(ipv4.tp);
			if (swkey->ip.proto != IPPROTO_TCP)
				goto invalid;
			tcp_key = nla_data(nla);
			swkey->ipv4.tp.src = tcp_key->tcp_src;
			swkey->ipv4.tp.dst = tcp_key->tcp_dst;
			break;

		case TRANSITION(ODP_KEY_ATTR_IPV6, ODP_KEY_ATTR_TCP):
			key_len = SW_FLOW_KEY_OFFSET(ipv6.tp);
			if (swkey->ip.proto != IPPROTO_TCP)
				goto invalid;
			tcp_key = nla_data(nla);
			swkey->ipv6.tp.src = tcp_key->tcp_src;
			swkey->ipv6.tp.dst = tcp_key->tcp_dst;
			break;

		case TRANSITION(ODP_KEY_ATTR_IPV4, ODP_KEY_ATTR_UDP):
			key_len = SW_FLOW_KEY_OFFSET(ipv4.tp);
			if (swkey->ip.proto != IPPROTO_UDP)
				goto invalid;
			udp_key = nla_data(nla);
			swkey->ipv4.tp.src = udp_key->udp_src;
			swkey->ipv4.tp.dst = udp_key->udp_dst;
			break;

		case TRANSITION(ODP_KEY_ATTR_IPV6, ODP_KEY_ATTR_UDP):
			key_len = SW_FLOW_KEY_OFFSET(ipv6.tp);
			if (swkey->ip.proto != IPPROTO_UDP)
				goto invalid;
			udp_key = nla_data(nla);
			swkey->ipv6.tp.src = udp_key->udp_src;
			swkey->ipv6.tp.dst = udp_key->udp_dst;
			break;

		case TRANSITION(ODP_KEY_ATTR_IPV4, ODP_KEY_ATTR_ICMP):
			key_len = SW_FLOW_KEY_OFFSET(ipv4.tp);
			if (swkey->ip.proto != IPPROTO_ICMP)
				goto invalid;
			icmp_key = nla_data(nla);
			swkey->ipv4.tp.src = htons(icmp_key->icmp_type);
			swkey->ipv4.tp.dst = htons(icmp_key->icmp_code);
			break;

		case TRANSITION(ODP_KEY_ATTR_IPV6, ODP_KEY_ATTR_ICMPV6):
			key_len = SW_FLOW_KEY_OFFSET(ipv6.tp);
			if (swkey->ip.proto != IPPROTO_ICMPV6)
				goto invalid;
			icmpv6_key = nla_data(nla);
			swkey->ipv6.tp.src = htons(icmpv6_key->icmpv6_type);
			swkey->ipv6.tp.dst = htons(icmpv6_key->icmpv6_code);
			break;

		case TRANSITION(ODP_KEY_ATTR_ETHERTYPE, ODP_KEY_ATTR_ARP):
			key_len = SW_FLOW_KEY_OFFSET(ipv4.arp);
			if (swkey->eth.type != htons(ETH_P_ARP))
				goto invalid;
			arp_key = nla_data(nla);
			swkey->ipv4.addr.src = arp_key->arp_sip;
			swkey->ipv4.addr.dst = arp_key->arp_tip;
			if (arp_key->arp_op & htons(0xff00))
				goto invalid;
			swkey->ip.proto = ntohs(arp_key->arp_op);
			memcpy(swkey->ipv4.arp.sha, arp_key->arp_sha, ETH_ALEN);
			memcpy(swkey->ipv4.arp.tha, arp_key->arp_tha, ETH_ALEN);
			break;

		case TRANSITION(ODP_KEY_ATTR_ICMPV6, ODP_KEY_ATTR_ND):
			key_len = SW_FLOW_KEY_OFFSET(ipv6.nd);
			if (swkey->ipv6.tp.src != htons(NDISC_NEIGHBOUR_SOLICITATION)
			    && swkey->ipv6.tp.src != htons(NDISC_NEIGHBOUR_ADVERTISEMENT))
				goto invalid;
			nd_key = nla_data(nla);
			memcpy(&swkey->ipv6.nd.target, nd_key->nd_target,
					sizeof(swkey->ipv6.nd.target));
			memcpy(swkey->ipv6.nd.sll, nd_key->nd_sll, ETH_ALEN);
			memcpy(swkey->ipv6.nd.tll, nd_key->nd_tll, ETH_ALEN);
			break;

		default:
			goto invalid;
		}

		prev_type = type;
	}
	if (rem)
		goto invalid;

	switch (prev_type) {
	case ODP_KEY_ATTR_UNSPEC:
		goto invalid;

	case ODP_KEY_ATTR_TUN_ID:
	case ODP_KEY_ATTR_IN_PORT:
		goto invalid;

	case ODP_KEY_ATTR_ETHERNET:
	case ODP_KEY_ATTR_8021Q:
		goto ok;

	case ODP_KEY_ATTR_ETHERTYPE:
		if (swkey->eth.type == htons(ETH_P_IP) ||
		    swkey->eth.type == htons(ETH_P_ARP))
			goto invalid;
		goto ok;

	case ODP_KEY_ATTR_IPV4:
		if (swkey->ip.proto == IPPROTO_TCP ||
		    swkey->ip.proto == IPPROTO_UDP ||
		    swkey->ip.proto == IPPROTO_ICMP)
			goto invalid;
		goto ok;

	case ODP_KEY_ATTR_IPV6:
		if (swkey->ip.proto == IPPROTO_TCP ||
		    swkey->ip.proto == IPPROTO_UDP ||
		    swkey->ip.proto == IPPROTO_ICMPV6)
			goto invalid;
		goto ok;

	case ODP_KEY_ATTR_ICMPV6:
		if (swkey->ipv6.tp.src == htons(NDISC_NEIGHBOUR_SOLICITATION) ||
		    swkey->ipv6.tp.src == htons(NDISC_NEIGHBOUR_ADVERTISEMENT))
			goto invalid;
		goto ok;

	case ODP_KEY_ATTR_TCP:
	case ODP_KEY_ATTR_UDP:
	case ODP_KEY_ATTR_ICMP:
	case ODP_KEY_ATTR_ARP:
	case ODP_KEY_ATTR_ND:
		goto ok;

	default:
		WARN_ON_ONCE(1);
	}

invalid:
	error = -EINVAL;

ok:
	WARN_ON_ONCE(!key_len && !error);
	*key_lenp = key_len;
	return error;
}

/**
 * flow_metadata_from_nlattrs - parses Netlink attributes into a flow key.
 * @in_port: receives the extracted input port.
 * @tun_id: receives the extracted tunnel ID.
 * @key: Netlink attribute holding nested %ODP_KEY_ATTR_* Netlink attribute
 * sequence.
 *
 * This parses a series of Netlink attributes that form a flow key, which must
 * take the same form accepted by flow_from_nlattrs(), but only enough of it to
 * get the metadata, that is, the parts of the flow key that cannot be
 * extracted from the packet itself.
 */
int flow_metadata_from_nlattrs(u16 *in_port, __be64 *tun_id,
			       const struct nlattr *attr)
{
	const struct nlattr *nla;
	u16 prev_type;
	int rem;

	*in_port = USHRT_MAX;
	*tun_id = 0;

	prev_type = ODP_KEY_ATTR_UNSPEC;
	nla_for_each_nested(nla, attr, rem) {
                int type = nla_type(nla);

                if (type > ODP_KEY_ATTR_MAX || nla_len(nla) != key_lens[type])
                        return -EINVAL;

		switch (TRANSITION(prev_type, type)) {
		case TRANSITION(ODP_KEY_ATTR_UNSPEC, ODP_KEY_ATTR_TUN_ID):
			*tun_id = nla_get_be64(nla);
			break;

		case TRANSITION(ODP_KEY_ATTR_UNSPEC, ODP_KEY_ATTR_IN_PORT):
		case TRANSITION(ODP_KEY_ATTR_TUN_ID, ODP_KEY_ATTR_IN_PORT):
			if (nla_get_u32(nla) >= DP_MAX_PORTS)
				return -EINVAL;
			*in_port = nla_get_u32(nla);
			break;

		default:
			return 0;
		}

		prev_type = type;
	}
	if (rem)
		return -EINVAL;

	return 0;
}

int flow_to_nlattrs(const struct sw_flow_key *swkey, struct sk_buff *skb)
{
	struct odp_key_ethernet *eth_key;
	struct nlattr *nla;

	/* This is an imperfect sanity-check that FLOW_BUFSIZE doesn't need
	 * to be updated, but will at least raise awareness when new ODP key
	 * types are added. */
	BUILD_BUG_ON(__ODP_KEY_ATTR_MAX != 14);

	if (swkey->eth.tun_id != cpu_to_be64(0))
		NLA_PUT_BE64(skb, ODP_KEY_ATTR_TUN_ID, swkey->eth.tun_id);

	if (swkey->eth.in_port != USHRT_MAX)
		NLA_PUT_U32(skb, ODP_KEY_ATTR_IN_PORT, swkey->eth.in_port);

	nla = nla_reserve(skb, ODP_KEY_ATTR_ETHERNET, sizeof(*eth_key));
	if (!nla)
		goto nla_put_failure;
	eth_key = nla_data(nla);
	memcpy(eth_key->eth_src, swkey->eth.src, ETH_ALEN);
	memcpy(eth_key->eth_dst, swkey->eth.dst, ETH_ALEN);

	if (swkey->eth.tci != htons(0)) {
		struct odp_key_8021q q_key;

		q_key.q_tpid = htons(ETH_P_8021Q);
		q_key.q_tci = swkey->eth.tci & ~htons(VLAN_TAG_PRESENT);
		NLA_PUT(skb, ODP_KEY_ATTR_8021Q, sizeof(q_key), &q_key);
	}

	if (swkey->eth.type == htons(ETH_P_802_2))
		return 0;

	NLA_PUT_BE16(skb, ODP_KEY_ATTR_ETHERTYPE, swkey->eth.type);

	if (swkey->eth.type == htons(ETH_P_IP)) {
		struct odp_key_ipv4 *ipv4_key;

		nla = nla_reserve(skb, ODP_KEY_ATTR_IPV4, sizeof(*ipv4_key));
		if (!nla)
			goto nla_put_failure;
		ipv4_key = nla_data(nla);
		memset(ipv4_key, 0, sizeof(struct odp_key_ipv4));
		ipv4_key->ipv4_src = swkey->ipv4.addr.src;
		ipv4_key->ipv4_dst = swkey->ipv4.addr.dst;
		ipv4_key->ipv4_proto = swkey->ip.proto;
		ipv4_key->ipv4_tos = swkey->ip.tos;
	} else if (swkey->eth.type == htons(ETH_P_IPV6)) {
		struct odp_key_ipv6 *ipv6_key;

		nla = nla_reserve(skb, ODP_KEY_ATTR_IPV6, sizeof(*ipv6_key));
		if (!nla)
			goto nla_put_failure;
		ipv6_key = nla_data(nla);
		memset(ipv6_key, 0, sizeof(struct odp_key_ipv6));
		memcpy(ipv6_key->ipv6_src, &swkey->ipv6.addr.src,
				sizeof(ipv6_key->ipv6_src));
		memcpy(ipv6_key->ipv6_dst, &swkey->ipv6.addr.dst,
				sizeof(ipv6_key->ipv6_dst));
		ipv6_key->ipv6_proto = swkey->ip.proto;
		ipv6_key->ipv6_tos = swkey->ip.tos;
	} else if (swkey->eth.type == htons(ETH_P_ARP)) {
		struct odp_key_arp *arp_key;

		nla = nla_reserve(skb, ODP_KEY_ATTR_ARP, sizeof(*arp_key));
		if (!nla)
			goto nla_put_failure;
		arp_key = nla_data(nla);
		memset(arp_key, 0, sizeof(struct odp_key_arp));
		arp_key->arp_sip = swkey->ipv4.addr.src;
		arp_key->arp_tip = swkey->ipv4.addr.dst;
		arp_key->arp_op = htons(swkey->ip.proto);
		memcpy(arp_key->arp_sha, swkey->ipv4.arp.sha, ETH_ALEN);
		memcpy(arp_key->arp_tha, swkey->ipv4.arp.tha, ETH_ALEN);
	}

	if (swkey->eth.type == htons(ETH_P_IP) ||
	    swkey->eth.type == htons(ETH_P_IPV6)) {

		if (swkey->ip.proto == IPPROTO_TCP) {
			struct odp_key_tcp *tcp_key;

			nla = nla_reserve(skb, ODP_KEY_ATTR_TCP, sizeof(*tcp_key));
			if (!nla)
				goto nla_put_failure;
			tcp_key = nla_data(nla);
			if (swkey->eth.type == htons(ETH_P_IP)) {
				tcp_key->tcp_src = swkey->ipv4.tp.src;
				tcp_key->tcp_dst = swkey->ipv4.tp.dst;
			} else if (swkey->eth.type == htons(ETH_P_IPV6)) {
				tcp_key->tcp_src = swkey->ipv6.tp.src;
				tcp_key->tcp_dst = swkey->ipv6.tp.dst;
			}
		} else if (swkey->ip.proto == IPPROTO_UDP) {
			struct odp_key_udp *udp_key;

			nla = nla_reserve(skb, ODP_KEY_ATTR_UDP, sizeof(*udp_key));
			if (!nla)
				goto nla_put_failure;
			udp_key = nla_data(nla);
			if (swkey->eth.type == htons(ETH_P_IP)) {
				udp_key->udp_src = swkey->ipv4.tp.src;
				udp_key->udp_dst = swkey->ipv4.tp.dst;
			} else if (swkey->eth.type == htons(ETH_P_IPV6)) {
				udp_key->udp_src = swkey->ipv6.tp.src;
				udp_key->udp_dst = swkey->ipv6.tp.dst;
			}
		} else if (swkey->eth.type == htons(ETH_P_IP) &&
			   swkey->ip.proto == IPPROTO_ICMP) {
			struct odp_key_icmp *icmp_key;

			nla = nla_reserve(skb, ODP_KEY_ATTR_ICMP, sizeof(*icmp_key));
			if (!nla)
				goto nla_put_failure;
			icmp_key = nla_data(nla);
			icmp_key->icmp_type = ntohs(swkey->ipv4.tp.src);
			icmp_key->icmp_code = ntohs(swkey->ipv4.tp.dst);
		} else if (swkey->eth.type == htons(ETH_P_IPV6) &&
			   swkey->ip.proto == IPPROTO_ICMPV6) {
			struct odp_key_icmpv6 *icmpv6_key;

			nla = nla_reserve(skb, ODP_KEY_ATTR_ICMPV6,
						sizeof(*icmpv6_key));
			if (!nla)
				goto nla_put_failure;
			icmpv6_key = nla_data(nla);
			icmpv6_key->icmpv6_type = ntohs(swkey->ipv6.tp.src);
			icmpv6_key->icmpv6_code = ntohs(swkey->ipv6.tp.dst);

			if (icmpv6_key->icmpv6_type == NDISC_NEIGHBOUR_SOLICITATION ||
			    icmpv6_key->icmpv6_type == NDISC_NEIGHBOUR_ADVERTISEMENT) {
				struct odp_key_nd *nd_key;

				nla = nla_reserve(skb, ODP_KEY_ATTR_ND, sizeof(*nd_key));
				if (!nla)
					goto nla_put_failure;
				nd_key = nla_data(nla);
				memcpy(nd_key->nd_target, &swkey->ipv6.nd.target,
							sizeof(nd_key->nd_target));
				memcpy(nd_key->nd_sll, swkey->ipv6.nd.sll, ETH_ALEN);
				memcpy(nd_key->nd_tll, swkey->ipv6.nd.tll, ETH_ALEN);
			}
		}
	}

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

/* Initializes the flow module.
 * Returns zero if successful or a negative error code. */
int flow_init(void)
{
	flow_cache = kmem_cache_create("sw_flow", sizeof(struct sw_flow), 0,
					0, NULL);
	if (flow_cache == NULL)
		return -ENOMEM;

	get_random_bytes(&hash_seed, sizeof(hash_seed));

	return 0;
}

/* Uninitializes the flow module. */
void flow_exit(void)
{
	kmem_cache_destroy(flow_cache);
}
