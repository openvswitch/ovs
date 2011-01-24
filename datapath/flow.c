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
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/inet_ecn.h>
#include <net/ip.h>

static struct kmem_cache *flow_cache;
static unsigned int hash_seed __read_mostly;

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

struct sw_flow_actions *flow_actions_alloc(u32 actions_len)
{
	struct sw_flow_actions *sfa;

	if (actions_len % NLA_ALIGNTO)
		return ERR_PTR(-EINVAL);

	/* At least DP_MAX_PORTS actions are required to be able to flood a
	 * packet to every port.  Factor of 2 allows for setting VLAN tags,
	 * etc. */
	if (actions_len > 2 * DP_MAX_PORTS * nla_total_size(4))
		return ERR_PTR(-EINVAL);

	sfa = kmalloc(sizeof(*sfa) + actions_len, GFP_KERNEL);
	if (!sfa)
		return ERR_PTR(-ENOMEM);

	sfa->actions_len = actions_len;
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

static void parse_vlan(struct sk_buff *skb, struct sw_flow_key *key)
{
	struct qtag_prefix {
		__be16 eth_type; /* ETH_P_8021Q */
		__be16 tci;
	};
	struct qtag_prefix *qp;

	if (skb->len < sizeof(struct qtag_prefix) + sizeof(__be16))
		return;

	qp = (struct qtag_prefix *) skb->data;
	key->dl_tci = qp->tci | htons(VLAN_TAG_PRESENT);
	__skb_pull(skb, sizeof(struct qtag_prefix));
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

	if (unlikely(skb->len < sizeof(struct llc_snap_hdr)))
		return htons(ETH_P_802_2);

	llc = (struct llc_snap_hdr *) skb->data;
	if (llc->dsap != LLC_SAP_SNAP ||
	    llc->ssap != LLC_SAP_SNAP ||
	    (llc->oui[0] | llc->oui[1] | llc->oui[2]) != 0)
		return htons(ETH_P_802_2);

	__skb_pull(skb, sizeof(struct llc_snap_hdr));
	return llc->ethertype;
}

/**
 * flow_extract - extracts a flow key from an Ethernet frame.
 * @skb: sk_buff that contains the frame, with skb->data pointing to the
 * Ethernet header
 * @in_port: port number on which @skb was received.
 * @key: output flow key
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
 *    - skb->transport_header: If key->dl_type is ETH_P_IP on output, then just
 *      past the IPv4 header, if one is present and of a correct length,
 *      otherwise the same as skb->network_header.  For other key->dl_type
 *      values it is left untouched.
 */
int flow_extract(struct sk_buff *skb, u16 in_port, struct sw_flow_key *key,
		 bool *is_frag)
{
	struct ethhdr *eth;

	memset(key, 0, sizeof(*key));
	key->tun_id = OVS_CB(skb)->tun_id;
	key->in_port = in_port;
	*is_frag = false;

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
		if (!(nh->frag_off & htons(IP_MF | IP_OFFSET)) &&
		    !(skb_shinfo(skb)->gso_type & SKB_GSO_UDP)) {
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
		} else
			*is_frag = true;

	} else if (key->dl_type == htons(ETH_P_ARP) && arphdr_ok(skb)) {
		struct arp_eth_header *arp;

		arp = (struct arp_eth_header *)skb_network_header(skb);

		if (arp->ar_hrd == htons(ARPHRD_ETHER)
				&& arp->ar_pro == htons(ETH_P_IP)
				&& arp->ar_hln == ETH_ALEN
				&& arp->ar_pln == 4) {

			/* We only match on the lower 8 bits of the opcode. */
			if (ntohs(arp->ar_op) <= 0xff)
				key->nw_proto = ntohs(arp->ar_op);

			if (key->nw_proto == ARPOP_REQUEST
					|| key->nw_proto == ARPOP_REPLY) {
				memcpy(&key->nw_src, arp->ar_sip, sizeof(key->nw_src));
				memcpy(&key->nw_dst, arp->ar_tip, sizeof(key->nw_dst));
			}
		}
	}
	return 0;
}

u32 flow_hash(const struct sw_flow_key *key)
{
	return jhash2((u32*)key, sizeof(*key) / sizeof(u32), hash_seed);
}

int flow_cmp(const struct tbl_node *node, void *key2_)
{
	const struct sw_flow_key *key1 = &flow_cast(node)->key;
	const struct sw_flow_key *key2 = key2_;

	return !memcmp(key1, key2, sizeof(struct sw_flow_key));
}

/**
 * flow_from_nlattrs - parses Netlink attributes into a flow key.
 * @swkey: receives the extracted flow key.
 * @key: start of %ODP_KEY_ATTR_* Netlink attribute sequence.
 * @key_len: number of bytes in @key.
 *
 * This state machine accepts the following forms, with [] for optional
 * elements and | for alternatives:
 *
 * [tun_id] in_port ethernet [8021q] [ethertype [IP [TCP|UDP|ICMP] | ARP]
 */
static int flow_from_nlattrs(struct sw_flow_key *swkey, const struct nlattr *key, u32 key_len)
{
	const struct nlattr *nla;
	u16 prev_type;
	int rem;

	memset(swkey, 0, sizeof(*swkey));
	swkey->dl_type = htons(ETH_P_802_2);

	prev_type = ODP_KEY_ATTR_UNSPEC;
	nla_for_each_attr(nla, key, key_len, rem) {
		static const u32 key_lens[ODP_KEY_ATTR_MAX + 1] = {
			[ODP_KEY_ATTR_TUN_ID] = 8,
			[ODP_KEY_ATTR_IN_PORT] = 4,
			[ODP_KEY_ATTR_ETHERNET] = sizeof(struct odp_key_ethernet),
			[ODP_KEY_ATTR_8021Q] = sizeof(struct odp_key_8021q),
			[ODP_KEY_ATTR_ETHERTYPE] = 2,
			[ODP_KEY_ATTR_IPV4] = sizeof(struct odp_key_ipv4),
			[ODP_KEY_ATTR_TCP] = sizeof(struct odp_key_tcp),
			[ODP_KEY_ATTR_UDP] = sizeof(struct odp_key_udp),
			[ODP_KEY_ATTR_ICMP] = sizeof(struct odp_key_icmp),
			[ODP_KEY_ATTR_ARP] = sizeof(struct odp_key_arp),
		};

		const struct odp_key_ethernet *eth_key;
		const struct odp_key_8021q *q_key;
		const struct odp_key_ipv4 *ipv4_key;
		const struct odp_key_tcp *tcp_key;
		const struct odp_key_udp *udp_key;
		const struct odp_key_icmp *icmp_key;
		const struct odp_key_arp *arp_key;

                int type = nla_type(nla);

                if (type > ODP_KEY_ATTR_MAX || nla_len(nla) != key_lens[type])
                        return -EINVAL;

#define TRANSITION(PREV_TYPE, TYPE) (((PREV_TYPE) << 16) | (TYPE))
		switch (TRANSITION(prev_type, type)) {
		case TRANSITION(ODP_KEY_ATTR_UNSPEC, ODP_KEY_ATTR_TUN_ID):
			swkey->tun_id = nla_get_be64(nla);
			break;

		case TRANSITION(ODP_KEY_ATTR_UNSPEC, ODP_KEY_ATTR_IN_PORT):
		case TRANSITION(ODP_KEY_ATTR_TUN_ID, ODP_KEY_ATTR_IN_PORT):
			if (nla_get_u32(nla) >= DP_MAX_PORTS)
				return -EINVAL;
			swkey->in_port = nla_get_u32(nla);
			break;

		case TRANSITION(ODP_KEY_ATTR_IN_PORT, ODP_KEY_ATTR_ETHERNET):
			eth_key = nla_data(nla);
			memcpy(swkey->dl_src, eth_key->eth_src, ETH_ALEN);
			memcpy(swkey->dl_dst, eth_key->eth_dst, ETH_ALEN);
			break;

		case TRANSITION(ODP_KEY_ATTR_ETHERNET, ODP_KEY_ATTR_8021Q):
			q_key = nla_data(nla);
			/* Only standard 0x8100 VLANs currently supported. */
			if (q_key->q_tpid != htons(ETH_P_8021Q))
				return -EINVAL;
			if (q_key->q_tci & htons(VLAN_TAG_PRESENT))
				return -EINVAL;
			swkey->dl_tci = q_key->q_tci | htons(VLAN_TAG_PRESENT);
			break;

		case TRANSITION(ODP_KEY_ATTR_8021Q, ODP_KEY_ATTR_ETHERTYPE):
		case TRANSITION(ODP_KEY_ATTR_ETHERNET, ODP_KEY_ATTR_ETHERTYPE):
			swkey->dl_type = nla_get_be16(nla);
			if (ntohs(swkey->dl_type) < 1536)
				return -EINVAL;
			break;

		case TRANSITION(ODP_KEY_ATTR_ETHERTYPE, ODP_KEY_ATTR_IPV4):
			if (swkey->dl_type != htons(ETH_P_IP))
				return -EINVAL;
			ipv4_key = nla_data(nla);
			swkey->nw_src = ipv4_key->ipv4_src;
			swkey->nw_dst = ipv4_key->ipv4_dst;
			swkey->nw_proto = ipv4_key->ipv4_proto;
			swkey->nw_tos = ipv4_key->ipv4_tos;
			if (swkey->nw_tos & INET_ECN_MASK)
				return -EINVAL;
			break;

		case TRANSITION(ODP_KEY_ATTR_IPV4, ODP_KEY_ATTR_TCP):
			if (swkey->nw_proto != IPPROTO_TCP)
				return -EINVAL;
			tcp_key = nla_data(nla);
			swkey->tp_src = tcp_key->tcp_src;
			swkey->tp_dst = tcp_key->tcp_dst;
			break;

		case TRANSITION(ODP_KEY_ATTR_IPV4, ODP_KEY_ATTR_UDP):
			if (swkey->nw_proto != IPPROTO_UDP)
				return -EINVAL;
			udp_key = nla_data(nla);
			swkey->tp_src = udp_key->udp_src;
			swkey->tp_dst = udp_key->udp_dst;
			break;

		case TRANSITION(ODP_KEY_ATTR_IPV4, ODP_KEY_ATTR_ICMP):
			if (swkey->nw_proto != IPPROTO_ICMP)
				return -EINVAL;
			icmp_key = nla_data(nla);
			swkey->tp_src = htons(icmp_key->icmp_type);
			swkey->tp_dst = htons(icmp_key->icmp_code);
			break;

		case TRANSITION(ODP_KEY_ATTR_ETHERTYPE, ODP_KEY_ATTR_ARP):
			if (swkey->dl_type != htons(ETH_P_ARP))
				return -EINVAL;
			arp_key = nla_data(nla);
			swkey->nw_src = arp_key->arp_sip;
			swkey->nw_dst = arp_key->arp_tip;
			if (arp_key->arp_op & htons(0xff00))
				return -EINVAL;
			swkey->nw_proto = ntohs(arp_key->arp_op);
			break;

		default:
			return -EINVAL;
		}

		prev_type = type;
	}
	if (rem)
		return -EINVAL;

	switch (prev_type) {
	case ODP_KEY_ATTR_UNSPEC:
		return -EINVAL;

	case ODP_KEY_ATTR_TUN_ID:
	case ODP_KEY_ATTR_IN_PORT:
		return -EINVAL;

	case ODP_KEY_ATTR_ETHERNET:
	case ODP_KEY_ATTR_8021Q:
		return 0;

	case ODP_KEY_ATTR_ETHERTYPE:
		if (swkey->dl_type == htons(ETH_P_IP) ||
		    swkey->dl_type == htons(ETH_P_ARP))
			return -EINVAL;
		return 0;

	case ODP_KEY_ATTR_IPV4:
		if (swkey->nw_proto == IPPROTO_TCP ||
		    swkey->nw_proto == IPPROTO_UDP ||
		    swkey->nw_proto == IPPROTO_ICMP)
			return -EINVAL;
		return 0;

	case ODP_KEY_ATTR_TCP:
	case ODP_KEY_ATTR_UDP:
	case ODP_KEY_ATTR_ICMP:
	case ODP_KEY_ATTR_ARP:
		return 0;
	}

	WARN_ON_ONCE(1);
	return -EINVAL;
}

u32 flow_to_nlattrs(const struct sw_flow_key *swkey, struct sk_buff *skb)
{
	struct odp_key_ethernet *eth_key;

	if (skb_tailroom(skb) < FLOW_BUFSIZE)
		return -EMSGSIZE;

	if (swkey->tun_id != cpu_to_be64(0))
		nla_put_be64(skb, ODP_KEY_ATTR_TUN_ID, swkey->tun_id);

	nla_put_u32(skb, ODP_KEY_ATTR_IN_PORT, swkey->in_port);

	eth_key = nla_data(__nla_reserve(skb, ODP_KEY_ATTR_ETHERNET, sizeof(*eth_key)));
	memcpy(eth_key->eth_src, swkey->dl_src, ETH_ALEN);
	memcpy(eth_key->eth_dst, swkey->dl_dst, ETH_ALEN);

	if (swkey->dl_tci != htons(0)) {
		struct odp_key_8021q *q_key;

		q_key = nla_data(__nla_reserve(skb, ODP_KEY_ATTR_8021Q, sizeof(*q_key)));
		q_key->q_tpid = htons(ETH_P_8021Q);
		q_key->q_tci = swkey->dl_tci & ~htons(VLAN_TAG_PRESENT);
	}

	if (swkey->dl_type == htons(ETH_P_802_2))
		goto exit;

	nla_put_be16(skb, ODP_KEY_ATTR_ETHERTYPE, swkey->dl_type);

	if (swkey->dl_type == htons(ETH_P_IP)) {
		struct odp_key_ipv4 *ipv4_key;

		ipv4_key = nla_data(__nla_reserve(skb, ODP_KEY_ATTR_IPV4, sizeof(*ipv4_key)));
		ipv4_key->ipv4_src = swkey->nw_src;
		ipv4_key->ipv4_dst = swkey->nw_dst;
		ipv4_key->ipv4_proto = swkey->nw_proto;
		ipv4_key->ipv4_tos = swkey->nw_tos;

		if (swkey->nw_proto == IPPROTO_TCP) {
			struct odp_key_tcp *tcp_key;

			tcp_key = nla_data(__nla_reserve(skb, ODP_KEY_ATTR_TCP, sizeof(*tcp_key)));
			tcp_key->tcp_src = swkey->tp_src;
			tcp_key->tcp_dst = swkey->tp_dst;
		} else if (swkey->nw_proto == IPPROTO_UDP) {
			struct odp_key_udp *udp_key;

			udp_key = nla_data(__nla_reserve(skb, ODP_KEY_ATTR_UDP, sizeof(*udp_key)));
			udp_key->udp_src = swkey->tp_src;
			udp_key->udp_dst = swkey->tp_dst;
		} else if (swkey->nw_proto == IPPROTO_ICMP) {
			struct odp_key_icmp *icmp_key;

			icmp_key = nla_data(__nla_reserve(skb, ODP_KEY_ATTR_ICMP, sizeof(*icmp_key)));
			icmp_key->icmp_type = ntohs(swkey->tp_src);
			icmp_key->icmp_code = ntohs(swkey->tp_dst);
		}
	} else if (swkey->dl_type == htons(ETH_P_ARP)) {
		struct odp_key_arp *arp_key;

		arp_key = nla_data(__nla_reserve(skb, ODP_KEY_ATTR_ARP, sizeof(*arp_key)));
		arp_key->arp_sip = swkey->nw_src;
		arp_key->arp_tip = swkey->nw_dst;
		arp_key->arp_op = htons(swkey->nw_proto);
	}

exit:
	return skb->len;
}

int flow_copy_from_user(struct sw_flow_key *swkey, const struct nlattr __user *ukey, u32 ukey_len)
{
	char key[FLOW_BUFSIZE] __aligned(NLA_ALIGNTO);

	if (ukey_len > FLOW_BUFSIZE || ukey_len % NLA_ALIGNTO)
		return -EINVAL;

	if (copy_from_user(key, ukey, ukey_len))
		return -EFAULT;

	return flow_from_nlattrs(swkey, (const struct nlattr *)key, ukey_len);
}

int flow_copy_to_user(struct nlattr __user *ukey, const struct sw_flow_key *swkey, u32 ukey_len)
{
	struct sk_buff *skb;
	int retval;

	skb = alloc_skb(FLOW_BUFSIZE, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	retval = flow_to_nlattrs(swkey, skb);
	if (copy_to_user(ukey, skb->data, min(skb->len, ukey_len)))
		retval = -EFAULT;
	kfree_skb(skb);

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

	get_random_bytes(&hash_seed, sizeof(hash_seed));

	return 0;
}

/* Uninitializes the flow module. */
void flow_exit(void)
{
	kmem_cache_destroy(flow_cache);
}
