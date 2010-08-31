/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/in_route.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/version.h>

#include <net/dsfield.h>
#include <net/dst.h>
#include <net/icmp.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#include <net/ipv6.h>
#endif
#include <net/route.h>
#include <net/xfrm.h>

#include "actions.h"
#include "datapath.h"
#include "table.h"
#include "tunnel.h"
#include "vport.h"
#include "vport-generic.h"

/* Protected by RCU. */
static struct tbl *port_table;

/*
 * These are just used as an optimization: they don't require any kind of
 * synchronization because we could have just as easily read the value before
 * the port change happened.
 */
static unsigned int key_local_remote_ports;
static unsigned int key_remote_ports;
static unsigned int local_remote_ports;
static unsigned int remote_ports;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
#define rt_dst(rt) (rt->dst)
#else
#define rt_dst(rt) (rt->u.dst)
#endif

static inline struct vport *tnl_vport_to_vport(const struct tnl_vport *tnl_vport)
{
	return vport_from_priv(tnl_vport);
}

static inline struct tnl_vport *tnl_vport_table_cast(const struct tbl_node *node)
{
	return container_of(node, struct tnl_vport, tbl_node);
}

/* RCU callback. */
static void free_config(struct rcu_head *rcu)
{
	struct tnl_mutable_config *c = container_of(rcu, struct tnl_mutable_config, rcu);
	kfree(c);
}

static void assign_config_rcu(struct vport *vport,
			      struct tnl_mutable_config *new_config)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct tnl_mutable_config *old_config;

	old_config = rcu_dereference(tnl_vport->mutable);
	rcu_assign_pointer(tnl_vport->mutable, new_config);
	call_rcu(&old_config->rcu, free_config);
}

static unsigned int *find_port_pool(const struct tnl_mutable_config *mutable)
{
	if (mutable->port_config.flags & TNL_F_IN_KEY_MATCH) {
		if (mutable->port_config.saddr)
			return &local_remote_ports;
		else
			return &remote_ports;
	} else {
		if (mutable->port_config.saddr)
			return &key_local_remote_ports;
		else
			return &key_remote_ports;
	}
}

enum lookup_key {
	LOOKUP_TUNNEL_TYPE	= 0,
	LOOKUP_SADDR		= 1,
	LOOKUP_DADDR		= 2,
	LOOKUP_KEY		= 3,
};

struct port_lookup_key {
	u32 vals[4];			/* Contains enum lookup_key keys. */
	const struct tnl_mutable_config *mutable;
};

/*
 * Modifies 'target' to store the rcu_dereferenced pointer that was used to do
 * the comparision.
 */
static int port_cmp(const struct tbl_node *node, void *target)
{
	const struct tnl_vport *tnl_vport = tnl_vport_table_cast(node);
	struct port_lookup_key *lookup = target;

	lookup->mutable = rcu_dereference(tnl_vport->mutable);

	return (lookup->mutable->tunnel_type == lookup->vals[LOOKUP_TUNNEL_TYPE]) &&
	       lookup->mutable->port_config.daddr == lookup->vals[LOOKUP_DADDR] &&
	       lookup->mutable->port_config.in_key == lookup->vals[LOOKUP_KEY] &&
	       lookup->mutable->port_config.saddr == lookup->vals[LOOKUP_SADDR];
}

static u32 port_hash(struct port_lookup_key *lookup)
{
	return jhash2(lookup->vals, ARRAY_SIZE(lookup->vals), 0);
}

static int add_port(struct vport *vport)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct port_lookup_key lookup;
	int err;

	if (!port_table) {
		struct tbl *new_table;

		new_table = tbl_create(0);
		if (!new_table)
			return -ENOMEM;

		rcu_assign_pointer(port_table, new_table);

	} else if (tbl_count(port_table) > tbl_n_buckets(port_table)) {
		struct tbl *old_table = port_table;
		struct tbl *new_table;

		new_table = tbl_expand(old_table);
		if (IS_ERR(new_table))
			return PTR_ERR(new_table);

		rcu_assign_pointer(port_table, new_table);
		tbl_deferred_destroy(old_table, NULL);
	}

	lookup.vals[LOOKUP_SADDR] = tnl_vport->mutable->port_config.saddr;
	lookup.vals[LOOKUP_DADDR] = tnl_vport->mutable->port_config.daddr;
	lookup.vals[LOOKUP_KEY] = tnl_vport->mutable->port_config.in_key;
	lookup.vals[LOOKUP_TUNNEL_TYPE] = tnl_vport->mutable->tunnel_type;

	err = tbl_insert(port_table, &tnl_vport->tbl_node, port_hash(&lookup));
	if (err)
		return err;

	(*find_port_pool(tnl_vport->mutable))++;

	return 0;
}

static int del_port(struct vport *vport)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	int err;

	err = tbl_remove(port_table, &tnl_vport->tbl_node);
	if (err)
		return err;

	(*find_port_pool(tnl_vport->mutable))--;

	return 0;
}

struct vport *tnl_find_port(__be32 saddr, __be32 daddr, __be32 key,
			    int tunnel_type,
			    const struct tnl_mutable_config **mutable)
{
	struct port_lookup_key lookup;
	struct tbl *table = rcu_dereference(port_table);
	struct tbl_node *tbl_node;

	if (!table)
		return NULL;

	lookup.vals[LOOKUP_SADDR] = saddr;
	lookup.vals[LOOKUP_DADDR] = daddr;

	if (tunnel_type & TNL_T_KEY_EXACT) {
		lookup.vals[LOOKUP_KEY] = key;
		lookup.vals[LOOKUP_TUNNEL_TYPE] = tunnel_type & ~TNL_T_KEY_MATCH;

		if (key_local_remote_ports) {
			tbl_node = tbl_lookup(table, &lookup, port_hash(&lookup), port_cmp);
			if (tbl_node)
				goto found;
		}

		if (key_remote_ports) {
			lookup.vals[LOOKUP_SADDR] = 0;

			tbl_node = tbl_lookup(table, &lookup, port_hash(&lookup), port_cmp);
			if (tbl_node)
				goto found;

			lookup.vals[LOOKUP_SADDR] = saddr;
		}
	}

	if (tunnel_type & TNL_T_KEY_MATCH) {
		lookup.vals[LOOKUP_KEY] = 0;
		lookup.vals[LOOKUP_TUNNEL_TYPE] = tunnel_type & ~TNL_T_KEY_EXACT;

		if (local_remote_ports) {
			tbl_node = tbl_lookup(table, &lookup, port_hash(&lookup), port_cmp);
			if (tbl_node)
				goto found;
		}

		if (remote_ports) {
			lookup.vals[LOOKUP_SADDR] = 0;

			tbl_node = tbl_lookup(table, &lookup, port_hash(&lookup), port_cmp);
			if (tbl_node)
				goto found;
		}
	}

	return NULL;

found:
	*mutable = lookup.mutable;
	return tnl_vport_to_vport(tnl_vport_table_cast(tbl_node));
}

static bool check_ipv4_address(__be32 addr)
{
	if (ipv4_is_multicast(addr) || ipv4_is_lbcast(addr)
	    || ipv4_is_loopback(addr) || ipv4_is_zeronet(addr))
		return false;

	return true;
}

static bool ipv4_should_icmp(struct sk_buff *skb)
{
	struct iphdr *old_iph = ip_hdr(skb);

	/* Don't respond to L2 broadcast. */
	if (is_multicast_ether_addr(eth_hdr(skb)->h_dest))
		return false;

	/* Don't respond to L3 broadcast or invalid addresses. */
	if (!check_ipv4_address(old_iph->daddr) ||
	    !check_ipv4_address(old_iph->saddr))
		return false;

	/* Only respond to the first fragment. */
	if (old_iph->frag_off & htons(IP_OFFSET))
		return false;

	/* Don't respond to ICMP error messages. */
	if (old_iph->protocol == IPPROTO_ICMP) {
		u8 icmp_type, *icmp_typep;

		icmp_typep = skb_header_pointer(skb, (u8 *)old_iph +
						(old_iph->ihl << 2) +
						offsetof(struct icmphdr, type) -
						skb->data, sizeof(icmp_type),
						&icmp_type);

		if (!icmp_typep)
			return false;

		if (*icmp_typep > NR_ICMP_TYPES
			|| (*icmp_typep <= ICMP_PARAMETERPROB
				&& *icmp_typep != ICMP_ECHOREPLY
				&& *icmp_typep != ICMP_ECHO))
			return false;
	}

	return true;
}

static void ipv4_build_icmp(struct sk_buff *skb, struct sk_buff *nskb,
			    unsigned int mtu, unsigned int payload_length)
{
	struct iphdr *iph, *old_iph = ip_hdr(skb);
	struct icmphdr *icmph;
	u8 *payload;

	iph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	icmph = (struct icmphdr *)skb_put(nskb, sizeof(struct icmphdr));
	payload = skb_put(nskb, payload_length);

	/* IP */
	iph->version		=	4;
	iph->ihl		=	sizeof(struct iphdr) >> 2;
	iph->tos		=	(old_iph->tos & IPTOS_TOS_MASK) |
					IPTOS_PREC_INTERNETCONTROL;
	iph->tot_len		=	htons(sizeof(struct iphdr)
					      + sizeof(struct icmphdr)
					      + payload_length);
	get_random_bytes(&iph->id, sizeof(iph->id));
	iph->frag_off		=	0;
	iph->ttl		=	IPDEFTTL;
	iph->protocol		=	IPPROTO_ICMP;
	iph->daddr		=	old_iph->saddr;
	iph->saddr		=	old_iph->daddr;

	ip_send_check(iph);

	/* ICMP */
	icmph->type		=	ICMP_DEST_UNREACH;
	icmph->code		=	ICMP_FRAG_NEEDED;
	icmph->un.gateway	=	htonl(mtu);
	icmph->checksum		=	0;

	nskb->csum = csum_partial((u8 *)icmph, sizeof(struct icmphdr), 0);
	nskb->csum = skb_copy_and_csum_bits(skb, (u8 *)old_iph - skb->data,
					    payload, payload_length,
					    nskb->csum);
	icmph->checksum = csum_fold(nskb->csum);
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static bool ipv6_should_icmp(struct sk_buff *skb)
{
	struct ipv6hdr *old_ipv6h = ipv6_hdr(skb);
	int addr_type;
	int payload_off = (u8 *)(old_ipv6h + 1) - skb->data;
	u8 nexthdr = ipv6_hdr(skb)->nexthdr;

	/* Check source address is valid. */
	addr_type = ipv6_addr_type(&old_ipv6h->saddr);
	if (addr_type & IPV6_ADDR_MULTICAST || addr_type == IPV6_ADDR_ANY)
		return false;

	/* Don't reply to unspecified addresses. */
	if (ipv6_addr_type(&old_ipv6h->daddr) == IPV6_ADDR_ANY)
		return false;

	/* Don't respond to ICMP error messages. */
	payload_off = ipv6_skip_exthdr(skb, payload_off, &nexthdr);
	if (payload_off < 0)
		return false;

	if (nexthdr == NEXTHDR_ICMP) {
		u8 icmp_type, *icmp_typep;

		icmp_typep = skb_header_pointer(skb, payload_off +
						offsetof(struct icmp6hdr,
							icmp6_type),
						sizeof(icmp_type), &icmp_type);

		if (!icmp_typep || !(*icmp_typep & ICMPV6_INFOMSG_MASK))
			return false;
	}

	return true;
}

static void ipv6_build_icmp(struct sk_buff *skb, struct sk_buff *nskb,
			    unsigned int mtu, unsigned int payload_length)
{
	struct ipv6hdr *ipv6h, *old_ipv6h = ipv6_hdr(skb);
	struct icmp6hdr *icmp6h;
	u8 *payload;

	ipv6h = (struct ipv6hdr *)skb_put(nskb, sizeof(struct ipv6hdr));
	icmp6h = (struct icmp6hdr *)skb_put(nskb, sizeof(struct icmp6hdr));
	payload = skb_put(nskb, payload_length);

	/* IPv6 */
	ipv6h->version		=	6;
	ipv6h->priority		=	0;
	memset(&ipv6h->flow_lbl, 0, sizeof(ipv6h->flow_lbl));
	ipv6h->payload_len	=	htons(sizeof(struct icmp6hdr)
					      + payload_length);
	ipv6h->nexthdr		=	NEXTHDR_ICMP;
	ipv6h->hop_limit	=	IPV6_DEFAULT_HOPLIMIT;
	ipv6_addr_copy(&ipv6h->daddr, &old_ipv6h->saddr);
	ipv6_addr_copy(&ipv6h->saddr, &old_ipv6h->daddr);

	/* ICMPv6 */
	icmp6h->icmp6_type	=	ICMPV6_PKT_TOOBIG;
	icmp6h->icmp6_code	=	0;
	icmp6h->icmp6_cksum	=	0;
	icmp6h->icmp6_mtu	=	htonl(mtu);

	nskb->csum = csum_partial((u8 *)icmp6h, sizeof(struct icmp6hdr), 0);
	nskb->csum = skb_copy_and_csum_bits(skb, (u8 *)old_ipv6h - skb->data,
					    payload, payload_length,
					    nskb->csum);
	icmp6h->icmp6_cksum = csum_ipv6_magic(&ipv6h->saddr, &ipv6h->daddr,
						sizeof(struct icmp6hdr)
						+ payload_length,
						ipv6h->nexthdr, nskb->csum);
}
#endif /* IPv6 */

bool tnl_frag_needed(struct vport *vport, const struct tnl_mutable_config *mutable,
		     struct sk_buff *skb, unsigned int mtu, __be32 flow_key)
{
	unsigned int eth_hdr_len = ETH_HLEN;
	unsigned int total_length = 0, header_length = 0, payload_length;
	struct ethhdr *eh, *old_eh = eth_hdr(skb);
	struct sk_buff *nskb;

	/* Sanity check */
	if (skb->protocol == htons(ETH_P_IP)) {
		if (mtu < IP_MIN_MTU)
			return false;

		if (!ipv4_should_icmp(skb))
			return true;
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		if (mtu < IPV6_MIN_MTU)
			return false;

		/*
		 * In theory we should do PMTUD on IPv6 multicast messages but
		 * we don't have an address to send from so just fragment.
		 */
		if (ipv6_addr_type(&ipv6_hdr(skb)->daddr) & IPV6_ADDR_MULTICAST)
			return false;

		if (!ipv6_should_icmp(skb))
			return true;
	}
#endif
	else
		return false;

	/* Allocate */
	if (old_eh->h_proto == htons(ETH_P_8021Q))
		eth_hdr_len = VLAN_ETH_HLEN;

	payload_length = skb->len - eth_hdr_len;
	if (skb->protocol == htons(ETH_P_IP)) {
		header_length = sizeof(struct iphdr) + sizeof(struct icmphdr);
		total_length = min_t(unsigned int, header_length +
						   payload_length, 576);
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else {
		header_length = sizeof(struct ipv6hdr) +
				sizeof(struct icmp6hdr);
		total_length = min_t(unsigned int, header_length +
						  payload_length, IPV6_MIN_MTU);
	}
#endif

	total_length = min(total_length, mutable->mtu);
	payload_length = total_length - header_length;

	nskb = dev_alloc_skb(NET_IP_ALIGN + eth_hdr_len + header_length +
			     payload_length);
	if (!nskb)
		return false;

	skb_reserve(nskb, NET_IP_ALIGN);

	/* Ethernet / VLAN */
	eh = (struct ethhdr *)skb_put(nskb, eth_hdr_len);
	memcpy(eh->h_dest, old_eh->h_source, ETH_ALEN);
	memcpy(eh->h_source, mutable->eth_addr, ETH_ALEN);
	nskb->protocol = eh->h_proto = old_eh->h_proto;
	if (old_eh->h_proto == htons(ETH_P_8021Q)) {
		struct vlan_ethhdr *vh = (struct vlan_ethhdr *)eh;

		vh->h_vlan_TCI = vlan_eth_hdr(skb)->h_vlan_TCI;
		vh->h_vlan_encapsulated_proto = skb->protocol;
	}
	skb_reset_mac_header(nskb);

	/* Protocol */
	if (skb->protocol == htons(ETH_P_IP))
		ipv4_build_icmp(skb, nskb, mtu, payload_length);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else
		ipv6_build_icmp(skb, nskb, mtu, payload_length);
#endif

	/*
	 * Assume that flow based keys are symmetric with respect to input
	 * and output and use the key that we were going to put on the
	 * outgoing packet for the fake received packet.  If the keys are
	 * not symmetric then PMTUD needs to be disabled since we won't have
	 * any way of synthesizing packets.
	 */
	if ((mutable->port_config.flags & (TNL_F_IN_KEY_MATCH | TNL_F_OUT_KEY_ACTION)) ==
	    (TNL_F_IN_KEY_MATCH | TNL_F_OUT_KEY_ACTION))
		OVS_CB(nskb)->tun_id = flow_key;

	compute_ip_summed(nskb, false);
	vport_receive(vport, nskb);

	return true;
}

static struct sk_buff *check_headroom(struct sk_buff *skb, int headroom)
{
	if (skb_headroom(skb) < headroom || skb_header_cloned(skb)) {
		struct sk_buff *nskb = skb_realloc_headroom(skb, headroom + 16);
		if (unlikely(!nskb)) {
			kfree_skb(skb);
			return ERR_PTR(-ENOMEM);
		}

		set_skb_csum_bits(skb, nskb);

		if (skb->sk)
			skb_set_owner_w(nskb, skb->sk);

		dev_kfree_skb(skb);
		return nskb;
	}

	return skb;
}

static inline u8 ecn_encapsulate(u8 tos, struct sk_buff *skb)
{
	u8 inner;

	if (skb->protocol == htons(ETH_P_IP))
		inner = ((struct iphdr *)skb_network_header(skb))->tos;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (skb->protocol == htons(ETH_P_IPV6))
		inner = ipv6_get_dsfield((struct ipv6hdr *)skb_network_header(skb));
#endif
	else
		inner = 0;

	return INET_ECN_encapsulate(tos, inner);
}

static inline void ecn_decapsulate(struct sk_buff *skb)
{
	u8 tos = ip_hdr(skb)->tos;

	if (INET_ECN_is_ce(tos)) {
		__be16 protocol = skb->protocol;
		unsigned int nw_header = skb_network_header(skb) - skb->data;

		if (skb->protocol == htons(ETH_P_8021Q)) {
			if (unlikely(!pskb_may_pull(skb, VLAN_ETH_HLEN)))
				return;

			protocol = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
			nw_header += VLAN_HLEN;
		}

		if (protocol == htons(ETH_P_IP)) {
			if (unlikely(!pskb_may_pull(skb, nw_header
			    + sizeof(struct iphdr))))
				return;

			IP_ECN_set_ce((struct iphdr *)(nw_header + skb->data));
		}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else if (protocol == htons(ETH_P_IPV6)) {
			if (unlikely(!pskb_may_pull(skb, nw_header
			    + sizeof(struct ipv6hdr))))
				return;

			IP6_ECN_set_ce((struct ipv6hdr *)(nw_header
							  + skb->data));
		}
#endif
	}
}

static struct sk_buff *handle_gso(struct sk_buff *skb)
{
	if (skb_is_gso(skb)) {
		struct sk_buff *nskb = skb_gso_segment(skb, 0);

		dev_kfree_skb(skb);
		return nskb;
	}

	return skb;
}

static int handle_csum_offload(struct sk_buff *skb)
{
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		return skb_checksum_help(skb);
	else {
		skb->ip_summed = CHECKSUM_NONE;
		return 0;
	}
}

/* Called with rcu_read_lock. */
void tnl_rcv(struct vport *vport, struct sk_buff *skb)
{
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, skb->dev);

	skb_dst_drop(skb);
	nf_reset(skb);
	secpath_reset(skb);
	skb_reset_network_header(skb);

	ecn_decapsulate(skb);

	skb_push(skb, ETH_HLEN);
	compute_ip_summed(skb, false);

	vport_receive(vport, skb);
}

static int build_packet(struct vport *vport, const struct tnl_mutable_config *mutable,
			struct iphdr *iph, struct rtable *rt, int max_headroom,
			int mtu, struct sk_buff *skb)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	int err;
	struct iphdr *new_iph;
	int orig_len = skb->len;
	__be16 frag_off = iph->frag_off;

	skb = check_headroom(skb, max_headroom);
	if (unlikely(IS_ERR(skb)))
		goto error;

	err = handle_csum_offload(skb);
	if (unlikely(err))
		goto error_free;

	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *old_iph = ip_hdr(skb);

		if ((old_iph->frag_off & htons(IP_DF)) &&
		    mtu < ntohs(old_iph->tot_len)) {
			if (tnl_frag_needed(vport, mutable, skb, mtu, OVS_CB(skb)->tun_id))
				goto error_free;
		}

	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		unsigned int packet_length = skb->len - ETH_HLEN
			- (eth_hdr(skb)->h_proto == htons(ETH_P_8021Q) ? VLAN_HLEN : 0);

		/* IPv6 requires PMTUD if the packet is above the minimum MTU. */
		if (packet_length > IPV6_MIN_MTU)
			frag_off = htons(IP_DF);

		if (mtu < packet_length) {
			if (tnl_frag_needed(vport, mutable, skb, mtu, OVS_CB(skb)->tun_id))
				goto error_free;
		}
	}
#endif

	new_iph = (struct iphdr *)skb_push(skb, mutable->tunnel_hlen);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));

	memcpy(new_iph, iph, sizeof(struct iphdr));
	new_iph->frag_off = frag_off;
	ip_select_ident(new_iph, &rt_dst(rt), NULL);

	memset(&IPCB(skb)->opt, 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags = 0;

	skb = tnl_vport->tnl_ops->build_header(skb, vport, mutable, &rt_dst(rt));
	if (unlikely(!skb))
		goto error;

	while (skb) {
		struct sk_buff *next = skb->next;
		int frag_len = skb->len - mutable->tunnel_hlen;

		skb->next = NULL;

		err = ip_local_out(skb);
		if (unlikely(net_xmit_eval(err) != 0)) {
			orig_len -= frag_len;
			skb = next;
			goto free_frags;
		}

		skb = next;
	};

	return orig_len;

error_free:
	kfree_skb(skb);
error:
	return 0;
free_frags:
	/*
	 * There's no point in continuing to send fragments once one has been
	 * dropped so just free the rest.  This may help improve the congestion
	 * that caused the first packet to be dropped.
	 */
	while (skb) {
		struct sk_buff *next = skb->next;
		orig_len -= skb->len - mutable->tunnel_hlen;
		kfree_skb(skb);
		skb = next;
	};
	return orig_len;
}

int tnl_send(struct vport *vport, struct sk_buff *skb)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	const struct tnl_mutable_config *mutable = rcu_dereference(tnl_vport->mutable);

	struct iphdr *old_iph;
	int orig_len;
	struct iphdr iph;
	struct rtable *rt;
	int max_headroom;
	int mtu;

	/* Validate the protocol headers before we try to use them. */
	if (skb->protocol == htons(ETH_P_8021Q)) {
		if (unlikely(!pskb_may_pull(skb, VLAN_ETH_HLEN)))
			goto error_free;

		skb->protocol = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
		skb_set_network_header(skb, VLAN_ETH_HLEN);
	}

	if (skb->protocol == htons(ETH_P_IP)) {
		if (unlikely(!pskb_may_pull(skb, skb_network_header(skb)
		    + sizeof(struct iphdr) - skb->data)))
			skb->protocol = 0;
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		if (unlikely(!pskb_may_pull(skb, skb_network_header(skb)
		    + sizeof(struct ipv6hdr) - skb->data)))
			skb->protocol = 0;
	}
#endif
	old_iph = ip_hdr(skb);

	iph.tos = mutable->port_config.tos;
	if (mutable->port_config.flags & TNL_F_TOS_INHERIT) {
		if (skb->protocol == htons(ETH_P_IP))
			iph.tos = old_iph->tos;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else if (skb->protocol == htons(ETH_P_IPV6))
			iph.tos = ipv6_get_dsfield(ipv6_hdr(skb));
#endif
	}
	iph.tos = ecn_encapsulate(iph.tos, skb);

	{
		struct flowi fl = { .nl_u = { .ip4_u =
					      { .daddr = mutable->port_config.daddr,
						.saddr = mutable->port_config.saddr,
						.tos = RT_TOS(iph.tos) } },
				    .proto = tnl_vport->tnl_ops->ipproto };

		if (unlikely(ip_route_output_key(&init_net, &rt, &fl)))
			goto error_free;
	}

	iph.ttl = mutable->port_config.ttl;
	if (mutable->port_config.flags & TNL_F_TTL_INHERIT) {
		if (skb->protocol == htons(ETH_P_IP))
			iph.ttl = old_iph->ttl;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else if (skb->protocol == htons(ETH_P_IPV6))
			iph.ttl = ipv6_hdr(skb)->hop_limit;
#endif
	}
	if (!iph.ttl)
		iph.ttl = dst_metric(&rt_dst(rt), RTAX_HOPLIMIT);

	iph.frag_off = (mutable->port_config.flags & TNL_F_PMTUD) ? htons(IP_DF) : 0;
	if (iph.frag_off)
		mtu = dst_mtu(&rt_dst(rt))
			- ETH_HLEN
			- mutable->tunnel_hlen
			- (eth_hdr(skb)->h_proto == htons(ETH_P_8021Q) ? VLAN_HLEN : 0);
	else
		mtu = mutable->mtu;

	if (skb->protocol == htons(ETH_P_IP)) {
		iph.frag_off |= old_iph->frag_off & htons(IP_DF);
		mtu = max(mtu, IP_MIN_MTU);
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (skb->protocol == htons(ETH_P_IPV6))
		mtu = max(mtu, IPV6_MIN_MTU);
#endif

	iph.version = 4;
	iph.ihl = sizeof(struct iphdr) >> 2;
	iph.protocol = tnl_vport->tnl_ops->ipproto;
	iph.daddr = rt->rt_dst;
	iph.saddr = rt->rt_src;

	nf_reset(skb);
	secpath_reset(skb);
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt_dst(rt));

	/*
	 * If we are doing GSO on a pskb it is better to make sure that the
	 * headroom is correct now.  We will only have to copy the portion in
	 * the linear data area and GSO will preserve headroom when it creates
	 * the segments.  This is particularly beneficial on Xen where we get
	 * lots of GSO pskbs.  Conversely, we delay copying if it is just to
	 * get our own writable clone because GSO may do the copy for us.
	 */
	max_headroom = LL_RESERVED_SPACE(rt_dst(rt).dev) + rt_dst(rt).header_len
			+ mutable->tunnel_hlen;

	if (skb_headroom(skb) < max_headroom) {
		skb = check_headroom(skb, max_headroom);
		if (unlikely(IS_ERR(skb))) {
			vport_record_error(vport, VPORT_E_TX_DROPPED);
			goto error;
		}
	}

	forward_ip_summed(skb);

	if (unlikely(vswitch_skb_checksum_setup(skb)))
		goto error_free;

	skb = handle_gso(skb);
	if (unlikely(IS_ERR(skb))) {
		vport_record_error(vport, VPORT_E_TX_DROPPED);
		goto error;
	}

	/*
	 * Process GSO segments.  Try to do any work for the entire packet that
	 * doesn't involve actually writing to it before this point.
	 */
	orig_len = 0;
	do {
		struct sk_buff *next_skb = skb->next;
		skb->next = NULL;

		orig_len += build_packet(vport, mutable, &iph, rt, max_headroom, mtu, skb);

		skb = next_skb;
	} while (skb);

	if (unlikely(orig_len == 0))
		vport_record_error(vport, VPORT_E_TX_DROPPED);

	return orig_len;

error_free:
	kfree_skb(skb);
	vport_record_error(vport, VPORT_E_TX_ERROR);
error:
	return 0;
}

int tnl_init(void)
{
	return 0;
}

void tnl_exit(void)
{
	tbl_destroy(port_table, NULL);
	port_table = NULL;
}

static int set_config(const void __user *uconfig, const struct tnl_ops *tnl_ops,
		      const struct vport *cur_vport,
		      struct tnl_mutable_config *mutable)
{
	const struct vport *old_vport;
	const struct tnl_mutable_config *old_mutable;

	if (copy_from_user(&mutable->port_config, uconfig, sizeof(struct tnl_port_config)))
		return -EFAULT;

	mutable->tunnel_hlen = tnl_ops->hdr_len(&mutable->port_config);
	if (mutable->tunnel_hlen < 0)
		return mutable->tunnel_hlen;

	mutable->tunnel_hlen += sizeof(struct iphdr);

	if (mutable->port_config.daddr == 0)
		return -EINVAL;

	mutable->tunnel_type = tnl_ops->tunnel_type;
	if (mutable->port_config.flags & TNL_F_IN_KEY_MATCH) {
		mutable->tunnel_type |= TNL_T_KEY_MATCH;
		mutable->port_config.in_key = 0;
	} else
		mutable->tunnel_type |= TNL_T_KEY_EXACT;

	old_vport = tnl_find_port(mutable->port_config.saddr,
				  mutable->port_config.daddr,
				  mutable->port_config.in_key,
				  mutable->tunnel_type,
				  &old_mutable);

	if (old_vport && old_vport != cur_vport)
		return -EEXIST;

	if (mutable->port_config.flags & TNL_F_OUT_KEY_ACTION)
		mutable->port_config.out_key = 0;

	return 0;
}

struct vport *tnl_create(const char *name, const void __user *config,
			 const struct vport_ops *vport_ops,
			 const struct tnl_ops *tnl_ops)
{
	struct vport *vport;
	struct tnl_vport *tnl_vport;
	int initial_frag_id;
	int err;

	vport = vport_alloc(sizeof(struct tnl_vport), vport_ops);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	tnl_vport = tnl_vport_priv(vport);

	strcpy(tnl_vport->name, name);
	tnl_vport->tnl_ops = tnl_ops;

	tnl_vport->mutable = kmalloc(sizeof(struct tnl_mutable_config), GFP_KERNEL);
	if (!tnl_vport->mutable) {
		err = -ENOMEM;
		goto error_free_vport;
	}

	vport_gen_rand_ether_addr(tnl_vport->mutable->eth_addr);
	tnl_vport->mutable->mtu = ETH_DATA_LEN;

	get_random_bytes(&initial_frag_id, sizeof(int));
	atomic_set(&tnl_vport->frag_id, initial_frag_id);

	err = set_config(config, tnl_ops, NULL, tnl_vport->mutable);
	if (err)
		goto error_free_mutable;

	err = add_port(vport);
	if (err)
		goto error_free_mutable;

	return vport;

error_free_mutable:
	kfree(tnl_vport->mutable);
error_free_vport:
	vport_free(vport);
error:
	return ERR_PTR(err);
}

int tnl_modify(struct vport *vport, const void __user *config)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct tnl_mutable_config *mutable;
	int err;
	bool update_hash = false;

	mutable = kmemdup(tnl_vport->mutable, sizeof(struct tnl_mutable_config), GFP_KERNEL);
	if (!mutable) {
		err = -ENOMEM;
		goto error;
	}

	err = set_config(config, tnl_vport->tnl_ops, vport, mutable);
	if (err)
		goto error_free;

	/*
	 * Only remove the port from the hash table if something that would
	 * affect the lookup has changed.
	 */
	if (tnl_vport->mutable->port_config.saddr != mutable->port_config.saddr ||
	    tnl_vport->mutable->port_config.daddr != mutable->port_config.daddr ||
	    tnl_vport->mutable->port_config.in_key != mutable->port_config.in_key ||
	    (tnl_vport->mutable->port_config.flags & TNL_F_IN_KEY_MATCH) !=
	    (mutable->port_config.flags & TNL_F_IN_KEY_MATCH))
		update_hash = true;


	/*
	 * This update is not atomic but the lookup uses the config, which
	 * serves as an inherent double check.
	 */
	if (update_hash) {
		err = del_port(vport);
		if (err)
			goto error_free;
	}

	assign_config_rcu(vport, mutable);

	if (update_hash) {
		err = add_port(vport);
		if (err)
			goto error_free;
	}

	return 0;

error_free:
	kfree(mutable);
error:
	return err;
}

static void free_port(struct rcu_head *rcu)
{
	struct tnl_vport *tnl_vport = container_of(rcu, struct tnl_vport, rcu);

	kfree(tnl_vport->mutable);
	vport_free(tnl_vport_to_vport(tnl_vport));
}

int tnl_destroy(struct vport *vport)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	const struct tnl_mutable_config *old_mutable;

	if (vport == tnl_find_port(tnl_vport->mutable->port_config.saddr,
	    tnl_vport->mutable->port_config.daddr,
	    tnl_vport->mutable->port_config.in_key,
	    tnl_vport->mutable->tunnel_type,
	    &old_mutable))
		del_port(vport);

	call_rcu(&tnl_vport->rcu, free_port);

	return 0;
}

int tnl_set_mtu(struct vport *vport, int mtu)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct tnl_mutable_config *mutable;

	mutable = kmemdup(tnl_vport->mutable, sizeof(struct tnl_mutable_config), GFP_KERNEL);
	if (!mutable)
		return -ENOMEM;

	mutable->mtu = mtu;
	assign_config_rcu(vport, mutable);

	return 0;
}

int tnl_set_addr(struct vport *vport, const unsigned char *addr)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct tnl_mutable_config *mutable;

	mutable = kmemdup(tnl_vport->mutable, sizeof(struct tnl_mutable_config), GFP_KERNEL);
	if (!mutable)
		return -ENOMEM;

	memcpy(mutable->eth_addr, addr, ETH_ALEN);
	assign_config_rcu(vport, mutable);

	return 0;
}


const char *tnl_get_name(const struct vport *vport)
{
	const struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	return tnl_vport->name;
}

const unsigned char *tnl_get_addr(const struct vport *vport)
{
	const struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	return rcu_dereference(tnl_vport->mutable)->eth_addr;
}

int tnl_get_mtu(const struct vport *vport)
{
	const struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	return rcu_dereference(tnl_vport->mutable)->mtu;
}
