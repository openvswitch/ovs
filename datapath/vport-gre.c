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
#include <linux/if_tunnel.h>
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
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>

#include "actions.h"
#include "datapath.h"
#include "openvswitch/gre.h"
#include "table.h"
#include "vport.h"
#include "vport-generic.h"

/* The absolute minimum fragment size.  Note that there are many other
 * definitions of the minimum MTU. */
#define IP_MIN_MTU 68

/* The GRE header is composed of a series of sections: a base and then a variable
 * number of options. */
#define GRE_HEADER_SECTION 4

struct mutable_config {
	struct rcu_head rcu;

	unsigned char eth_addr[ETH_ALEN];
	unsigned int mtu;
	struct gre_port_config port_config;

	int tunnel_hlen; /* Tunnel header length. */
};

struct gre_vport {
	struct tbl_node tbl_node;

	char name[IFNAMSIZ];

	/* Protected by RCU. */
	struct mutable_config *mutable;
};

/* Protected by RCU. */
static struct tbl *port_table;

/* These are just used as an optimization: they don't require any kind of
 * synchronization because we could have just as easily read the value before
 * the port change happened. */
static unsigned int key_local_remote_ports;
static unsigned int key_remote_ports;
static unsigned int local_remote_ports;
static unsigned int remote_ports;

static inline struct gre_vport *
gre_vport_priv(const struct vport *vport)
{
	return vport_priv(vport);
}

static inline struct vport *
gre_vport_to_vport(const struct gre_vport *gre_vport)
{
	return vport_from_priv(gre_vport);
}

static inline struct gre_vport *
gre_vport_table_cast(const struct tbl_node *node)
{
	return container_of(node, struct gre_vport, tbl_node);
}

/* RCU callback. */
static void
free_config(struct rcu_head *rcu)
{
	struct mutable_config *c = container_of(rcu, struct mutable_config, rcu);
	kfree(c);
}

static void
assign_config_rcu(struct vport *vport, struct mutable_config *new_config)
{
	struct gre_vport *gre_vport = gre_vport_priv(vport);
	struct mutable_config *old_config;

	old_config = rcu_dereference(gre_vport->mutable);
	rcu_assign_pointer(gre_vport->mutable, new_config);
	call_rcu(&old_config->rcu, free_config);
}

static unsigned int *
find_port_pool(const struct mutable_config *mutable)
{
	if (mutable->port_config.flags & GRE_F_IN_KEY_MATCH) {
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
	LOOKUP_SADDR		= 0,
	LOOKUP_DADDR		= 1,
	LOOKUP_KEY		= 2,
	LOOKUP_KEY_MATCH	= 3
};

struct port_lookup_key {
	u32 vals[4];			/* Contains enum lookup_key keys. */
	const struct mutable_config *mutable;
};

/* Modifies 'target' to store the rcu_dereferenced pointer that was used to do
 * the comparision. */
static int
port_cmp(const struct tbl_node *node, void *target)
{
	const struct gre_vport *gre_vport = gre_vport_table_cast(node);
	struct port_lookup_key *lookup = target;

	lookup->mutable = rcu_dereference(gre_vport->mutable);

	return ((lookup->mutable->port_config.flags & GRE_F_IN_KEY_MATCH) ==
			lookup->vals[LOOKUP_KEY_MATCH]) &&
	       lookup->mutable->port_config.daddr == lookup->vals[LOOKUP_DADDR] &&
	       lookup->mutable->port_config.in_key == lookup->vals[LOOKUP_KEY] &&
	       lookup->mutable->port_config.saddr == lookup->vals[LOOKUP_SADDR];
}

static u32
port_hash(struct port_lookup_key *lookup)
{
	return jhash2(lookup->vals, ARRAY_SIZE(lookup->vals), 0);
}

static int
add_port(struct vport *vport)
{
	struct gre_vport *gre_vport = gre_vport_priv(vport);
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

	lookup.vals[LOOKUP_SADDR] = gre_vport->mutable->port_config.saddr;
	lookup.vals[LOOKUP_DADDR] = gre_vport->mutable->port_config.daddr;
	lookup.vals[LOOKUP_KEY] = gre_vport->mutable->port_config.in_key;
	lookup.vals[LOOKUP_KEY_MATCH] = gre_vport->mutable->port_config.flags & GRE_F_IN_KEY_MATCH;

	err = tbl_insert(port_table, &gre_vport->tbl_node, port_hash(&lookup));
	if (err)
		return err;

	(*find_port_pool(gre_vport->mutable))++;

	return 0;
}

static int
del_port(struct vport *vport)
{
	struct gre_vport *gre_vport = gre_vport_priv(vport);
	int err;

	err = tbl_remove(port_table, &gre_vport->tbl_node);
	if (err)
		return err;

	(*find_port_pool(gre_vport->mutable))--;

	return 0;
}

#define FIND_PORT_KEY		(1 << 0)
#define FIND_PORT_MATCH		(1 << 1)
#define FIND_PORT_ANY		(FIND_PORT_KEY | FIND_PORT_MATCH)

static struct vport *
find_port(__be32 saddr, __be32 daddr, __be32 key, int port_type,
	  const struct mutable_config **mutable)
{
	struct port_lookup_key lookup;
	struct tbl *table = rcu_dereference(port_table);
	struct tbl_node *tbl_node;

	if (!table)
		return NULL;

	lookup.vals[LOOKUP_SADDR] = saddr;
	lookup.vals[LOOKUP_DADDR] = daddr;

	if (port_type & FIND_PORT_KEY) {
		lookup.vals[LOOKUP_KEY] = key;
		lookup.vals[LOOKUP_KEY_MATCH] = 0;

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

	if (port_type & FIND_PORT_MATCH) {
		lookup.vals[LOOKUP_KEY] = 0;
		lookup.vals[LOOKUP_KEY_MATCH] = GRE_F_IN_KEY_MATCH;

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
	return gre_vport_to_vport(gre_vport_table_cast(tbl_node));
}

static bool
check_ipv4_address(__be32 addr)
{
	if (ipv4_is_multicast(addr) || ipv4_is_lbcast(addr)
	    || ipv4_is_loopback(addr) || ipv4_is_zeronet(addr))
		return false;

	return true;
}

static bool
ipv4_should_icmp(struct sk_buff *skb)
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

static void
ipv4_build_icmp(struct sk_buff *skb, struct sk_buff *nskb,
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
static bool
ipv6_should_icmp(struct sk_buff *skb)
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

static void
ipv6_build_icmp(struct sk_buff *skb, struct sk_buff *nskb, unsigned int mtu,
		unsigned int payload_length)
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

static bool
send_frag_needed(struct vport *vport, const struct mutable_config *mutable,
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

		/* In theory we should do PMTUD on IPv6 multicast messages but
		 * we don't have an address to send from so just fragment. */
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

	/* Assume that flow based keys are symmetric with respect to input
	 * and output and use the key that we were going to put on the
	 * outgoing packet for the fake received packet.  If the keys are
	 * not symmetric then PMTUD needs to be disabled since we won't have
	 * any way of synthesizing packets. */
	if (mutable->port_config.flags & GRE_F_IN_KEY_MATCH &&
	    mutable->port_config.flags & GRE_F_OUT_KEY_ACTION)
		OVS_CB(nskb)->tun_id = flow_key;

	compute_ip_summed(nskb, false);
	vport_receive(vport, nskb);

	return true;
}

static struct sk_buff *
check_headroom(struct sk_buff *skb, int headroom)
{
	if (skb_headroom(skb) < headroom ||
	    (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
		struct sk_buff *nskb = skb_realloc_headroom(skb, headroom);
		if (!nskb) {
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

static void
create_gre_header(struct sk_buff *skb, const struct mutable_config *mutable)
{
	struct iphdr *iph = ip_hdr(skb);
	__be16 *flags = (__be16 *)(iph + 1);
	__be16 *protocol = flags + 1;
	__be32 *options = (__be32 *)((u8 *)iph + mutable->tunnel_hlen
					       - GRE_HEADER_SECTION);

	*protocol = htons(ETH_P_TEB);
	*flags = 0;

	/* Work backwards over the options so the checksum is last. */
	if (mutable->port_config.out_key ||
	    mutable->port_config.flags & GRE_F_OUT_KEY_ACTION) {
		*flags |= GRE_KEY;

		if (mutable->port_config.flags & GRE_F_OUT_KEY_ACTION)
			*options = OVS_CB(skb)->tun_id;
		else
			*options = mutable->port_config.out_key;

		options--;
	}

	if (mutable->port_config.flags & GRE_F_OUT_CSUM) {
		*flags |= GRE_CSUM;

		*options = 0;
		*(__sum16 *)options = csum_fold(skb_checksum(skb,
						sizeof(struct iphdr),
						skb->len - sizeof(struct iphdr),
						0));
	}
}

static int
check_checksum(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	__be16 flags = *(__be16 *)(iph + 1);
	__sum16 csum = 0;

	if (flags & GRE_CSUM) {
		switch (skb->ip_summed) {
		case CHECKSUM_COMPLETE:
			csum = csum_fold(skb->csum);

			if (!csum)
				break;
			/* Fall through. */

		case CHECKSUM_NONE:
			skb->csum = 0;
			csum = __skb_checksum_complete(skb);
			skb->ip_summed = CHECKSUM_COMPLETE;
			break;
		}
	}

	return (csum == 0);
}

static int
parse_gre_header(struct iphdr *iph, __be16 *flags, __be32 *key)
{
	/* IP and ICMP protocol handlers check that the IHL is valid. */
	__be16 *flagsp = (__be16 *)((u8 *)iph + (iph->ihl << 2));
	__be16 *protocol = flagsp + 1;
	__be32 *options = (__be32 *)(protocol + 1);
	int hdr_len;

	*flags = *flagsp;

	if (*flags & (GRE_VERSION | GRE_ROUTING))
		return -EINVAL;

	if (*protocol != htons(ETH_P_TEB))
		return -EINVAL;

	hdr_len = GRE_HEADER_SECTION;

	if (*flags & GRE_CSUM) {
		hdr_len += GRE_HEADER_SECTION;
		options++;
	}

	if (*flags & GRE_KEY) {
		hdr_len += GRE_HEADER_SECTION;

		*key = *options;
		options++;
	} else
		*key = 0;

	if (*flags & GRE_SEQ)
		hdr_len += GRE_HEADER_SECTION;

	return hdr_len;
}

static inline u8
ecn_encapsulate(u8 tos, struct sk_buff *skb)
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

static inline void
ecn_decapsulate(u8 tos, struct sk_buff *skb)
{
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

static struct sk_buff *
handle_gso(struct sk_buff *skb)
{
	if (skb_is_gso(skb)) {
		struct sk_buff *nskb = skb_gso_segment(skb, NETIF_F_SG);

		dev_kfree_skb(skb);
		return nskb;
	}

	return skb;
}

static int
handle_csum_offload(struct sk_buff *skb)
{
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		return skb_checksum_help(skb);
	else {
		skb->ip_summed = CHECKSUM_NONE;
		return 0;
	}
}

/* Called with rcu_read_lock. */
static void
gre_err(struct sk_buff *skb, u32 info)
{
	struct vport *vport;
	const struct mutable_config *mutable;
	const int type = icmp_hdr(skb)->type;
	const int code = icmp_hdr(skb)->code;
	int mtu = ntohs(icmp_hdr(skb)->un.frag.mtu);

	struct iphdr *iph;
	__be16 flags;
	__be32 key;
	int tunnel_hdr_len, tot_hdr_len;
	unsigned int orig_mac_header;
	unsigned int orig_nw_header;

	if (type != ICMP_DEST_UNREACH || code != ICMP_FRAG_NEEDED)
		return;

	/* The mimimum size packet that we would actually be able to process:
	 * encapsulating IP header, minimum GRE header, Ethernet header,
	 * inner IPv4 header. */
	if (!pskb_may_pull(skb, sizeof(struct iphdr) + GRE_HEADER_SECTION +
				ETH_HLEN + sizeof(struct iphdr)))
		return;

	iph = (struct iphdr *)skb->data;

	tunnel_hdr_len = parse_gre_header(iph, &flags, &key);
	if (tunnel_hdr_len < 0)
		return;

	vport = find_port(iph->saddr, iph->daddr, key, FIND_PORT_ANY, &mutable);
	if (!vport)
		return;

	/* Packets received by this function were previously sent by us, so
	 * any comparisons should be to the output values, not the input.
	 * However, it's not really worth it to have a hash table based on
	 * output keys (especially since ICMP error handling of tunneled packets
	 * isn't that reliable anyways).  Therefore, we do a lookup based on the
	 * out key as if it were the in key and then check to see if the input
	 * and output keys are the same. */
	if (mutable->port_config.in_key != mutable->port_config.out_key)
		return;

	if (!!(mutable->port_config.flags & GRE_F_IN_KEY_MATCH) !=
	    !!(mutable->port_config.flags & GRE_F_OUT_KEY_ACTION))
		return;

	if ((mutable->port_config.flags & GRE_F_OUT_CSUM) && !(flags & GRE_CSUM))
		return;

	tunnel_hdr_len += iph->ihl << 2;

	orig_mac_header = skb_mac_header(skb) - skb->data;
	orig_nw_header = skb_network_header(skb) - skb->data;
	skb_set_mac_header(skb, tunnel_hdr_len);

	tot_hdr_len = tunnel_hdr_len + ETH_HLEN;

	skb->protocol = eth_hdr(skb)->h_proto;
	if (skb->protocol == htons(ETH_P_8021Q)) {
		tot_hdr_len += VLAN_HLEN;
		skb->protocol = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
	}

	skb_set_network_header(skb, tot_hdr_len);
	mtu -= tot_hdr_len;

	if (skb->protocol == htons(ETH_P_IP))
		tot_hdr_len += sizeof(struct iphdr);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (skb->protocol == htons(ETH_P_IPV6))
		tot_hdr_len += sizeof(struct ipv6hdr);
#endif
	else
		goto out;

	if (!pskb_may_pull(skb, tot_hdr_len))
		goto out;

	if (skb->protocol == htons(ETH_P_IP)) {
		if (mtu < IP_MIN_MTU) {
			if (ntohs(ip_hdr(skb)->tot_len) >= IP_MIN_MTU)
				mtu = IP_MIN_MTU;
			else
				goto out;
		}

	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		if (mtu < IPV6_MIN_MTU) {
			unsigned int packet_length = sizeof(struct ipv6hdr) +
					      ntohs(ipv6_hdr(skb)->payload_len);

			if (packet_length >= IPV6_MIN_MTU
			    || ntohs(ipv6_hdr(skb)->payload_len) == 0)
				mtu = IPV6_MIN_MTU;
			else
				goto out;
		}
	}
#endif

	__pskb_pull(skb, tunnel_hdr_len);
	send_frag_needed(vport, mutable, skb, mtu, key);
	skb_push(skb, tunnel_hdr_len);

out:
	skb_set_mac_header(skb, orig_mac_header);
	skb_set_network_header(skb, orig_nw_header);
	skb->protocol = htons(ETH_P_IP);
}

/* Called with rcu_read_lock. */
static int
gre_rcv(struct sk_buff *skb)
{
	struct vport *vport;
	const struct mutable_config *mutable;
	int hdr_len;
	struct iphdr *iph;
	__be16 flags;
	__be32 key;

	if (!pskb_may_pull(skb, GRE_HEADER_SECTION + ETH_HLEN))
		goto error;

	if (!check_checksum(skb))
		goto error;

	iph = ip_hdr(skb);

	hdr_len = parse_gre_header(iph, &flags, &key);
	if (hdr_len < 0)
		goto error;

	vport = find_port(iph->daddr, iph->saddr, key, FIND_PORT_ANY, &mutable);
	if (!vport) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
		goto error;
	}

	if ((mutable->port_config.flags & GRE_F_IN_CSUM) && !(flags & GRE_CSUM)) {
		vport_record_error(vport, VPORT_E_RX_CRC);
		goto error;
	}

	if (!pskb_pull(skb, hdr_len) || !pskb_may_pull(skb, ETH_HLEN)) {
		vport_record_error(vport, VPORT_E_RX_ERROR);
		goto error;
	}

	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, skb->dev);
	skb_postpull_rcsum(skb, skb_transport_header(skb), hdr_len + ETH_HLEN);

	skb_dst_drop(skb);
	nf_reset(skb);
	secpath_reset(skb);
	skb_reset_network_header(skb);

	ecn_decapsulate(iph->tos, skb);

	if (mutable->port_config.flags & GRE_F_IN_KEY_MATCH)
		OVS_CB(skb)->tun_id = key;
	else
		OVS_CB(skb)->tun_id = 0;

	skb_push(skb, ETH_HLEN);
	compute_ip_summed(skb, false);

	vport_receive(vport, skb);

	return 0;

error:
	kfree_skb(skb);
	return 0;
}

static int
build_packet(struct vport *vport, const struct mutable_config *mutable,
	     struct iphdr *iph, struct rtable *rt, int max_headroom, int mtu,
	     struct sk_buff *skb)
{
	int err;
	struct iphdr *new_iph;
	int orig_len = skb->len;
	__be16 frag_off = iph->frag_off;

	skb = check_headroom(skb, max_headroom);
	if (unlikely(IS_ERR(skb)))
		goto error;

	err = handle_csum_offload(skb);
	if (err)
		goto error_free;

	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *old_iph = ip_hdr(skb);

		if ((old_iph->frag_off & htons(IP_DF)) &&
		    mtu < ntohs(old_iph->tot_len)) {
			if (send_frag_needed(vport, mutable, skb, mtu, OVS_CB(skb)->tun_id))
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
			if (send_frag_needed(vport, mutable, skb, mtu, OVS_CB(skb)->tun_id))
				goto error_free;
		}
	}
#endif

	skb_reset_transport_header(skb);
	new_iph = (struct iphdr *)skb_push(skb, mutable->tunnel_hlen);
	skb_reset_network_header(skb);

	memcpy(new_iph, iph, sizeof(struct iphdr));
	new_iph->frag_off = frag_off;
	ip_select_ident(new_iph, &rt->u.dst, NULL);

	create_gre_header(skb, mutable);

	/* Allow our local IP stack to fragment the outer packet even if the
	 * DF bit is set as a last resort. */
	skb->local_df = 1;

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags = 0;

	err = ip_local_out(skb);
	if (likely(net_xmit_eval(err) == 0))
		return orig_len;
	else {
		vport_record_error(vport, VPORT_E_TX_ERROR);
		return 0;
	}

error_free:
	kfree_skb(skb);
error:
	vport_record_error(vport, VPORT_E_TX_DROPPED);

	return 0;
}

static int
gre_send(struct vport *vport, struct sk_buff *skb)
{
	struct gre_vport *gre_vport = gre_vport_priv(vport);
	const struct mutable_config *mutable = rcu_dereference(gre_vport->mutable);

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
	if (mutable->port_config.flags & GRE_F_TOS_INHERIT) {
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
				    .proto = IPPROTO_GRE };

		if (ip_route_output_key(&init_net, &rt, &fl))
			goto error_free;
	}

	iph.ttl = mutable->port_config.ttl;
	if (mutable->port_config.flags & GRE_F_TTL_INHERIT) {
		if (skb->protocol == htons(ETH_P_IP))
			iph.ttl = old_iph->ttl;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else if (skb->protocol == htons(ETH_P_IPV6))
			iph.ttl = ipv6_hdr(skb)->hop_limit;
#endif
	}
	if (!iph.ttl)
		iph.ttl = dst_metric(&rt->u.dst, RTAX_HOPLIMIT);

	iph.frag_off = (mutable->port_config.flags & GRE_F_PMTUD) ? htons(IP_DF) : 0;
	if (iph.frag_off)
		mtu = dst_mtu(&rt->u.dst)
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
	iph.protocol = IPPROTO_GRE;
	iph.daddr = rt->rt_dst;
	iph.saddr = rt->rt_src;

	nf_reset(skb);
	secpath_reset(skb);
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* If we are doing GSO on a pskb it is better to make sure that the
	 * headroom is correct now.  We will only have to copy the portion in
	 * the linear data area and GSO will preserve headroom when it creates
	 * the segments.  This is particularly beneficial on Xen where we get
	 * lots of GSO pskbs.  Conversely, we delay copying if it is just to
	 * get our own writable clone because GSO may do the copy for us. */
	max_headroom = LL_RESERVED_SPACE(rt->u.dst.dev) + rt->u.dst.header_len
			+ mutable->tunnel_hlen;

	if (skb_headroom(skb) < max_headroom) {
		skb = check_headroom(skb, max_headroom);
		if (unlikely(IS_ERR(skb))) {
			vport_record_error(vport, VPORT_E_TX_DROPPED);
			goto error;
		}
	}

	forward_ip_summed(skb);
	vswitch_skb_checksum_setup(skb);

	skb = handle_gso(skb);
	if (unlikely(IS_ERR(skb))) {
		vport_record_error(vport, VPORT_E_TX_DROPPED);
		goto error;
	}

	/* Process GSO segments.  Try to do any work for the entire packet that
	 * doesn't involve actually writing to it before this point. */
	orig_len = 0;
	do {
		struct sk_buff *next_skb = skb->next;
		skb->next = NULL;

		orig_len += build_packet(vport, mutable, &iph, rt, max_headroom, mtu, skb);

		skb = next_skb;
	} while (skb);

	return orig_len;

error_free:
	kfree_skb(skb);
	vport_record_error(vport, VPORT_E_TX_ERROR);
error:
	return 0;
}

static struct net_protocol gre_protocol_handlers = {
	.handler	=	gre_rcv,
	.err_handler	=	gre_err,
};

static int
gre_init(void)
{
	int err;

	err = inet_add_protocol(&gre_protocol_handlers, IPPROTO_GRE);
	if (err)
		printk(KERN_WARNING "openvswitch: cannot register gre protocol handler\n");

	return err;
}

static void
gre_exit(void)
{
	tbl_destroy(port_table, NULL);
	inet_del_protocol(&gre_protocol_handlers, IPPROTO_GRE);
}

static int
set_config(const struct vport *cur_vport, struct mutable_config *mutable,
	   const void __user *uconfig)
{
	const struct vport *old_vport;
	const struct mutable_config *old_mutable;
	int port_type;

	if (copy_from_user(&mutable->port_config, uconfig, sizeof(struct gre_port_config)))
		return -EFAULT;

	if (mutable->port_config.daddr == 0)
		return -EINVAL;

	if (mutable->port_config.flags & GRE_F_IN_KEY_MATCH) {
		port_type = FIND_PORT_MATCH;
		mutable->port_config.in_key = 0;
	} else
		port_type = FIND_PORT_KEY;

	old_vport = find_port(mutable->port_config.saddr,
			      mutable->port_config.daddr,
			      mutable->port_config.in_key, port_type,
			      &old_mutable);

	if (old_vport && old_vport != cur_vport)
		return -EEXIST;

	if (mutable->port_config.flags & GRE_F_OUT_KEY_ACTION)
		mutable->port_config.out_key = 0;

	mutable->tunnel_hlen = sizeof(struct iphdr) + GRE_HEADER_SECTION;

	if (mutable->port_config.flags & GRE_F_OUT_CSUM)
		mutable->tunnel_hlen += GRE_HEADER_SECTION;

	if (mutable->port_config.out_key ||
	    mutable->port_config.flags & GRE_F_OUT_KEY_ACTION)
		mutable->tunnel_hlen += GRE_HEADER_SECTION;

	return 0;
}

static struct vport *
gre_create(const char *name, const void __user *config)
{
	struct vport *vport;
	struct gre_vport *gre_vport;
	int err;

	vport = vport_alloc(sizeof(struct gre_vport), &gre_vport_ops);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	gre_vport = gre_vport_priv(vport);

	strcpy(gre_vport->name, name);

	gre_vport->mutable = kmalloc(sizeof(struct mutable_config), GFP_KERNEL);
	if (!gre_vport->mutable) {
		err = -ENOMEM;
		goto error_free_vport;
	}

	vport_gen_rand_ether_addr(gre_vport->mutable->eth_addr);
	gre_vport->mutable->mtu = ETH_DATA_LEN;

	err = set_config(NULL, gre_vport->mutable, config);
	if (err)
		goto error_free_mutable;

	err = add_port(vport);
	if (err)
		goto error_free_mutable;

	return vport;

error_free_mutable:
	kfree(gre_vport->mutable);
error_free_vport:
	vport_free(vport);
error:
	return ERR_PTR(err);
}

static int
gre_modify(struct vport *vport, const void __user *config)
{
	struct gre_vport *gre_vport = gre_vport_priv(vport);
	struct mutable_config *mutable;
	int err;
	int update_hash = 0;

	mutable = kmemdup(gre_vport->mutable, sizeof(struct mutable_config), GFP_KERNEL);
	if (!mutable) {
		err = -ENOMEM;
		goto error;
	}

	err = set_config(vport, mutable, config);
	if (err)
		goto error_free;

	/* Only remove the port from the hash table if something that would
	 * affect the lookup has changed. */
	if (gre_vport->mutable->port_config.saddr != mutable->port_config.saddr ||
	    gre_vport->mutable->port_config.daddr != mutable->port_config.daddr ||
	    gre_vport->mutable->port_config.in_key != mutable->port_config.in_key ||
	    (gre_vport->mutable->port_config.flags & GRE_F_IN_KEY_MATCH) !=
	    (mutable->port_config.flags & GRE_F_IN_KEY_MATCH))
		update_hash = 1;


	/* This update is not atomic but the lookup uses the config, which
	 * serves as an inherent double check. */
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

static int
gre_destroy(struct vport *vport)
{
	struct gre_vport *gre_vport = gre_vport_priv(vport);
	int port_type;
	const struct mutable_config *old_mutable;

	/* Do a hash table lookup to make sure that the port exists.  It should
	 * exist but might not if a modify failed earlier. */
	if (gre_vport->mutable->port_config.flags & GRE_F_IN_KEY_MATCH)
		port_type = FIND_PORT_MATCH;
	else
		port_type = FIND_PORT_KEY;

	if (vport == find_port(gre_vport->mutable->port_config.saddr,
	    gre_vport->mutable->port_config.daddr,
	    gre_vport->mutable->port_config.in_key, port_type, &old_mutable))
		del_port(vport);

	kfree(gre_vport->mutable);
	vport_free(vport);

	return 0;
}

static int
gre_set_mtu(struct vport *vport, int mtu)
{
	struct gre_vport *gre_vport = gre_vport_priv(vport);
	struct mutable_config *mutable;

	mutable = kmemdup(gre_vport->mutable, sizeof(struct mutable_config), GFP_KERNEL);
	if (!mutable)
		return -ENOMEM;

	mutable->mtu = mtu;
	assign_config_rcu(vport, mutable);

	return 0;
}

static int
gre_set_addr(struct vport *vport, const unsigned char *addr)
{
	struct gre_vport *gre_vport = gre_vport_priv(vport);
	struct mutable_config *mutable;

	mutable = kmemdup(gre_vport->mutable, sizeof(struct mutable_config), GFP_KERNEL);
	if (!mutable)
		return -ENOMEM;

	memcpy(mutable->eth_addr, addr, ETH_ALEN);
	assign_config_rcu(vport, mutable);

	return 0;
}


static const char *
gre_get_name(const struct vport *vport)
{
	const struct gre_vport *gre_vport = gre_vport_priv(vport);
	return gre_vport->name;
}

static const unsigned char *
gre_get_addr(const struct vport *vport)
{
	const struct gre_vport *gre_vport = gre_vport_priv(vport);
	return rcu_dereference(gre_vport->mutable)->eth_addr;
}

static int
gre_get_mtu(const struct vport *vport)
{
	const struct gre_vport *gre_vport = gre_vport_priv(vport);
	return rcu_dereference(gre_vport->mutable)->mtu;
}

struct vport_ops gre_vport_ops = {
	.type		= "gre",
	.flags		= VPORT_F_GEN_STATS | VPORT_F_TUN_ID,
	.init		= gre_init,
	.exit		= gre_exit,
	.create		= gre_create,
	.modify		= gre_modify,
	.destroy	= gre_destroy,
	.set_mtu	= gre_set_mtu,
	.set_addr	= gre_set_addr,
	.get_name	= gre_get_name,
	.get_addr	= gre_get_addr,
	.get_dev_flags	= vport_gen_get_dev_flags,
	.is_running	= vport_gen_is_running,
	.get_operstate	= vport_gen_get_operstate,
	.get_mtu	= gre_get_mtu,
	.send		= gre_send,
};
