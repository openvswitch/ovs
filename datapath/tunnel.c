/*
 * Copyright (c) 2010, 2011 Nicira Networks.
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
#include <linux/workqueue.h>

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
#include "checksum.h"
#include "datapath.h"
#include "table.h"
#include "tunnel.h"
#include "vlan.h"
#include "vport.h"
#include "vport-generic.h"
#include "vport-internal_dev.h"

#ifdef NEED_CACHE_TIMEOUT
/*
 * On kernels where we can't quickly detect changes in the rest of the system
 * we use an expiration time to invalidate the cache.  A shorter expiration
 * reduces the length of time that we may potentially blackhole packets while
 * a longer time increases performance by reducing the frequency that the
 * cache needs to be rebuilt.  A variety of factors may cause the cache to be
 * invalidated before the expiration time but this is the maximum.  The time
 * is expressed in jiffies.
 */
#define MAX_CACHE_EXP HZ
#endif

/*
 * Interval to check for and remove caches that are no longer valid.  Caches
 * are checked for validity before they are used for packet encapsulation and
 * old caches are removed at that time.  However, if no packets are sent through
 * the tunnel then the cache will never be destroyed.  Since it holds
 * references to a number of system objects, the cache will continue to use
 * system resources by not allowing those objects to be destroyed.  The cache
 * cleaner is periodically run to free invalid caches.  It does not
 * significantly affect system performance.  A lower interval will release
 * resources faster but will itself consume resources by requiring more frequent
 * checks.  A longer interval may result in messages being printed to the kernel
 * message buffer about unreleased resources.  The interval is expressed in
 * jiffies.
 */
#define CACHE_CLEANER_INTERVAL (5 * HZ)

#define CACHE_DATA_ALIGN 16

static struct tbl __rcu *port_table __read_mostly;

static void cache_cleaner(struct work_struct *work);
static DECLARE_DELAYED_WORK(cache_cleaner_wq, cache_cleaner);

/*
 * These are just used as an optimization: they don't require any kind of
 * synchronization because we could have just as easily read the value before
 * the port change happened.
 */
static unsigned int key_local_remote_ports __read_mostly;
static unsigned int key_remote_ports __read_mostly;
static unsigned int local_remote_ports __read_mostly;
static unsigned int remote_ports __read_mostly;

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

/* This is analogous to rtnl_dereference for the tunnel cache.  It checks that
 * cache_lock is held, so it is only for update side code.
 */
static inline struct tnl_cache *cache_dereference(struct tnl_vport *tnl_vport)
{
	return rcu_dereference_protected(tnl_vport->cache,
					 lockdep_is_held(&tnl_vport->cache_lock));
}

static inline void schedule_cache_cleaner(void)
{
	schedule_delayed_work(&cache_cleaner_wq, CACHE_CLEANER_INTERVAL);
}

static void free_cache(struct tnl_cache *cache)
{
	if (!cache)
		return;

	flow_put(cache->flow);
	ip_rt_put(cache->rt);
	kfree(cache);
}

static void free_config_rcu(struct rcu_head *rcu)
{
	struct tnl_mutable_config *c = container_of(rcu, struct tnl_mutable_config, rcu);
	kfree(c);
}

static void free_cache_rcu(struct rcu_head *rcu)
{
	struct tnl_cache *c = container_of(rcu, struct tnl_cache, rcu);
	free_cache(c);
}

static void assign_config_rcu(struct vport *vport,
			      struct tnl_mutable_config *new_config)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct tnl_mutable_config *old_config;

	old_config = rtnl_dereference(tnl_vport->mutable);
	rcu_assign_pointer(tnl_vport->mutable, new_config);
	call_rcu(&old_config->rcu, free_config_rcu);
}

static void assign_cache_rcu(struct vport *vport, struct tnl_cache *new_cache)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct tnl_cache *old_cache;

	old_cache = cache_dereference(tnl_vport);
	rcu_assign_pointer(tnl_vport->cache, new_cache);

	if (old_cache)
		call_rcu(&old_cache->rcu, free_cache_rcu);
}

static unsigned int *find_port_pool(const struct tnl_mutable_config *mutable)
{
	if (mutable->flags & TNL_F_IN_KEY_MATCH) {
		if (mutable->saddr)
			return &local_remote_ports;
		else
			return &remote_ports;
	} else {
		if (mutable->saddr)
			return &key_local_remote_ports;
		else
			return &key_remote_ports;
	}
}

struct port_lookup_key {
	const struct tnl_mutable_config *mutable;
	__be64 key;
	u32 tunnel_type;
	__be32 saddr;
	__be32 daddr;
};

/*
 * Modifies 'target' to store the rcu_dereferenced pointer that was used to do
 * the comparision.
 */
static int port_cmp(const struct tbl_node *node, void *target, int unused)
{
	const struct tnl_vport *tnl_vport = tnl_vport_table_cast(node);
	struct port_lookup_key *lookup = target;

	lookup->mutable = rcu_dereference_rtnl(tnl_vport->mutable);

	return (lookup->mutable->tunnel_type == lookup->tunnel_type &&
		lookup->mutable->daddr == lookup->daddr &&
		lookup->mutable->in_key == lookup->key &&
		lookup->mutable->saddr == lookup->saddr);
}

static u32 port_hash(struct port_lookup_key *k)
{
	u32 x = jhash_3words((__force u32)k->saddr, (__force u32)k->daddr,
			     k->tunnel_type, 0);
	return jhash_2words((__force u64)k->key >> 32, (__force u32)k->key, x);
}

static u32 mutable_hash(const struct tnl_mutable_config *mutable)
{
	struct port_lookup_key lookup;

	lookup.saddr = mutable->saddr;
	lookup.daddr = mutable->daddr;
	lookup.key = mutable->in_key;
	lookup.tunnel_type = mutable->tunnel_type;

	return port_hash(&lookup);
}

static void check_table_empty(void)
{
	struct tbl *old_table = rtnl_dereference(port_table);

	if (tbl_count(old_table) == 0) {
		cancel_delayed_work_sync(&cache_cleaner_wq);
		rcu_assign_pointer(port_table, NULL);
		tbl_deferred_destroy(old_table, NULL);
	}
}

static int add_port(struct vport *vport)
{
	struct tbl *cur_table = rtnl_dereference(port_table);
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	int err;

	if (!port_table) {
		struct tbl *new_table;

		new_table = tbl_create(TBL_MIN_BUCKETS);
		if (!new_table)
			return -ENOMEM;

		rcu_assign_pointer(port_table, new_table);
		schedule_cache_cleaner();

	} else if (tbl_count(cur_table) > tbl_n_buckets(cur_table)) {
		struct tbl *new_table;

		new_table = tbl_expand(cur_table);
		if (IS_ERR(new_table))
			return PTR_ERR(new_table);

		rcu_assign_pointer(port_table, new_table);
		tbl_deferred_destroy(cur_table, NULL);
	}

	err = tbl_insert(rtnl_dereference(port_table), &tnl_vport->tbl_node,
			 mutable_hash(rtnl_dereference(tnl_vport->mutable)));
	if (err) {
		check_table_empty();
		return err;
	}

	(*find_port_pool(rtnl_dereference(tnl_vport->mutable)))++;

	return 0;
}

static int move_port(struct vport *vport, struct tnl_mutable_config *new_mutable)
{
	int err;
	struct tbl *cur_table = rtnl_dereference(port_table);
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	u32 hash;

	hash = mutable_hash(new_mutable);
	if (hash == tnl_vport->tbl_node.hash)
		goto table_updated;

	/*
	 * Ideally we should make this move atomic to avoid having gaps in
	 * finding tunnels or the possibility of failure.  However, if we do
	 * find a tunnel it will always be consistent.
	 */
	err = tbl_remove(cur_table, &tnl_vport->tbl_node);
	if (err)
		return err;

	err = tbl_insert(cur_table, &tnl_vport->tbl_node, hash);
	if (err) {
		(*find_port_pool(rtnl_dereference(tnl_vport->mutable)))--;
		check_table_empty();
		return err;
	}

table_updated:
	(*find_port_pool(rtnl_dereference(tnl_vport->mutable)))--;
	assign_config_rcu(vport, new_mutable);
	(*find_port_pool(rtnl_dereference(tnl_vport->mutable)))++;

	return 0;
}

static int del_port(struct vport *vport)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	int err;

	err = tbl_remove(rtnl_dereference(port_table), &tnl_vport->tbl_node);
	if (err)
		return err;

	check_table_empty();
	(*find_port_pool(rtnl_dereference(tnl_vport->mutable)))--;

	return 0;
}

struct vport *tnl_find_port(__be32 saddr, __be32 daddr, __be64 key,
			    int tunnel_type,
			    const struct tnl_mutable_config **mutable)
{
	struct port_lookup_key lookup;
	struct tbl *table = rcu_dereference_rtnl(port_table);
	struct tbl_node *tbl_node;

	if (unlikely(!table))
		return NULL;

	lookup.saddr = saddr;
	lookup.daddr = daddr;

	if (tunnel_type & TNL_T_KEY_EXACT) {
		lookup.key = key;
		lookup.tunnel_type = tunnel_type & ~TNL_T_KEY_MATCH;

		if (key_local_remote_ports) {
			tbl_node = tbl_lookup(table, &lookup, sizeof(lookup),
					      port_hash(&lookup), port_cmp);
			if (tbl_node)
				goto found;
		}

		if (key_remote_ports) {
			lookup.saddr = 0;

			tbl_node = tbl_lookup(table, &lookup, sizeof(lookup),
					      port_hash(&lookup), port_cmp);
			if (tbl_node)
				goto found;

			lookup.saddr = saddr;
		}
	}

	if (tunnel_type & TNL_T_KEY_MATCH) {
		lookup.key = 0;
		lookup.tunnel_type = tunnel_type & ~TNL_T_KEY_EXACT;

		if (local_remote_ports) {
			tbl_node = tbl_lookup(table, &lookup, sizeof(lookup),
					      port_hash(&lookup), port_cmp);
			if (tbl_node)
				goto found;
		}

		if (remote_ports) {
			lookup.saddr = 0;

			tbl_node = tbl_lookup(table, &lookup, sizeof(lookup),
					      port_hash(&lookup), port_cmp);
			if (tbl_node)
				goto found;
		}
	}

	return NULL;

found:
	*mutable = lookup.mutable;
	return tnl_vport_to_vport(tnl_vport_table_cast(tbl_node));
}

static void ecn_decapsulate(struct sk_buff *skb, u8 tos)
{
	if (unlikely(INET_ECN_is_ce(tos))) {
		__be16 protocol = skb->protocol;

		skb_set_network_header(skb, ETH_HLEN);

		if (protocol == htons(ETH_P_8021Q)) {
			if (unlikely(!pskb_may_pull(skb, VLAN_ETH_HLEN)))
				return;

			protocol = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
			skb_set_network_header(skb, VLAN_ETH_HLEN);
		}

		if (protocol == htons(ETH_P_IP)) {
			if (unlikely(!pskb_may_pull(skb, skb_network_offset(skb)
			    + sizeof(struct iphdr))))
				return;

			IP_ECN_set_ce(ip_hdr(skb));
		}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else if (protocol == htons(ETH_P_IPV6)) {
			if (unlikely(!pskb_may_pull(skb, skb_network_offset(skb)
			    + sizeof(struct ipv6hdr))))
				return;

			IP6_ECN_set_ce(ipv6_hdr(skb));
		}
#endif
	}
}

/**
 *	tnl_rcv - ingress point for generic tunnel code
 *
 * @vport: port this packet was received on
 * @skb: received packet
 * @tos: ToS from encapsulating IP packet, used to copy ECN bits
 *
 * Must be called with rcu_read_lock.
 *
 * Packets received by this function are in the following state:
 * - skb->data points to the inner Ethernet header.
 * - The inner Ethernet header is in the linear data area.
 * - skb->csum does not include the inner Ethernet header.
 * - The layer pointers are undefined.
 */
void tnl_rcv(struct vport *vport, struct sk_buff *skb, u8 tos)
{
	struct ethhdr *eh;

	skb_reset_mac_header(skb);
	eh = eth_hdr(skb);

	if (likely(ntohs(eh->h_proto) >= 1536))
		skb->protocol = eh->h_proto;
	else
		skb->protocol = htons(ETH_P_802_2);

	skb_dst_drop(skb);
	nf_reset(skb);
	skb_clear_rxhash(skb);
	secpath_reset(skb);

	ecn_decapsulate(skb, tos);
	vlan_set_tci(skb, 0);

	if (unlikely(compute_ip_summed(skb, false))) {
		kfree_skb(skb);
		return;
	}

	vport_receive(vport, skb);
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
		     struct sk_buff *skb, unsigned int mtu, __be64 flow_key)
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
	} else
		vlan_set_tci(nskb, vlan_get_tci(skb));
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
	if ((mutable->flags & (TNL_F_IN_KEY_MATCH | TNL_F_OUT_KEY_ACTION)) ==
	    (TNL_F_IN_KEY_MATCH | TNL_F_OUT_KEY_ACTION))
		OVS_CB(nskb)->tun_id = flow_key;

	if (unlikely(compute_ip_summed(nskb, false))) {
		kfree_skb(nskb);
		return false;
	}

	vport_receive(vport, nskb);

	return true;
}

static bool check_mtu(struct sk_buff *skb,
		      struct vport *vport,
		      const struct tnl_mutable_config *mutable,
		      const struct rtable *rt, __be16 *frag_offp)
{
	bool df_inherit = mutable->flags & TNL_F_DF_INHERIT;
	bool pmtud = mutable->flags & TNL_F_PMTUD;
	__be16 frag_off = mutable->flags & TNL_F_DF_DEFAULT ? htons(IP_DF) : 0;
	int mtu = 0;
	unsigned int packet_length = skb->len - ETH_HLEN;

	/* Allow for one level of tagging in the packet length. */
	if (!vlan_tx_tag_present(skb) &&
	    eth_hdr(skb)->h_proto == htons(ETH_P_8021Q))
		packet_length -= VLAN_HLEN;

	if (pmtud) {
		int vlan_header = 0;

		/* The tag needs to go in packet regardless of where it
		 * currently is, so subtract it from the MTU.
		 */
		if (vlan_tx_tag_present(skb) ||
		    eth_hdr(skb)->h_proto == htons(ETH_P_8021Q))
			vlan_header = VLAN_HLEN;

		mtu = dst_mtu(&rt_dst(rt))
			- ETH_HLEN
			- mutable->tunnel_hlen
			- vlan_header;
	}

	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iph = ip_hdr(skb);

		if (df_inherit)
			frag_off = iph->frag_off & htons(IP_DF);

		if (pmtud && iph->frag_off & htons(IP_DF)) {
			mtu = max(mtu, IP_MIN_MTU);

			if (packet_length > mtu &&
			    tnl_frag_needed(vport, mutable, skb, mtu,
					    OVS_CB(skb)->tun_id))
				return false;
		}
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		/* IPv6 requires end hosts to do fragmentation
		 * if the packet is above the minimum MTU.
		 */
		if (df_inherit && packet_length > IPV6_MIN_MTU)
			frag_off = htons(IP_DF);

		if (pmtud) {
			mtu = max(mtu, IPV6_MIN_MTU);

			if (packet_length > mtu &&
			    tnl_frag_needed(vport, mutable, skb, mtu,
					    OVS_CB(skb)->tun_id))
				return false;
		}
	}
#endif

	*frag_offp = frag_off;
	return true;
}

static void create_tunnel_header(const struct vport *vport,
				 const struct tnl_mutable_config *mutable,
				 const struct rtable *rt, void *header)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct iphdr *iph = header;

	iph->version	= 4;
	iph->ihl	= sizeof(struct iphdr) >> 2;
	iph->frag_off	= htons(IP_DF);
	iph->protocol	= tnl_vport->tnl_ops->ipproto;
	iph->tos	= mutable->tos;
	iph->daddr	= rt->rt_dst;
	iph->saddr	= rt->rt_src;
	iph->ttl	= mutable->ttl;
	if (!iph->ttl)
		iph->ttl = ip4_dst_hoplimit(&rt_dst(rt));

	tnl_vport->tnl_ops->build_header(vport, mutable, iph + 1);
}

static inline void *get_cached_header(const struct tnl_cache *cache)
{
	return (void *)cache + ALIGN(sizeof(struct tnl_cache), CACHE_DATA_ALIGN);
}

static inline bool check_cache_valid(const struct tnl_cache *cache,
				     const struct tnl_mutable_config *mutable)
{
	return cache &&
#ifdef NEED_CACHE_TIMEOUT
		time_before(jiffies, cache->expiration) &&
#endif
#ifdef HAVE_RT_GENID
		atomic_read(&init_net.ipv4.rt_genid) == cache->rt->rt_genid &&
#endif
#ifdef HAVE_HH_SEQ
		rt_dst(cache->rt).hh->hh_lock.sequence == cache->hh_seq &&
#endif
		mutable->seq == cache->mutable_seq &&
		(!is_internal_dev(rt_dst(cache->rt).dev) ||
		(cache->flow && !cache->flow->dead));
}

static int cache_cleaner_cb(struct tbl_node *tbl_node, void *aux)
{
	struct tnl_vport *tnl_vport = tnl_vport_table_cast(tbl_node);
	const struct tnl_mutable_config *mutable = rcu_dereference(tnl_vport->mutable);
	const struct tnl_cache *cache = rcu_dereference(tnl_vport->cache);

	if (cache && !check_cache_valid(cache, mutable) &&
	    spin_trylock_bh(&tnl_vport->cache_lock)) {
		assign_cache_rcu(tnl_vport_to_vport(tnl_vport), NULL);
		spin_unlock_bh(&tnl_vport->cache_lock);
	}

	return 0;
}

static void cache_cleaner(struct work_struct *work)
{
	schedule_cache_cleaner();

	rcu_read_lock();
	tbl_foreach(rcu_dereference(port_table), cache_cleaner_cb, NULL);
	rcu_read_unlock();
}

static inline void create_eth_hdr(struct tnl_cache *cache,
				  const struct rtable *rt)
{
	void *cache_data = get_cached_header(cache);
	int hh_len = rt_dst(rt).hh->hh_len;
	int hh_off = HH_DATA_ALIGN(rt_dst(rt).hh->hh_len) - hh_len;

#ifdef HAVE_HH_SEQ
	unsigned hh_seq;

	do {
		hh_seq = read_seqbegin(&rt_dst(rt).hh->hh_lock);
		memcpy(cache_data, (void *)rt_dst(rt).hh->hh_data + hh_off, hh_len);
	} while (read_seqretry(&rt_dst(rt).hh->hh_lock, hh_seq));

	cache->hh_seq = hh_seq;
#else
	read_lock_bh(&rt_dst(rt).hh->hh_lock);
	memcpy(cache_data, (void *)rt_dst(rt).hh->hh_data + hh_off, hh_len);
	read_unlock_bh(&rt_dst(rt).hh->hh_lock);
#endif
}

static struct tnl_cache *build_cache(struct vport *vport,
				     const struct tnl_mutable_config *mutable,
				     struct rtable *rt)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct tnl_cache *cache;
	void *cache_data;
	int cache_len;

	if (!(mutable->flags & TNL_F_HDR_CACHE))
		return NULL;

	/*
	 * If there is no entry in the ARP cache or if this device does not
	 * support hard header caching just fall back to the IP stack.
	 */
	if (!rt_dst(rt).hh)
		return NULL;

	/*
	 * If lock is contended fall back to directly building the header.
	 * We're not going to help performance by sitting here spinning.
	 */
	if (!spin_trylock_bh(&tnl_vport->cache_lock))
		return NULL;

	cache = cache_dereference(tnl_vport);
	if (check_cache_valid(cache, mutable))
		goto unlock;
	else
		cache = NULL;

	cache_len = rt_dst(rt).hh->hh_len + mutable->tunnel_hlen;

	cache = kzalloc(ALIGN(sizeof(struct tnl_cache), CACHE_DATA_ALIGN) +
			cache_len, GFP_ATOMIC);
	if (!cache)
		goto unlock;

	cache->len = cache_len;

	create_eth_hdr(cache, rt);
	cache_data = get_cached_header(cache) + rt_dst(rt).hh->hh_len;

	create_tunnel_header(vport, mutable, rt, cache_data);

	cache->mutable_seq = mutable->seq;
	cache->rt = rt;
#ifdef NEED_CACHE_TIMEOUT
	cache->expiration = jiffies + tnl_vport->cache_exp_interval;
#endif

	if (is_internal_dev(rt_dst(rt).dev)) {
		struct sw_flow_key flow_key;
		struct tbl_node *flow_node;
		struct vport *dst_vport;
		struct sk_buff *skb;
		bool is_frag;
		int err;
		int flow_key_len;

		dst_vport = internal_dev_get_vport(rt_dst(rt).dev);
		if (!dst_vport)
			goto done;

		skb = alloc_skb(cache->len, GFP_ATOMIC);
		if (!skb)
			goto done;

		__skb_put(skb, cache->len);
		memcpy(skb->data, get_cached_header(cache), cache->len);

		err = flow_extract(skb, dst_vport->port_no, &flow_key,
				   &flow_key_len, &is_frag);

		consume_skb(skb);
		if (err || is_frag)
			goto done;

		flow_node = tbl_lookup(rcu_dereference(dst_vport->dp->table),
				       &flow_key, flow_key_len,
				       flow_hash(&flow_key, flow_key_len),
				       flow_cmp);
		if (flow_node) {
			struct sw_flow *flow = flow_cast(flow_node);

			cache->flow = flow;
			flow_hold(flow);
		}
	}

done:
	assign_cache_rcu(vport, cache);

unlock:
	spin_unlock_bh(&tnl_vport->cache_lock);

	return cache;
}

static struct rtable *find_route(struct vport *vport,
				 const struct tnl_mutable_config *mutable,
				 u8 tos, struct tnl_cache **cache)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct tnl_cache *cur_cache = rcu_dereference(tnl_vport->cache);

	*cache = NULL;
	tos = RT_TOS(tos);

	if (likely(tos == mutable->tos && check_cache_valid(cur_cache, mutable))) {
		*cache = cur_cache;
		return cur_cache->rt;
	} else {
		struct rtable *rt;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
		struct flowi fl = { .nl_u = { .ip4_u =
					      { .daddr = mutable->daddr,
						.saddr = mutable->saddr,
						.tos = tos } },
				    .proto = tnl_vport->tnl_ops->ipproto };

		if (unlikely(ip_route_output_key(&init_net, &rt, &fl)))
			return NULL;
#else
		struct flowi4 fl = { .daddr = mutable->daddr,
				     .saddr = mutable->saddr,
				     .flowi4_tos = tos,
				     .flowi4_proto = tnl_vport->tnl_ops->ipproto };

		rt = ip_route_output_key(&init_net, &fl);
		if (IS_ERR(rt))
			return NULL;
#endif

		if (likely(tos == mutable->tos))
			*cache = build_cache(vport, mutable, rt);

		return rt;
	}
}

static inline bool need_linearize(const struct sk_buff *skb)
{
	int i;

	if (unlikely(skb_shinfo(skb)->frag_list))
		return true;

	/*
	 * Generally speaking we should linearize if there are paged frags.
	 * However, if all of the refcounts are 1 we know nobody else can
	 * change them from underneath us and we can skip the linearization.
	 */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
		if (unlikely(page_count(skb_shinfo(skb)->frags[i].page) > 1))
			return true;

	return false;
}

static struct sk_buff *handle_offloads(struct sk_buff *skb,
				       const struct tnl_mutable_config *mutable,
				       const struct rtable *rt)
{
	int min_headroom;
	int err;

	min_headroom = LL_RESERVED_SPACE(rt_dst(rt).dev) + rt_dst(rt).header_len
			+ mutable->tunnel_hlen
			+ (vlan_tx_tag_present(skb) ? VLAN_HLEN : 0);

	if (skb_headroom(skb) < min_headroom || skb_header_cloned(skb)) {
		int head_delta = SKB_DATA_ALIGN(min_headroom -
						skb_headroom(skb) +
						16);
		err = pskb_expand_head(skb, max_t(int, head_delta, 0),
					0, GFP_ATOMIC);
		if (unlikely(err))
			goto error_free;
	}

	forward_ip_summed(skb, true);

	if (skb_is_gso(skb)) {
		struct sk_buff *nskb;

		nskb = skb_gso_segment(skb, 0);
		if (IS_ERR(nskb)) {
			kfree_skb(skb);
			err = PTR_ERR(nskb);
			goto error;
		}

		consume_skb(skb);
		skb = nskb;
	} else if (get_ip_summed(skb) == OVS_CSUM_PARTIAL) {
		/* Pages aren't locked and could change at any time.
		 * If this happens after we compute the checksum, the
		 * checksum will be wrong.  We linearize now to avoid
		 * this problem.
		 */
		if (unlikely(need_linearize(skb))) {
			err = __skb_linearize(skb);
			if (unlikely(err))
				goto error_free;
		}

		err = skb_checksum_help(skb);
		if (unlikely(err))
			goto error_free;
	}

	set_ip_summed(skb, OVS_CSUM_NONE);

	return skb;

error_free:
	kfree_skb(skb);
error:
	return ERR_PTR(err);
}

static int send_frags(struct sk_buff *skb,
		      const struct tnl_mutable_config *mutable)
{
	int sent_len;

	sent_len = 0;
	while (skb) {
		struct sk_buff *next = skb->next;
		int frag_len = skb->len - mutable->tunnel_hlen;
		int err;

		skb->next = NULL;
		memset(IPCB(skb), 0, sizeof(*IPCB(skb)));

		err = ip_local_out(skb);
		skb = next;
		if (unlikely(net_xmit_eval(err)))
			goto free_frags;
		sent_len += frag_len;
	}

	return sent_len;

free_frags:
	/*
	 * There's no point in continuing to send fragments once one has been
	 * dropped so just free the rest.  This may help improve the congestion
	 * that caused the first packet to be dropped.
	 */
	tnl_free_linked_skbs(skb);
	return sent_len;
}

int tnl_send(struct vport *vport, struct sk_buff *skb)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	const struct tnl_mutable_config *mutable = rcu_dereference(tnl_vport->mutable);

	enum vport_err_type err = VPORT_E_TX_ERROR;
	struct rtable *rt;
	struct dst_entry *unattached_dst = NULL;
	struct tnl_cache *cache;
	int sent_len = 0;
	__be16 frag_off = 0;
	u8 ttl;
	u8 inner_tos;
	u8 tos;

	/* Validate the protocol headers before we try to use them. */
	if (skb->protocol == htons(ETH_P_8021Q) &&
	    !vlan_tx_tag_present(skb)) {
		if (unlikely(!pskb_may_pull(skb, VLAN_ETH_HLEN)))
			goto error_free;

		skb->protocol = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
		skb_set_network_header(skb, VLAN_ETH_HLEN);
	}

	if (skb->protocol == htons(ETH_P_IP)) {
		if (unlikely(!pskb_may_pull(skb, skb_network_offset(skb)
		    + sizeof(struct iphdr))))
			skb->protocol = 0;
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		if (unlikely(!pskb_may_pull(skb, skb_network_offset(skb)
		    + sizeof(struct ipv6hdr))))
			skb->protocol = 0;
	}
#endif

	/* ToS */
	if (skb->protocol == htons(ETH_P_IP))
		inner_tos = ip_hdr(skb)->tos;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (skb->protocol == htons(ETH_P_IPV6))
		inner_tos = ipv6_get_dsfield(ipv6_hdr(skb));
#endif
	else
		inner_tos = 0;

	if (mutable->flags & TNL_F_TOS_INHERIT)
		tos = inner_tos;
	else
		tos = mutable->tos;

	tos = INET_ECN_encapsulate(tos, inner_tos);

	/* Route lookup */
	rt = find_route(vport, mutable, tos, &cache);
	if (unlikely(!rt))
		goto error_free;
	if (unlikely(!cache))
		unattached_dst = &rt_dst(rt);

	/* Reset SKB */
	nf_reset(skb);
	secpath_reset(skb);
	skb_dst_drop(skb);
	skb_clear_rxhash(skb);

	/* Offloading */
	skb = handle_offloads(skb, mutable, rt);
	if (IS_ERR(skb))
		goto error;

	/* MTU */
	if (unlikely(!check_mtu(skb, vport, mutable, rt, &frag_off))) {
		err = VPORT_E_TX_DROPPED;
		goto error_free;
	}

	/*
	 * If we are over the MTU, allow the IP stack to handle fragmentation.
	 * Fragmentation is a slow path anyways.
	 */
	if (unlikely(skb->len + mutable->tunnel_hlen > dst_mtu(&rt_dst(rt)) &&
		     cache)) {
		unattached_dst = &rt_dst(rt);
		dst_hold(unattached_dst);
		cache = NULL;
	}

	/* TTL */
	ttl = mutable->ttl;
	if (!ttl)
		ttl = ip4_dst_hoplimit(&rt_dst(rt));

	if (mutable->flags & TNL_F_TTL_INHERIT) {
		if (skb->protocol == htons(ETH_P_IP))
			ttl = ip_hdr(skb)->ttl;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else if (skb->protocol == htons(ETH_P_IPV6))
			ttl = ipv6_hdr(skb)->hop_limit;
#endif
	}

	while (skb) {
		struct iphdr *iph;
		struct sk_buff *next_skb = skb->next;
		skb->next = NULL;

		if (unlikely(vlan_deaccel_tag(skb)))
			goto next;

		if (likely(cache)) {
			skb_push(skb, cache->len);
			memcpy(skb->data, get_cached_header(cache), cache->len);
			skb_reset_mac_header(skb);
			skb_set_network_header(skb, rt_dst(rt).hh->hh_len);

		} else {
			skb_push(skb, mutable->tunnel_hlen);
			create_tunnel_header(vport, mutable, rt, skb->data);
			skb_reset_network_header(skb);

			if (next_skb)
				skb_dst_set(skb, dst_clone(unattached_dst));
			else {
				skb_dst_set(skb, unattached_dst);
				unattached_dst = NULL;
			}
		}
		skb_set_transport_header(skb, skb_network_offset(skb) + sizeof(struct iphdr));

		iph = ip_hdr(skb);
		iph->tos = tos;
		iph->ttl = ttl;
		iph->frag_off = frag_off;
		ip_select_ident(iph, &rt_dst(rt), NULL);

		skb = tnl_vport->tnl_ops->update_header(vport, mutable, &rt_dst(rt), skb);
		if (unlikely(!skb))
			goto next;

		if (likely(cache)) {
			int orig_len = skb->len - cache->len;
			struct vport *cache_vport = internal_dev_get_vport(rt_dst(rt).dev);

			skb->protocol = htons(ETH_P_IP);
			iph = ip_hdr(skb);
			iph->tot_len = htons(skb->len - skb_network_offset(skb));
			ip_send_check(iph);

			if (cache_vport) {
				if (unlikely(compute_ip_summed(skb, true))) {
					kfree_skb(skb);
					goto next;
				}

				OVS_CB(skb)->flow = cache->flow;
				vport_receive(cache_vport, skb);
				sent_len += orig_len;
			} else {
				int xmit_err;

				skb->dev = rt_dst(rt).dev;
				xmit_err = dev_queue_xmit(skb);

				if (likely(net_xmit_eval(xmit_err) == 0))
					sent_len += orig_len;
			}
		} else
			sent_len += send_frags(skb, mutable);

next:
		skb = next_skb;
	}

	if (unlikely(sent_len == 0))
		vport_record_error(vport, VPORT_E_TX_DROPPED);

	goto out;

error_free:
	tnl_free_linked_skbs(skb);
error:
	vport_record_error(vport, err);
out:
	dst_release(unattached_dst);
	return sent_len;
}

static const struct nla_policy tnl_policy[ODP_TUNNEL_ATTR_MAX + 1] = {
	[ODP_TUNNEL_ATTR_FLAGS]    = { .type = NLA_U32 },
	[ODP_TUNNEL_ATTR_DST_IPV4] = { .type = NLA_U32 },
	[ODP_TUNNEL_ATTR_SRC_IPV4] = { .type = NLA_U32 },
	[ODP_TUNNEL_ATTR_OUT_KEY]  = { .type = NLA_U64 },
	[ODP_TUNNEL_ATTR_IN_KEY]   = { .type = NLA_U64 },
	[ODP_TUNNEL_ATTR_TOS]      = { .type = NLA_U8 },
	[ODP_TUNNEL_ATTR_TTL]      = { .type = NLA_U8 },
};

/* Sets ODP_TUNNEL_ATTR_* fields in 'mutable', which must initially be zeroed. */
static int tnl_set_config(struct nlattr *options, const struct tnl_ops *tnl_ops,
			  const struct vport *cur_vport,
			  struct tnl_mutable_config *mutable)
{
	const struct vport *old_vport;
	const struct tnl_mutable_config *old_mutable;
	struct nlattr *a[ODP_TUNNEL_ATTR_MAX + 1];
	int err;

	if (!options)
		return -EINVAL;

	err = nla_parse_nested(a, ODP_TUNNEL_ATTR_MAX, options, tnl_policy);
	if (err)
		return err;

	if (!a[ODP_TUNNEL_ATTR_FLAGS] || !a[ODP_TUNNEL_ATTR_DST_IPV4])
		return -EINVAL;

	mutable->flags = nla_get_u32(a[ODP_TUNNEL_ATTR_FLAGS]) & TNL_F_PUBLIC;

	if (a[ODP_TUNNEL_ATTR_SRC_IPV4])
		mutable->saddr = nla_get_be32(a[ODP_TUNNEL_ATTR_SRC_IPV4]);
	mutable->daddr = nla_get_be32(a[ODP_TUNNEL_ATTR_DST_IPV4]);

	if (a[ODP_TUNNEL_ATTR_TOS]) {
		mutable->tos = nla_get_u8(a[ODP_TUNNEL_ATTR_TOS]);
		if (mutable->tos != RT_TOS(mutable->tos))
			return -EINVAL;
	}

	if (a[ODP_TUNNEL_ATTR_TTL])
		mutable->ttl = nla_get_u8(a[ODP_TUNNEL_ATTR_TTL]);

	mutable->tunnel_type = tnl_ops->tunnel_type;
	if (!a[ODP_TUNNEL_ATTR_IN_KEY]) {
		mutable->tunnel_type |= TNL_T_KEY_MATCH;
		mutable->flags |= TNL_F_IN_KEY_MATCH;
	} else {
		mutable->tunnel_type |= TNL_T_KEY_EXACT;
		mutable->in_key = nla_get_be64(a[ODP_TUNNEL_ATTR_IN_KEY]);
	}

	if (!a[ODP_TUNNEL_ATTR_OUT_KEY])
		mutable->flags |= TNL_F_OUT_KEY_ACTION;
	else
		mutable->out_key = nla_get_be64(a[ODP_TUNNEL_ATTR_OUT_KEY]);

	mutable->tunnel_hlen = tnl_ops->hdr_len(mutable);
	if (mutable->tunnel_hlen < 0)
		return mutable->tunnel_hlen;

	mutable->tunnel_hlen += sizeof(struct iphdr);

	old_vport = tnl_find_port(mutable->saddr, mutable->daddr,
				  mutable->in_key, mutable->tunnel_type,
				  &old_mutable);

	if (old_vport && old_vport != cur_vport)
		return -EEXIST;

	return 0;
}

struct vport *tnl_create(const struct vport_parms *parms,
			 const struct vport_ops *vport_ops,
			 const struct tnl_ops *tnl_ops)
{
	struct vport *vport;
	struct tnl_vport *tnl_vport;
	struct tnl_mutable_config *mutable;
	int initial_frag_id;
	int err;

	vport = vport_alloc(sizeof(struct tnl_vport), vport_ops, parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	tnl_vport = tnl_vport_priv(vport);

	strcpy(tnl_vport->name, parms->name);
	tnl_vport->tnl_ops = tnl_ops;

	mutable = kzalloc(sizeof(struct tnl_mutable_config), GFP_KERNEL);
	if (!mutable) {
		err = -ENOMEM;
		goto error_free_vport;
	}

	vport_gen_rand_ether_addr(mutable->eth_addr);

	get_random_bytes(&initial_frag_id, sizeof(int));
	atomic_set(&tnl_vport->frag_id, initial_frag_id);

	err = tnl_set_config(parms->options, tnl_ops, NULL, mutable);
	if (err)
		goto error_free_mutable;

	spin_lock_init(&tnl_vport->cache_lock);

#ifdef NEED_CACHE_TIMEOUT
	tnl_vport->cache_exp_interval = MAX_CACHE_EXP -
				       (net_random() % (MAX_CACHE_EXP / 2));
#endif

	rcu_assign_pointer(tnl_vport->mutable, mutable);

	err = add_port(vport);
	if (err)
		goto error_free_mutable;

	return vport;

error_free_mutable:
	kfree(mutable);
error_free_vport:
	vport_free(vport);
error:
	return ERR_PTR(err);
}

int tnl_set_options(struct vport *vport, struct nlattr *options)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	const struct tnl_mutable_config *old_mutable;
	struct tnl_mutable_config *mutable;
	int err;

	mutable = kzalloc(sizeof(struct tnl_mutable_config), GFP_KERNEL);
	if (!mutable) {
		err = -ENOMEM;
		goto error;
	}

	/* Copy fields whose values should be retained. */
	old_mutable = rtnl_dereference(tnl_vport->mutable);
	mutable->seq = old_mutable->seq + 1;
	memcpy(mutable->eth_addr, old_mutable->eth_addr, ETH_ALEN);

	/* Parse the others configured by userspace. */
	err = tnl_set_config(options, tnl_vport->tnl_ops, vport, mutable);
	if (err)
		goto error_free;

	err = move_port(vport, mutable);
	if (err)
		goto error_free;

	return 0;

error_free:
	kfree(mutable);
error:
	return err;
}

int tnl_get_options(const struct vport *vport, struct sk_buff *skb)
{
	const struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	const struct tnl_mutable_config *mutable = rcu_dereference_rtnl(tnl_vport->mutable);

	NLA_PUT_U32(skb, ODP_TUNNEL_ATTR_FLAGS, mutable->flags & TNL_F_PUBLIC);
	NLA_PUT_BE32(skb, ODP_TUNNEL_ATTR_DST_IPV4, mutable->daddr);

	if (!(mutable->flags & TNL_F_IN_KEY_MATCH))
		NLA_PUT_BE64(skb, ODP_TUNNEL_ATTR_IN_KEY, mutable->in_key);
	if (!(mutable->flags & TNL_F_OUT_KEY_ACTION))
		NLA_PUT_BE64(skb, ODP_TUNNEL_ATTR_OUT_KEY, mutable->out_key);
	if (mutable->saddr)
		NLA_PUT_BE32(skb, ODP_TUNNEL_ATTR_SRC_IPV4, mutable->saddr);
	if (mutable->tos)
		NLA_PUT_U8(skb, ODP_TUNNEL_ATTR_TOS, mutable->tos);
	if (mutable->ttl)
		NLA_PUT_U8(skb, ODP_TUNNEL_ATTR_TTL, mutable->ttl);

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static void free_port_rcu(struct rcu_head *rcu)
{
	struct tnl_vport *tnl_vport = container_of(rcu,
						   struct tnl_vport, rcu);

	free_cache((struct tnl_cache __force *)tnl_vport->cache);
	kfree((struct tnl_mutable __force *)tnl_vport->mutable);
	vport_free(tnl_vport_to_vport(tnl_vport));
}

int tnl_destroy(struct vport *vport)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	const struct tnl_mutable_config *mutable, *old_mutable;

	mutable = rtnl_dereference(tnl_vport->mutable);

	if (vport == tnl_find_port(mutable->saddr, mutable->daddr,
				   mutable->in_key, mutable->tunnel_type,
				   &old_mutable))
		del_port(vport);

	call_rcu(&tnl_vport->rcu, free_port_rcu);

	return 0;
}

int tnl_set_addr(struct vport *vport, const unsigned char *addr)
{
	struct tnl_vport *tnl_vport = tnl_vport_priv(vport);
	struct tnl_mutable_config *mutable;

	mutable = kmemdup(rtnl_dereference(tnl_vport->mutable),
			  sizeof(struct tnl_mutable_config), GFP_KERNEL);
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
	return rcu_dereference_rtnl(tnl_vport->mutable)->eth_addr;
}

void tnl_free_linked_skbs(struct sk_buff *skb)
{
	while (skb) {
		struct sk_buff *next = skb->next;
		kfree_skb(skb);
		skb = next;
	}
}
