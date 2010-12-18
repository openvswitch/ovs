/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef TUNNEL_H
#define TUNNEL_H 1

#include <linux/version.h>

#include "flow.h"
#include "openvswitch/tunnel.h"
#include "table.h"
#include "vport.h"

/*
 * The absolute minimum fragment size.  Note that there are many other
 * definitions of the minimum MTU.
 */
#define IP_MIN_MTU 68

/*
 * One of these goes in struct tnl_ops and in tnl_find_port().
 * These values are in the same namespace as other TNL_T_* values, so
 * only the least significant 10 bits are available to define protocol
 * identifiers.
 */
#define TNL_T_PROTO_GRE		0
#define TNL_T_PROTO_CAPWAP	1

/* These flags are only needed when calling tnl_find_port(). */
#define TNL_T_KEY_EXACT		(1 << 10)
#define TNL_T_KEY_MATCH		(1 << 11)
#define TNL_T_KEY_EITHER	(TNL_T_KEY_EXACT | TNL_T_KEY_MATCH)

struct tnl_mutable_config {
	struct rcu_head rcu;

	unsigned seq;		/* Sequence number to identify this config. */

	u32 tunnel_type;	/* Set of TNL_T_* flags that define lookup. */
	unsigned tunnel_hlen; 	/* Tunnel header length. */

	unsigned char eth_addr[ETH_ALEN];
	unsigned mtu;

	struct tnl_port_config port_config;
};

struct tnl_ops {
	u32 tunnel_type;	/* Put the TNL_T_PROTO_* type in here. */
	u8 ipproto;		/* The IP protocol for the tunnel. */

	/*
	 * Returns the length of the tunnel header that will be added in
	 * build_header() (i.e. excludes the IP header).  Returns a negative
	 * error code if the configuration is invalid.
	 */
	int (*hdr_len)(const struct tnl_port_config *);

	/*
	 * Builds the static portion of the tunnel header, which is stored in
	 * the header cache.  In general the performance of this function is
	 * not too important as we try to only call it when building the cache
	 * so it is preferable to shift as much work as possible here.  However,
	 * in some circumstances caching is disabled and this function will be
	 * called for every packet, so try not to make it too slow.
	 */
	void (*build_header)(const struct vport *,
			     const struct tnl_mutable_config *, void *header);

	/*
	 * Updates the cached header of a packet to match the actual packet
	 * data.  Typical things that might need to be updated are length,
	 * checksum, etc.  The IP header will have already been updated and this
	 * is the final step before transmission.  Returns a linked list of
	 * completed SKBs (multiple packets may be generated in the event
	 * of fragmentation).
	 */
	struct sk_buff *(*update_header)(const struct vport *,
					 const struct tnl_mutable_config *,
					 struct dst_entry *, struct sk_buff *);
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
/*
 * On these kernels we have a fast mechanism to tell if the ARP cache for a
 * particular destination has changed.
 */
#define HAVE_HH_SEQ
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
/*
 * On these kernels we have a fast mechanism to tell if the routing table
 * has changed.
 */
#define HAVE_RT_GENID
#endif
#if !defined(HAVE_HH_SEQ) || !defined(HAVE_RT_GENID)
/* If we can't detect all system changes directly we need to use a timeout. */
#define NEED_CACHE_TIMEOUT
#endif
struct tnl_cache {
	struct rcu_head rcu;

	int len;		/* Length of data to be memcpy'd from cache. */

	/* Sequence number of mutable->seq from which this cache was generated. */
	unsigned mutable_seq;

#ifdef HAVE_HH_SEQ
	/*
	 * The sequence number from the seqlock protecting the hardware header
	 * cache (in the ARP cache).  Since every write increments the counter
	 * this gives us an easy way to tell if it has changed.
	 */
	unsigned hh_seq;
#endif

#ifdef NEED_CACHE_TIMEOUT
	/*
	 * If we don't have direct mechanisms to detect all important changes in
	 * the system fall back to an expiration time.  This expiration time
	 * can be relatively short since at high rates there will be millions of
	 * packets per second, so we'll still get plenty of benefit from the
	 * cache.  Note that if something changes we may blackhole packets
	 * until the expiration time (depending on what changed and the kernel
	 * version we may be able to detect the change sooner).  Expiration is
	 * expressed as a time in jiffies.
	 */
	unsigned long expiration;
#endif

	/*
	 * The routing table entry that is the result of looking up the tunnel
	 * endpoints.  It also contains a sequence number (called a generation
	 * ID) that can be compared to a global sequence to tell if the routing
	 * table has changed (and therefore there is a potential that this
	 * cached route has been invalidated).
	 */
	struct rtable *rt;

	/*
	 * If the output device for tunnel traffic is an OVS internal device,
	 * the flow of that datapath.  Since all tunnel traffic will have the
	 * same headers this allows us to cache the flow lookup.  NULL if the
	 * output device is not OVS or if there is no flow installed.
	 */
	struct sw_flow *flow;

	/* The cached header follows after padding for alignment. */
};

struct tnl_vport {
	struct rcu_head rcu;
	struct tbl_node tbl_node;

	char name[IFNAMSIZ];
	const struct tnl_ops *tnl_ops;

	struct tnl_mutable_config __rcu *mutable;

	/*
	 * ID of last fragment sent (for tunnel protocols with direct support
	 * fragmentation).  If the protocol relies on IP fragmentation then
	 * this is not needed.
	 */
	atomic_t frag_id;

	spinlock_t cache_lock;
	struct tnl_cache __rcu *cache;		/* Protected by RCU/cache_lock. */

#ifdef NEED_CACHE_TIMEOUT
	/*
	 * If we must rely on expiration time to invalidate the cache, this is
	 * the interval.  It is randomized within a range (defined by
	 * MAX_CACHE_EXP in tunnel.c) to avoid synchronized expirations caused
	 * by creation of a large number of tunnels at a one time.
	 */
	unsigned long cache_exp_interval;
#endif
};

struct vport *tnl_create(const struct vport_parms *, const struct vport_ops *,
			 const struct tnl_ops *);
int tnl_modify(struct vport *, struct odp_port *);
int tnl_destroy(struct vport *);
int tnl_set_mtu(struct vport *vport, int mtu);
int tnl_set_addr(struct vport *vport, const unsigned char *addr);
const char *tnl_get_name(const struct vport *vport);
const unsigned char *tnl_get_addr(const struct vport *vport);
void tnl_get_config(const struct vport *vport, void *config);
int tnl_get_mtu(const struct vport *vport);
int tnl_send(struct vport *vport, struct sk_buff *skb);
void tnl_rcv(struct vport *vport, struct sk_buff *skb);

struct vport *tnl_find_port(__be32 saddr, __be32 daddr, __be64 key,
			    int tunnel_type,
			    const struct tnl_mutable_config **mutable);
bool tnl_frag_needed(struct vport *vport,
		     const struct tnl_mutable_config *mutable,
		     struct sk_buff *skb, unsigned int mtu, __be64 flow_key);
void tnl_free_linked_skbs(struct sk_buff *skb);

static inline struct tnl_vport *tnl_vport_priv(const struct vport *vport)
{
	return vport_priv(vport);
}


#endif /* tunnel.h */
