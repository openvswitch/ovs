/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef FLOW_H
#define FLOW_H 1

#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/flex_array.h>
#include <net/inet_ecn.h>

struct sk_buff;

struct sw_flow_actions {
	struct rcu_head rcu;
	u32 actions_len;
	struct nlattr actions[];
};

/* Mask for the OVS_FRAG_TYPE_* value in the low 2 bits of ip.tos_frag in
 * struct sw_flow_key. */
#define OVS_FRAG_TYPE_MASK INET_ECN_MASK

struct sw_flow_key {
	struct {
		__be64	tun_id;		/* Encapsulating tunnel ID. */
		u32	priority;	/* Packet QoS priority. */
		u16	in_port;	/* Input switch port (or USHRT_MAX). */
	} phy;
	struct {
		u8     src[ETH_ALEN];	/* Ethernet source address. */
		u8     dst[ETH_ALEN];	/* Ethernet destination address. */
		__be16 tci;		/* 0 if no VLAN, VLAN_TAG_PRESENT set otherwise. */
		__be16 type;		/* Ethernet frame type. */
	} eth;
	struct {
		u8     proto;		/* IP protocol or lower 8 bits of ARP opcode. */
		u8     tos_frag;	/* IP ToS DSCP in high 6 bits,
					 * OVS_FRAG_TYPE_* in low 2 bits. */
	} ip;
	union {
		struct {
			struct {
				__be32 src;	/* IP source address. */
				__be32 dst;	/* IP destination address. */
			} addr;
			union {
				struct {
					__be16 src;		/* TCP/UDP source port. */
					__be16 dst;		/* TCP/UDP destination port. */
				} tp;
				struct {
					u8 sha[ETH_ALEN];	/* ARP source hardware address. */
					u8 tha[ETH_ALEN];	/* ARP target hardware address. */
				} arp;
			};
		} ipv4;
		struct {
			struct {
				struct in6_addr src;	/* IPv6 source address. */
				struct in6_addr dst;	/* IPv6 destination address. */
			} addr;
			__be32 label; 		/* IPv6 flow label. */
			struct {
				__be16 src;		/* TCP/UDP source port. */
				__be16 dst;		/* TCP/UDP destination port. */
			} tp;
			struct {
				struct in6_addr target;	/* ND target address. */
				u8 sll[ETH_ALEN];	/* ND source link layer address. */
				u8 tll[ETH_ALEN];	/* ND target link layer address. */
			} nd;
		} ipv6;
	};
};

struct sw_flow {
	struct rcu_head rcu;
	struct hlist_node  hash_node;
	u32 hash;

	struct sw_flow_key key;
	struct sw_flow_actions __rcu *sf_acts;

	atomic_t refcnt;
	bool dead;

	spinlock_t lock;	/* Lock for values below. */
	unsigned long used;	/* Last used time (in jiffies). */
	u64 packet_count;	/* Number of packets matched. */
	u64 byte_count;		/* Number of bytes matched. */
	u8 tcp_flags;		/* Union of seen TCP flags. */
};

struct arp_eth_header {
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
} __packed;

int flow_init(void);
void flow_exit(void);

struct sw_flow *flow_alloc(void);
void flow_deferred_free(struct sw_flow *);

struct sw_flow_actions *flow_actions_alloc(const struct nlattr *);
void flow_deferred_free_acts(struct sw_flow_actions *);

void flow_hold(struct sw_flow *);
void flow_put(struct sw_flow *);

int flow_extract(struct sk_buff *, u16 in_port, struct sw_flow_key *,
		 int *key_lenp);
void flow_used(struct sw_flow *, struct sk_buff *);
u64 flow_used_time(unsigned long flow_jiffies);

/* Upper bound on the length of a nlattr-formatted flow key.  The longest
 * nlattr-formatted flow key would be:
 *
 *                         struct  pad  nl hdr  total
 *                         ------  ---  ------  -----
 *  OVS_KEY_ATTR_PRIORITY      4    --     4      8
 *  OVS_KEY_ATTR_TUN_ID        8    --     4     12
 *  OVS_KEY_ATTR_IN_PORT       4    --     4      8
 *  OVS_KEY_ATTR_ETHERNET     12    --     4     16
 *  OVS_KEY_ATTR_8021Q         4    --     4      8
 *  OVS_KEY_ATTR_ETHERTYPE     2     2     4      8
 *  OVS_KEY_ATTR_IPV6         38     2     4     44
 *  OVS_KEY_ATTR_ICMPV6        2     2     4      8
 *  OVS_KEY_ATTR_ND           28    --     4     32
 *  -------------------------------------------------
 *  total                                       144
 */
#define FLOW_BUFSIZE 144

int flow_to_nlattrs(const struct sw_flow_key *, struct sk_buff *);
int flow_from_nlattrs(struct sw_flow_key *swkey, int *key_lenp,
		      const struct nlattr *);
int flow_metadata_from_nlattrs(u32 *priority, u16 *in_port, __be64 *tun_id,
			       const struct nlattr *);

#define TBL_MIN_BUCKETS		1024

struct flow_table {
	struct flex_array *buckets;
	unsigned int count, n_buckets;
	struct rcu_head rcu;
};

static inline int flow_tbl_count(struct flow_table *table)
{
	return table->count;
}

static inline int flow_tbl_need_to_expand(struct flow_table *table)
{
	return (table->count > table->n_buckets);
}

struct sw_flow *flow_tbl_lookup(struct flow_table *table,
				struct sw_flow_key *key,    int len);
void flow_tbl_destroy(struct flow_table *table);
void flow_tbl_deferred_destroy(struct flow_table *table);
struct flow_table *flow_tbl_alloc(int new_size);
struct flow_table *flow_tbl_expand(struct flow_table *table);
void flow_tbl_insert(struct flow_table *table, struct sw_flow *flow);
void flow_tbl_remove(struct flow_table *table, struct sw_flow *flow);
u32 flow_hash(const struct sw_flow_key *key, int key_len);

struct sw_flow *flow_tbl_next(struct flow_table *table, u32 *bucket, u32 *idx);
extern const u32 ovs_key_lens[OVS_KEY_ATTR_MAX + 1];

#endif /* flow.h */
