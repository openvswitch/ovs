/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef TUNNEL_H
#define TUNNEL_H 1

#include "openvswitch/tunnel.h"
#include "table.h"
#include "vport.h"

/*
 * The absolute minimum fragment size.  Note that there are many other
 * definitions of the minimum MTU.
 */
#define IP_MIN_MTU 68

/*
 * One of these goes in your struct tnl_ops and in tnl_find_port().
 * These values are in the same namespace as other TNL_T_* values, so
 * you have only the first 10 bits to define protocol identifiers.
 */
#define TNL_T_PROTO_GRE		0
#define TNL_T_PROTO_CAPWAP	1

/* You only need these flags when you are calling tnl_find_port(). */
#define TNL_T_KEY_EXACT		(1 << 10)
#define TNL_T_KEY_MATCH		(1 << 11)
#define TNL_T_KEY_EITHER	(TNL_T_KEY_EXACT | TNL_T_KEY_MATCH)

struct tnl_mutable_config {
	struct rcu_head rcu;

	unsigned char eth_addr[ETH_ALEN];
	unsigned int mtu;
	struct tnl_port_config port_config;

	/* Set of TNL_T_* flags that define the category for lookup. */
	u32 tunnel_type;

	int tunnel_hlen; /* Tunnel header length. */
};

struct tnl_ops {
	/* Put your TNL_T_PROTO_* type in here. */
	u32 tunnel_type;
	u8 ipproto;

	/*
	 * Returns the length of the tunnel header you will add in
	 * build_header() (i.e. excludes the IP header).  Returns a negative
	 * error code if the configuration is invalid.
	 */
	int (*hdr_len)(const struct tnl_port_config *);

	/*
	 * Returns a linked list of SKBs with tunnel headers (multiple
	 * packets may be generated in the event of fragmentation).  Space
	 * will have already been allocated at the start of the packet equal
	 * to sizeof(struct iphdr) + value returned by hdr_len().  The IP
	 * header will have already been constructed.
	 */
	struct sk_buff *(*build_header)(struct sk_buff *,
					const struct vport *,
					const struct tnl_mutable_config *,
					struct dst_entry *);
};

struct tnl_vport {
	struct rcu_head rcu;
	struct tbl_node tbl_node;

	char name[IFNAMSIZ];
	const struct tnl_ops *tnl_ops;

	/* Protected by RCU. */
	struct tnl_mutable_config *mutable;

	atomic_t frag_id;
};

int tnl_init(void);
void tnl_exit(void);
struct vport *tnl_create(const char *name, const void __user *config,
			 const struct vport_ops *,
			 const struct tnl_ops *);
int tnl_modify(struct vport *, const void __user *config);
int tnl_destroy(struct vport *);
int tnl_set_mtu(struct vport *vport, int mtu);
int tnl_set_addr(struct vport *vport, const unsigned char *addr);
const char *tnl_get_name(const struct vport *vport);
const unsigned char *tnl_get_addr(const struct vport *vport);
int tnl_get_mtu(const struct vport *vport);
int tnl_send(struct vport *vport, struct sk_buff *skb);
void tnl_rcv(struct vport *vport, struct sk_buff *skb);

struct vport *tnl_find_port(__be32 saddr, __be32 daddr, __be32 key,
			    int tunnel_type,
			    const struct tnl_mutable_config **mutable);
bool tnl_frag_needed(struct vport *vport,
		     const struct tnl_mutable_config *mutable,
		     struct sk_buff *skb, unsigned int mtu, __be32 flow_key);

static inline struct tnl_vport *tnl_vport_priv(const struct vport *vport)
{
	return vport_priv(vport);
}

#endif /* tunnel.h */
