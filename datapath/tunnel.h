/*
 * Copyright (c) 2007-2012 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef TUNNEL_H
#define TUNNEL_H 1

#include <linux/version.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "flow.h"
#include "vport.h"

struct tnl_ops {
	u8 ipproto;		/* The IP protocol for the tunnel. */

	/*
	 * Returns the length of the tunnel header that will be added in
	 * build_header() (i.e. excludes the IP header).
	 */
	int (*hdr_len)(const struct ovs_key_ipv4_tunnel *);
	/*
	* Builds header for given SKB.  Space will have already been
	* allocated at the start of the packet equal
	* to sizeof(struct iphdr) + value returned by hdr_len().
	*/
	void (*build_header)(const struct vport *, struct sk_buff *,
			     int tunnel_hlen);
};

struct tnl_vport {
	struct rcu_head rcu;

	__be16 dst_port;
	char name[IFNAMSIZ];
	const struct tnl_ops *tnl_ops;
};

struct vport *ovs_tnl_create(const struct vport_parms *, const struct vport_ops *,
			     const struct tnl_ops *);
void ovs_tnl_destroy(struct vport *);

const char *ovs_tnl_get_name(const struct vport *vport);
int ovs_tnl_send(struct vport *vport, struct sk_buff *skb);
void ovs_tnl_rcv(struct vport *vport, struct sk_buff *skb);
u16 ovs_tnl_get_src_port(struct sk_buff *skb);

static inline struct tnl_vport *tnl_vport_priv(const struct vport *vport)
{
	return vport_priv(vport);
}

static inline void tnl_tun_key_init(struct ovs_key_ipv4_tunnel *tun_key,
				    const struct iphdr *iph, __be64 tun_id, u32 tun_flags)
{
	tun_key->tun_id = tun_id;
	tun_key->ipv4_src = iph->saddr;
	tun_key->ipv4_dst = iph->daddr;
	tun_key->ipv4_tos = iph->tos;
	tun_key->ipv4_ttl = iph->ttl;
	tun_key->tun_flags = tun_flags;

	/* clear struct padding. */
	memset((unsigned char*) tun_key + OVS_TUNNEL_KEY_SIZE, 0,
	       sizeof(*tun_key) - OVS_TUNNEL_KEY_SIZE);
}

#endif /* tunnel.h */
