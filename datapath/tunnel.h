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

u16 ovs_tnl_get_src_port(struct sk_buff *skb);

int ovs_tnl_send(struct vport *vport, struct sk_buff *skb,
		 u8 ipproto, int tunnel_hlen,
		 void (*build_header)(const struct vport *,
				      struct sk_buff *,
				      int tunnel_hlen));

void ovs_tnl_rcv(struct vport *vport, struct sk_buff *skb,
		 struct ovs_key_ipv4_tunnel *tun_key);

#endif /* TUNNEL_H */
