/*
 * Copyright (c) 2014 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#ifndef _NET_MPLS_WRAPPER_H
#define _NET_MPLS_WRAPPER_H 1

#include <linux/if_ether.h>
#include <linux/netdevice.h>

#define MPLS_HLEN 4

struct mpls_shim_hdr {
	__be32 label_stack_entry;
};

static inline bool eth_p_mpls(__be16 eth_type)
{
	return eth_type == htons(ETH_P_MPLS_UC) ||
		eth_type == htons(ETH_P_MPLS_MC);
}

/* Starting from kernel 4.9, commit 48d2ab609b6b ("net: mpls: Fixups for GSO")
 * and commit 85de4a2101ac ("openvswitch: use mpls_hdr") introduced
 * behavioural changes to mpls_gso kernel module. It now assumes that
 * skb_network_header() points to the mpls header and
 * skb_inner_network_header() points to the L3 header. However, the old
 * mpls_gso kernel module assumes that the skb_network_header() points
 * to the L3 header. We shall backport the following function to ensure
 * MPLS GSO works properly for kernels older than the one which contains
 * these commits.
 */
#ifdef MPLS_HEADER_IS_L3
static inline struct mpls_shim_hdr *mpls_hdr(const struct sk_buff *skb)
{
    return (struct mpls_shim_hdr *)skb_network_header(skb);
}
#else
#define mpls_hdr rpl_mpls_hdr
/*
 * For non-MPLS skbs this will correspond to the network header.
 * For MPLS skbs it will be before the network_header as the MPLS
 * label stack lies between the end of the mac header and the network
 * header. That is, for MPLS skbs the end of the mac header
 * is the top of the MPLS label stack.
 */
static inline struct mpls_shim_hdr *rpl_mpls_hdr(const struct sk_buff *skb)
{
	return (struct mpls_shim_hdr *) (skb_mac_header(skb) + skb->mac_len);
}
#endif

#endif /* _NET_MPLS_WRAPPER_H */
