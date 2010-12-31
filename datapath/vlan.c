/*
 * Copyright (c) 2011 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/if_vlan.h>
#include <linux/skbuff.h>

#include "datapath.h"
#include "vlan.h"

#ifdef NEED_VLAN_FIELD
void vlan_copy_skb_tci(struct sk_buff *skb)
{
	OVS_CB(skb)->vlan_tci = 0;
}

u16 vlan_get_tci(struct sk_buff *skb)
{
	return OVS_CB(skb)->vlan_tci;
}

void vlan_set_tci(struct sk_buff *skb, u16 vlan_tci)
{
	OVS_CB(skb)->vlan_tci = vlan_tci;
}

bool vlan_tx_tag_present(struct sk_buff *skb)
{
	return OVS_CB(skb)->vlan_tci & VLAN_TAG_PRESENT;
}

u16 vlan_tx_tag_get(struct sk_buff *skb)
{
	return OVS_CB(skb)->vlan_tci & ~VLAN_TAG_PRESENT;
}

struct sk_buff *__vlan_hwaccel_put_tag(struct sk_buff *skb, u16 vlan_tci)
{
	OVS_CB(skb)->vlan_tci = vlan_tci | VLAN_TAG_PRESENT;
	return skb;
}
#endif /* NEED_VLAN_FIELD */
