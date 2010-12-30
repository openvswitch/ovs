/*
 * Copyright (c) 2011 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef VLAN_H
#define VLAN_H 1

#include <linux/if_vlan.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
#define NEED_VLAN_FIELD
#endif

#ifndef NEED_VLAN_FIELD
static inline void vlan_copy_skb_tci(struct sk_buff *skb) { }

static inline u16 vlan_get_tci(struct sk_buff *skb)
{
	return skb->vlan_tci;
}

static inline void vlan_set_tci(struct sk_buff *skb, u16 vlan_tci)
{
	skb->vlan_tci = vlan_tci;
}
#else
void vlan_copy_skb_tci(struct sk_buff *skb);
u16 vlan_get_tci(struct sk_buff *skb);
void vlan_set_tci(struct sk_buff *skb, u16 vlan_tci);

#undef vlan_tx_tag_present
bool vlan_tx_tag_present(struct sk_buff *skb);

#undef vlan_tx_tag_get
u16 vlan_tx_tag_get(struct sk_buff *skb);

#define __vlan_hwaccel_put_tag rpl__vlan_hwaccel_put_tag
struct sk_buff *__vlan_hwaccel_put_tag(struct sk_buff *skb, u16 vlan_tci);
#endif /* NEED_VLAN_FIELD */

static inline int vlan_deaccel_tag(struct sk_buff *skb)
{
	if (!vlan_tx_tag_present(skb))
		return 0;

	skb = __vlan_put_tag(skb, vlan_tx_tag_get(skb));
	if (unlikely(!skb))
		return -ENOMEM;

	vlan_set_tci(skb, 0);
	return 0;
}

#endif /* vlan.h */
