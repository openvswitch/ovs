/*
 * Copyright (c) 2007-2011 Nicira, Inc.
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

#ifndef VLAN_H
#define VLAN_H 1

#include <linux/if_vlan.h>
#include <linux/skbuff.h>
#include <linux/version.h>

/**
 * DOC: VLAN tag manipulation.
 *
 * &struct sk_buff handling of VLAN tags has evolved over time:
 *
 * In 2.6.26 and earlier, VLAN tags did not have any generic representation in
 * an skb, other than as a raw 802.1Q header inside the packet data.
 *
 * In 2.6.27 &struct sk_buff added a @vlan_tci member.  Between 2.6.27 and
 * 2.6.32, its value was the raw contents of the 802.1Q TCI field, or zero if
 * no 802.1Q header was present.  This worked OK except for the corner case of
 * an 802.1Q header with an all-0-bits TCI, which could not be represented.
 *
 * In 2.6.33, @vlan_tci semantics changed.  Now, if an 802.1Q header is
 * present, then the VLAN_TAG_PRESENT bit is always set.  This fixes the
 * all-0-bits TCI corner case.
 *
 * For compatibility we emulate the 2.6.33+ behavior on earlier kernel
 * versions.  The client must not access @vlan_tci directly.  Instead, use
 * vlan_get_tci() to read it or vlan_set_tci() to write it, with semantics
 * equivalent to those on 2.6.33+.
 */

static inline u16 vlan_get_tci(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	if (skb->vlan_tci)
		return skb->vlan_tci | VLAN_TAG_PRESENT;
#endif
	return skb->vlan_tci;
}

static inline void vlan_set_tci(struct sk_buff *skb, u16 vlan_tci)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	vlan_tci &= ~VLAN_TAG_PRESENT;
#endif
	skb->vlan_tci = vlan_tci;
}
#endif /* vlan.h */
