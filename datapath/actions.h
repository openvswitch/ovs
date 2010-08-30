/*
 * Copyright (c) 2009, 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef ACTIONS_H
#define ACTIONS_H 1

#include <linux/gfp.h>
#include <linux/skbuff.h>
#include <linux/version.h>

struct datapath;
struct sk_buff;
struct odp_flow_key;
union odp_action;

int execute_actions(struct datapath *dp, struct sk_buff *skb,
		    const struct odp_flow_key *key,
		    const union odp_action *, int n_actions,
		    gfp_t gfp);

static inline void set_skb_csum_bits(const struct sk_buff *old_skb,
				     struct sk_buff *new_skb)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	/* Before 2.6.24 these fields were not copied when
	 * doing an skb_copy_expand. */
	new_skb->ip_summed = old_skb->ip_summed;
	new_skb->csum = old_skb->csum;
#endif
#if defined(CONFIG_XEN) && defined(HAVE_PROTO_DATA_VALID)
	/* These fields are copied in skb_clone but not in
	 * skb_copy or related functions.  We need to manually
	 * copy them over here. */
	new_skb->proto_data_valid = old_skb->proto_data_valid;
	new_skb->proto_csum_blank = old_skb->proto_csum_blank;
#endif
}

#endif /* actions.h */
