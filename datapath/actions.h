/*
 * Copyright (c) 2009 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef ACTIONS_H
#define ACTIONS_H 1

#include <linux/gfp.h>

struct datapath;
struct sk_buff;
struct odp_flow_key;
union odp_action;

int dp_xmit_skb(struct sk_buff *);
int execute_actions(struct datapath *dp, struct sk_buff *skb,
		    struct odp_flow_key *key,
		    const union odp_action *, int n_actions,
		    gfp_t gfp);

#endif /* actions.h */
