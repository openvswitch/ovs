/*
 * Copyright (c) 2009, 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef ACTIONS_H
#define ACTIONS_H 1

#include <linux/skbuff.h>
#include <linux/version.h>

struct datapath;
struct sk_buff;
struct odp_flow_key;
union odp_action;

int execute_actions(struct datapath *dp, struct sk_buff *skb,
		    const struct odp_flow_key *key,
		    const union odp_action *, int n_actions);

#endif /* actions.h */
