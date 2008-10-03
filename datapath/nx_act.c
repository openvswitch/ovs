/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008 The Board of Trustees of The Leland 
 * Stanford Junior University
 */

/* Functions for Nicira-extended actions. */
#include "nicira-ext.h"
#include "nx_act.h"

uint16_t
nx_validate_act(struct datapath *dp, const struct sw_flow_key *key,
		const struct ofp_action_vendor_header *avh, uint16_t len)
{
	/* Nothing to validate yet */
	return OFPBAC_BAD_VENDOR_TYPE;
}

struct sk_buff *
nx_execute_act(struct sk_buff *skb, const struct sw_flow_key *key,
		const struct ofp_action_vendor_header *avh)
{
	/* Nothing to execute yet */
	return skb;
}

