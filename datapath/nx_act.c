/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2008 Nicira Networks
 */

/* Functions for Nicira-extended actions. */
#include "openflow/nicira-ext.h"
#include "dp_act.h"
#include "nx_act.h"
#include "nx_act_snat.h"

uint16_t
nx_validate_act(struct datapath *dp, const struct sw_flow_key *key,
		const struct nx_action_header *nah, uint16_t len)
{
	if (len < sizeof *nah) 
		return OFPBAC_BAD_LEN;

#ifdef SUPPORT_SNAT
	if (nah->subtype == ntohs(NXAST_SNAT)) {
		struct nx_action_snat *nas = (struct nx_action_snat *)nah;
		if (len != sizeof(*nas))
			return OFPBAC_BAD_LEN;
		else if (ntohs(nas->port) >= OFPP_MAX)
			return OFPBAC_BAD_ARGUMENT;

		return ACT_VALIDATION_OK;
	}
#endif
	return OFPBAC_BAD_VENDOR_TYPE;
}

struct sk_buff *
nx_execute_act(struct sk_buff *skb, const struct sw_flow_key *key,
		const struct nx_action_header *nah)
{
#ifdef SUPPORT_SNAT
	if (nah->subtype == ntohs(NXAST_SNAT)) {
		struct nx_action_snat *nas = (struct nx_action_snat *)nah;
		snat_skb(skb->dev->br_port->dp, skb, ntohs(nas->port));
	}
#endif

	return skb;
}

