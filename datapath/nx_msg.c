/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2008 Nicira Networks
 */

#include "chain.h"
#include "datapath.h"
#include "openflow/nicira-ext.h"
#include "nx_act_snat.h"
#include "nx_msg.h"


int
nx_recv_msg(struct sw_chain *chain, const struct sender *sender,
		const void *msg)
{
	const struct nicira_header *nh = msg;

	switch (ntohl(nh->subtype)) {
#ifdef SUPPORT_SNAT
	case NXT_ACT_SET_CONFIG: {
		const struct nx_act_config *nac = msg;
		if (ntohs(nh->header.length) < sizeof(*nac)) 
			return -EINVAL;

		if (nac->type == htons(NXAST_SNAT))
			return snat_mod_config(chain->dp, nac);
		else
			return -EINVAL;
		break;
	}
#endif

	default:
		dp_send_error_msg(chain->dp, sender, OFPET_BAD_REQUEST,
				  OFPBRC_BAD_SUBTYPE, msg, ntohs(nh->header.length));
		return -EINVAL;
	}

	return -EINVAL;
}
