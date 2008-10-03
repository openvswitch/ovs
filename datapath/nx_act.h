#ifndef NX_ACT_H
#define NX_ACT_H 1

#include "datapath.h"


uint16_t nx_validate_act(struct datapath *dp, const struct sw_flow_key *key,
		const struct ofp_action_vendor_header *avh, uint16_t len);

struct sk_buff *nx_execute_act(struct sk_buff *skb, 
		const struct sw_flow_key *key,
		const struct ofp_action_vendor_header *avh);

#endif /* nx_act.h */
