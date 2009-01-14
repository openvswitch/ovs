/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008 The Board of Trustees of The Leland 
 * Stanford Junior University
 */

/* Functions for executing OpenFlow actions. */

#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in6.h>
#include <linux/if_vlan.h>
#include <net/checksum.h>
#include "forward.h"
#include "dp_act.h"
#include "openflow/nicira-ext.h"
#include "nx_act.h"


static uint16_t
validate_output(struct datapath *dp, const struct sw_flow_key *key, 
		const struct ofp_action_header *ah) 
{
	struct ofp_action_output *oa = (struct ofp_action_output *)ah;

	if (oa->port == htons(OFPP_NONE) || 
			(!(key->wildcards & OFPFW_IN_PORT) && oa->port == key->in_port)) 
		return OFPBAC_BAD_OUT_PORT;

	return ACT_VALIDATION_OK;
}

static int 
do_output(struct datapath *dp, struct sk_buff *skb, size_t max_len,
		int out_port, int ignore_no_fwd)
{
	if (!skb)
		return -ENOMEM;
	return (likely(out_port != OFPP_CONTROLLER)
		? dp_output_port(dp, skb, out_port, ignore_no_fwd)
		: dp_output_control(dp, skb, fwd_save_skb(skb),
					 max_len, OFPR_ACTION));
}


static struct sk_buff *
vlan_pull_tag(struct sk_buff *skb)
{
	struct vlan_ethhdr *vh = vlan_eth_hdr(skb);
	struct ethhdr *eh;


	/* Verify we were given a vlan packet */
	if (vh->h_vlan_proto != htons(ETH_P_8021Q))
		return skb;

	memmove(skb->data + VLAN_HLEN, skb->data, 2 * VLAN_ETH_ALEN);

	eh = (struct ethhdr *)skb_pull(skb, VLAN_HLEN);

	skb->protocol = eh->h_proto;
	skb->mac_header += VLAN_HLEN;

	return skb;
}


static struct sk_buff *
modify_vlan_tci(struct sk_buff *skb, struct sw_flow_key *key, 
		uint16_t tci, uint16_t mask)
{
	struct vlan_ethhdr *vh = vlan_eth_hdr(skb);

	if (key->dl_vlan != htons(OFP_VLAN_NONE)) {
		/* Modify vlan id, but maintain other TCI values */
		vh->h_vlan_TCI = (vh->h_vlan_TCI & ~(htons(mask))) | htons(tci);
	} else  {
		/* Add vlan header */

		/* xxx The vlan_put_tag function, doesn't seem to work
		 * xxx reliably when it attempts to use the hardware-accelerated
		 * xxx version.  We'll directly use the software version
		 * xxx until the problem can be diagnosed.
		 */
		skb = __vlan_put_tag(skb, tci);
		vh = vlan_eth_hdr(skb);
	}
	key->dl_vlan = vh->h_vlan_TCI & htons(VLAN_VID_MASK);

	return skb;
}

static struct sk_buff *
set_vlan_vid(struct sk_buff *skb, struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
	struct ofp_action_vlan_vid *va = (struct ofp_action_vlan_vid *)ah;
	uint16_t tci = ntohs(va->vlan_vid);

	return modify_vlan_tci(skb, key, tci, VLAN_VID_MASK);
}

/* Mask for the priority bits in a vlan header.  The kernel doesn't
 * define this like it does for VID. */
#define VLAN_PCP_MASK 0xe000

static struct sk_buff *
set_vlan_pcp(struct sk_buff *skb, struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
	struct ofp_action_vlan_pcp *va = (struct ofp_action_vlan_pcp *)ah;
	uint16_t tci = (uint16_t)va->vlan_pcp << 13;

	return modify_vlan_tci(skb, key, tci, VLAN_PCP_MASK);
}

static struct sk_buff *
strip_vlan(struct sk_buff *skb, struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
	vlan_pull_tag(skb);
	key->dl_vlan = htons(OFP_VLAN_NONE);

	return skb;
}

static struct sk_buff *
set_dl_addr(struct sk_buff *skb, struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
	struct ofp_action_dl_addr *da = (struct ofp_action_dl_addr *)ah;
	struct ethhdr *eh = eth_hdr(skb);

	if (da->type == htons(OFPAT_SET_DL_SRC))
		memcpy(eh->h_source, da->dl_addr, sizeof eh->h_source);
	else 
		memcpy(eh->h_dest, da->dl_addr, sizeof eh->h_dest);

	return skb;
}

/* Updates 'sum', which is a field in 'skb''s data, given that a 4-byte field
 * covered by the sum has been changed from 'from' to 'to'.  If set,
 * 'pseudohdr' indicates that the field is in the TCP or UDP pseudo-header.
 * Based on nf_proto_csum_replace4. */
static void update_csum(__sum16 *sum, struct sk_buff *skb,
			__be32 from, __be32 to, int pseudohdr)
{
	__be32 diff[] = { ~from, to };
	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		*sum = csum_fold(csum_partial((char *)diff, sizeof(diff),
				~csum_unfold(*sum)));
		if (skb->ip_summed == CHECKSUM_COMPLETE && pseudohdr)
			skb->csum = ~csum_partial((char *)diff, sizeof(diff),
						~skb->csum);
	} else if (pseudohdr)
		*sum = ~csum_fold(csum_partial((char *)diff, sizeof(diff),
				csum_unfold(*sum)));
}

static struct sk_buff * 
set_nw_addr(struct sk_buff *skb, struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
	struct ofp_action_nw_addr *na = (struct ofp_action_nw_addr *)ah;
	uint16_t eth_proto = ntohs(key->dl_type);

	if (eth_proto == ETH_P_IP) {
		struct iphdr *nh = ip_hdr(skb);
		uint32_t new, *field;

		new = na->nw_addr;

		if (ah->type == htons(OFPAT_SET_NW_SRC))
			field = &nh->saddr;
		else
			field = &nh->daddr;

		if (key->nw_proto == IPPROTO_TCP) {
			struct tcphdr *th = tcp_hdr(skb);
			update_csum(&th->check, skb, *field, new, 1);
		} else if (key->nw_proto == IPPROTO_UDP) {
			struct udphdr *th = udp_hdr(skb);
			update_csum(&th->check, skb, *field, new, 1);
		}
		update_csum(&nh->check, skb, *field, new, 0);
		*field = new;
	}

	return skb;
}

static struct sk_buff *
set_tp_port(struct sk_buff *skb, struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
	struct ofp_action_tp_port *ta = (struct ofp_action_tp_port *)ah;
	uint16_t eth_proto = ntohs(key->dl_type);

	if (eth_proto == ETH_P_IP) {
		uint16_t new, *field;

		new = ta->tp_port;

		if (key->nw_proto == IPPROTO_TCP) {
			struct tcphdr *th = tcp_hdr(skb);

			if (ah->type == htons(OFPAT_SET_TP_SRC))
				field = &th->source;
			else
				field = &th->dest;

			update_csum(&th->check, skb, *field, new, 1);
			*field = new;
		} else if (key->nw_proto == IPPROTO_UDP) {
			struct udphdr *th = udp_hdr(skb);

			if (ah->type == htons(OFPAT_SET_TP_SRC))
				field = &th->source;
			else
				field = &th->dest;

			update_csum(&th->check, skb, *field, new, 1);
			*field = new;
		}
	}

	return skb;
}

struct openflow_action {
	size_t min_size;
	size_t max_size;
	uint16_t (*validate)(struct datapath *dp, 
			const struct sw_flow_key *key,
			const struct ofp_action_header *ah);
	struct sk_buff *(*execute)(struct sk_buff *skb, 
			struct sw_flow_key *key, 
			const struct ofp_action_header *ah);
};

static const struct openflow_action of_actions[] = {
	[OFPAT_OUTPUT] = {
		sizeof(struct ofp_action_output),
		sizeof(struct ofp_action_output),
		validate_output,
		NULL                   /* This is optimized into execute_actions */
	},
	[OFPAT_SET_VLAN_VID] = {
		sizeof(struct ofp_action_vlan_vid),
		sizeof(struct ofp_action_vlan_vid),
		NULL,
		set_vlan_vid
	},
	[OFPAT_SET_VLAN_PCP] = {
		sizeof(struct ofp_action_vlan_pcp),
		sizeof(struct ofp_action_vlan_pcp),
		NULL,
		set_vlan_pcp
	},
	[OFPAT_STRIP_VLAN] = {
		sizeof(struct ofp_action_header),
		sizeof(struct ofp_action_header),
		NULL,
		strip_vlan
	},
	[OFPAT_SET_DL_SRC] = {
		sizeof(struct ofp_action_dl_addr),
		sizeof(struct ofp_action_dl_addr),
		NULL,
		set_dl_addr
	},
	[OFPAT_SET_DL_DST] = {
		sizeof(struct ofp_action_dl_addr),
		sizeof(struct ofp_action_dl_addr),
		NULL,
		set_dl_addr
	},
	[OFPAT_SET_NW_SRC] = {
		sizeof(struct ofp_action_nw_addr),
		sizeof(struct ofp_action_nw_addr),
		NULL,
		set_nw_addr
	},
	[OFPAT_SET_NW_DST] = {
		sizeof(struct ofp_action_nw_addr),
		sizeof(struct ofp_action_nw_addr),
		NULL,
		set_nw_addr
	},
	[OFPAT_SET_TP_SRC] = {
		sizeof(struct ofp_action_tp_port),
		sizeof(struct ofp_action_tp_port),
		NULL,
		set_tp_port
	},
	[OFPAT_SET_TP_DST] = {
		sizeof(struct ofp_action_tp_port),
		sizeof(struct ofp_action_tp_port),
		NULL,
		set_tp_port
	}
	/* OFPAT_VENDOR is not here, since it would blow up the array size. */
};

/* Validate built-in OpenFlow actions.  Either returns ACT_VALIDATION_OK
 * or an OFPET_BAD_ACTION error code. */
static uint16_t 
validate_ofpat(struct datapath *dp, const struct sw_flow_key *key, 
		const struct ofp_action_header *ah, uint16_t type, uint16_t len)
{
	int ret = ACT_VALIDATION_OK;
	const struct openflow_action *act = &of_actions[type];

	if ((len < act->min_size) || (len > act->max_size)) 
		return OFPBAC_BAD_LEN;

	if (act->validate) 
		ret = act->validate(dp, key, ah);

	return ret;
}

/* Validate vendor-defined actions.  Either returns ACT_VALIDATION_OK
 * or an OFPET_BAD_ACTION error code. */
static uint16_t 
validate_vendor(struct datapath *dp, const struct sw_flow_key *key, 
		const struct ofp_action_header *ah, uint16_t len)
{
	struct ofp_action_vendor_header *avh;
	int ret = ACT_VALIDATION_OK;

	if (len < sizeof(struct ofp_action_vendor_header))
		return OFPBAC_BAD_LEN;

	avh = (struct ofp_action_vendor_header *)ah;

	switch(ntohl(avh->vendor)) {
	case NX_VENDOR_ID: 
		ret = nx_validate_act(dp, key, (struct nx_action_header *)avh, len);
		break;

	default:
		return OFPBAC_BAD_VENDOR;
	}

	return ret;
}

/* Validates a list of actions.  If a problem is found, a code for the
 * OFPET_BAD_ACTION error type is returned.  If the action list validates, 
 * ACT_VALIDATION_OK is returned. */
uint16_t 
validate_actions(struct datapath *dp, const struct sw_flow_key *key,
		const struct ofp_action_header *actions, size_t actions_len)
{
	uint8_t *p = (uint8_t *)actions;
	int err;

	while (actions_len >= sizeof(struct ofp_action_header)) {
		struct ofp_action_header *ah = (struct ofp_action_header *)p;
		size_t len = ntohs(ah->len);
		uint16_t type;

		/* Make there's enough remaining data for the specified length
		 * and that the action length is a multiple of 64 bits. */
		if ((actions_len < len) || (len % 8) != 0)
			return OFPBAC_BAD_LEN;

		type = ntohs(ah->type);
		if (type < ARRAY_SIZE(of_actions)) {
			err = validate_ofpat(dp, key, ah, type, len);
			if (err != ACT_VALIDATION_OK)
				return err;
		} else if (type == OFPAT_VENDOR) {
			err = validate_vendor(dp, key, ah, len);
			if (err != ACT_VALIDATION_OK)
				return err;
		} else 
			return OFPBAC_BAD_TYPE;

		p += len;
		actions_len -= len;
	}

	/* Check if there's any trailing garbage. */
	if (actions_len != 0) 
		return OFPBAC_BAD_LEN;

	return ACT_VALIDATION_OK;
}

/* Execute a built-in OpenFlow action against 'skb'. */
static struct sk_buff *
execute_ofpat(struct sk_buff *skb, struct sw_flow_key *key, 
		const struct ofp_action_header *ah, uint16_t type)
{
	const struct openflow_action *act = &of_actions[type];

	if (act->execute)  {
		if (!make_writable(&skb)) {
			if (net_ratelimit())
				printk("make_writable failed\n");
			return skb;
		}
		skb = act->execute(skb, key, ah);
	}

	return skb;
}

/* Execute a vendor-defined action against 'skb'. */
static struct sk_buff *
execute_vendor(struct sk_buff *skb, const struct sw_flow_key *key, 
		const struct ofp_action_header *ah)
{
	struct ofp_action_vendor_header *avh 
			= (struct ofp_action_vendor_header *)ah;

	/* NB: If changes need to be made to the packet, a call should be
	 * made to make_writable or its equivalent first. */

	switch(ntohl(avh->vendor)) {
	case NX_VENDOR_ID: 
		skb = nx_execute_act(skb, key, (struct nx_action_header *)avh);
		break;

	default:
		/* This should not be possible due to prior validation. */
		if (net_ratelimit())
			printk("attempt to execute action with unknown vendor: %#x\n", 
					ntohl(avh->vendor));
		break;
	}

	return skb;
}

/* Execute a list of actions against 'skb'. */
void execute_actions(struct datapath *dp, struct sk_buff *skb,
		     struct sw_flow_key *key,
		     const struct ofp_action_header *actions, size_t actions_len,
		     int ignore_no_fwd)
{
	/* Every output action needs a separate clone of 'skb', but the common
	 * case is just a single output action, so that doing a clone and
	 * then freeing the original skbuff is wasteful.  So the following code
	 * is slightly obscure just to avoid that. */
	int prev_port;
	size_t max_len=0;	 /* Initialze to make compiler happy */
	uint8_t *p = (uint8_t *)actions;

	prev_port = -1;

	/* The action list was already validated, so we can be a bit looser
	 * in our sanity-checking. */
	while (actions_len > 0) {
		struct ofp_action_header *ah = (struct ofp_action_header *)p;
		size_t len = htons(ah->len);

		WARN_ON_ONCE(skb_shared(skb));
		if (prev_port != -1) {
			do_output(dp, skb_clone(skb, GFP_ATOMIC),
				  max_len, prev_port, ignore_no_fwd);
			prev_port = -1;
		}

		if (likely(ah->type == htons(OFPAT_OUTPUT))) {
			struct ofp_action_output *oa = (struct ofp_action_output *)p;
			prev_port = ntohs(oa->port);
			max_len = ntohs(oa->max_len);
		} else {
			uint16_t type = ntohs(ah->type);

			if (type < ARRAY_SIZE(of_actions)) 
				skb = execute_ofpat(skb, key, ah, type);
			else if (type == OFPAT_VENDOR) 
				skb = execute_vendor(skb, key, ah);

			if (!skb) {
				if (net_ratelimit())
					printk("execute_actions lost skb\n");
				return;
			}
		}

		p += len;
		actions_len -= len;
	}
	if (prev_port != -1)
		do_output(dp, skb, max_len, prev_port, ignore_no_fwd);
	else
		kfree_skb(skb);
}

/* Utility functions. */

/* Makes '*pskb' writable, possibly copying it and setting '*pskb' to point to
 * the copy.
 * Returns 1 if successful, 0 on failure. */
int
make_writable(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	if (skb_shared(skb) || skb_cloned(skb)) {
		struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);
		if (!nskb)
			return 0;
		kfree_skb(skb);
		*pskb = nskb;
		return 1;
	} else {
		unsigned int hdr_len = (skb_transport_offset(skb)
					+ sizeof(struct tcphdr));
		return pskb_may_pull(skb, min(hdr_len, skb->len));
	}
}
