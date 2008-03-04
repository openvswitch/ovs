/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007 The Board of Trustees of The Leland Stanford Junior Univer
sity
 */

#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/random.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "forward.h"
#include "tests/forward_t.h"
#include "openflow.h"
#include "unit.h"
#include "flow.h"

/*
 * Tests execute_settings() in forward.c to check that actions are
 * appropriately taken on packets, meaning:
 *
 * 1. Checksums are correct.
 * 2. Actions are only taken on compatible packets (IP action not taken on
 * non-IP packet)
 * 3. Other packet data remains untouched.

 * forward_t.h contains static packet definitions.  forward_t.h should be
 * generated using gen_forward_t.c.  This test is run on whatever packets are
 * defined in forward_t.h.
 *
 * NOTE:  Tests assume packets in forward_t.h are present in full and IP and
 * transport checksums are correct. (Can prevent offloading of checksum
 * computation using ethtool.
 */

/*
 * Sets 'a->data'.  If 'key' != NULL, sets 'data' to equal 'key's value for type
 * specified by 'a->type'.  If 'key' == NULL, sets data to a random value.
 */

static void
set_action_data(struct sk_buff *skb, struct sw_flow_key *key, struct ofp_action *a)
{
	if (key != NULL) {
		switch(a->type) {
		case(OFPAT_SET_DL_SRC):
			memcpy(a->arg.dl_addr, key->dl_src, sizeof key->dl_src);
			break;
		case(OFPAT_SET_DL_DST):
			memcpy(a->arg.dl_addr, key->dl_dst, sizeof key->dl_dst);
			break;
		case(OFPAT_SET_NW_SRC):
			if (key->dl_type == htons(ETH_P_IP))
				a->arg.nw_addr = key->nw_src;
			else
				a->arg.nw_addr = random32();
			break;
		case(OFPAT_SET_NW_DST):
			if (key->dl_type == htons(ETH_P_IP))
				a->arg.nw_addr = key->nw_dst;
			else
				a->arg.nw_addr = random32();
			break;
		case(OFPAT_SET_TP_SRC):
			if (key->nw_proto == IPPROTO_TCP || key->nw_proto == IPPROTO_UDP)
				a->arg.tp = key->tp_src;
			else
				a->arg.tp = (uint16_t) random32();
			break;
		case(OFPAT_SET_TP_DST):
			if (key->nw_proto == IPPROTO_TCP || key->nw_proto == IPPROTO_UDP)
				a->arg.tp = key->tp_dst;
			else
				a->arg.tp = (uint16_t) random32();
			break;
		default:
			BUG();
		}
	} else {
		((uint32_t*)a->arg.dl_addr)[0] = random32();
		((uint16_t*)a->arg.dl_addr)[2] = random32();
	}
}


/*
 * Checks the IP sum of an IP packet.  Returns 0 if correct, else -1.
 */

static void
check_IP_csum(struct iphdr *ih)
{
	uint16_t check, *data;
	uint32_t n_bytes, sum;

	check = ih->check;
	ih->check = 0;
	data = (uint16_t*) ih;
	sum = 0;
	n_bytes = ih->ihl * 4;

	while (n_bytes > 1) {
		sum += ntohs(*data);
		sum = (sum >> 16) + (uint16_t)sum;
		data++;
		n_bytes -= 2;
	}

	if (n_bytes == 1) {
		sum += *(uint8_t*)data;
		sum = (sum >> 16) + (uint16_t)sum;
	}

	ih->check = htons((uint16_t)(~sum));
	if (ih->check != check) {
		unit_fail("IP checksum %hu does not match %hu",
			  ntohs(ih->check), ntohs(check));
	}
}

/*
 * Partially computes TCP checksum over 'n_bytes' pointed to by 'data'.  Can be
 * called multiple times if data csum is to be computed on is fragmented.  If
 * 'is_last' == 0, assumes will be called again on more data and returns the
 * value that should be passed in as 'incr_sum' on the next call.  Else if
 * 'is_last' == 1, returns the final checksum.  On the first call, 'incr_sum'
 * should equal 0.  If 'is_last' == 0, 'n_bytes' must be even.  i.e. Should
 * first be called on pseudo header fields that are multiples of two, and then
 * on the TCP packet.
 */
static uint32_t
compute_transport_checksum(uint16_t *data, uint32_t n_bytes,
			uint32_t incr_sum, uint8_t is_last)
{
	uint8_t arr[2];

	if (n_bytes % 2 != 0 && is_last == 0)
		BUG();

	while (n_bytes > 1) {
		incr_sum += ntohs(*data);
		incr_sum = (incr_sum >> 16) + (uint16_t)incr_sum;
		data++;
		n_bytes -= 2;
	}

	if (is_last == 0)
		return incr_sum;

	if(n_bytes == 1) {
		arr[0] = *(uint8_t*)data;
		arr[1] = 0;
		incr_sum += ntohs(*((uint16_t*)arr));
		incr_sum = (incr_sum >> 16) + (uint16_t)incr_sum;
	}

	return ~incr_sum;
}

/*
 * Checks the transport layer's checksum of a packet.  Returns '0' if correct,
 * else '1'.  'ih' should point to the IP header of the packet, if TCP, 'th'
 * should point the TCP header, and if UDP, 'uh' should point to the UDP
 * header.
 */
static int
check_transport_csum(struct iphdr *ih, struct tcphdr *th,
			 struct udphdr *uh)
{
	uint32_t tmp;
	uint16_t len, check;
	uint8_t arr[2];

	tmp = compute_transport_checksum((uint16_t*)(&ih->saddr),
					 2 * sizeof ih->saddr, 0, 0);
	arr[0] = 0;
	arr[1] = ih->protocol;
	tmp = compute_transport_checksum((uint16_t*)arr, 2, tmp, 0);
	len = ntohs(ih->tot_len) - (ih->ihl * 4);
	*((uint16_t*)arr) = htons(len);
	tmp = compute_transport_checksum((uint16_t*)arr, 2, tmp, 0);

	if (th != NULL) {
		check = th->check;
		th->check = 0;
		th->check = htons((uint16_t)compute_transport_checksum((uint16_t*)th,
									len, tmp, 1));
		if (th->check != check) {
			unit_fail("TCP checksum %hu does not match %hu",
				  ntohs(th->check), ntohs(check));
			return -1;
		}
	} else if (uh != NULL) {
		check = uh->check;
		uh->check = 0;
		uh->check = htons((uint16_t)compute_transport_checksum((uint16_t*)uh,
									len, tmp, 1));
		if (uh->check != check) {
			unit_fail("UDP checksum %hu does not match %hu",
				  ntohs(uh->check), ntohs(check));
			return -1;
		}
	}

	return 0;
}


/*
 * Compares 'pkt_len' bytes of 'data' to 'pkt'.  excl_start and excl_end point
 * together delineate areas of 'data' that are not supposed to match 'pkt'.
 * 'num_excl' specify how many such areas exist.  An 'excl_start' entry is
 * ignored if it equals NULL.  See 'check_packet()' for usage.
 */

static void
compare(uint8_t *data, uint8_t *pkt, uint32_t pkt_len,
	uint8_t **excl_start, uint8_t **excl_end, uint32_t num_excl)
{
	uint32_t i;
	uint8_t *d, *p, *end;
	int ret;

	end = data + pkt_len;
	d = data;
	p = pkt;
	ret = 0;

	for (i = 0; i < num_excl; i++) {
		if(*excl_start != NULL) {
			if ((ret = memcmp(d, p, *excl_start - d)) != 0)
				break;
			p += (*excl_end - d);
			d = *excl_end;
		}
		excl_start++;
		excl_end++;
	}

	if (ret == 0)
		ret = memcmp(d, p, end - d);

	if (ret != 0) {
		unit_fail("skb and packet comparison failed:");
		for (i = 0; i < pkt_len; i++) {
			if (data[i] != pkt[i]) {
				unit_fail("skb[%u] = 0x%x != 0x%x",
					  i, data[i], pkt[i]);
			}
		}
	}
}


/*
 * Checks that a packet's data has remained consistent after an action has been
 * applied.  'skb' is the modified packet, 'a' is the action that was taken on
 * the packet, 'p' is a copy of the packet's data before action 'a' was taken.
 * Checks that the action was in fact taken, that the checksums of the packet
 * are correct, and that no other data in the packet was altered.
 */

static void
check_packet(struct sk_buff *skb, struct ofp_action *a, struct pkt *p)
{
	struct ethhdr *eh;
	struct iphdr *ih;
	struct tcphdr *th;
	struct udphdr *uh;
	uint8_t *excl_start[5], *excl_end[5];

	eh = eth_hdr(skb);
	ih = NULL;
	th = NULL;
	uh = NULL;

	memset(excl_start, 0, sizeof excl_start);
	memset(excl_end, 0, sizeof excl_end);

	if (eh->h_proto == htons(ETH_P_IP)) {
		ih = ip_hdr(skb);
		excl_start[1] = (uint8_t*)&ih->check;
		excl_end[1] = (uint8_t*)(&ih->check + 1);
		if (ih->protocol == IPPROTO_TCP) {
			th = tcp_hdr(skb);
			excl_start[4] = (uint8_t*)&th->check;
			excl_end[4] = (uint8_t*)(&th->check + 1);
		} else if (ih->protocol == IPPROTO_UDP) {
			uh = udp_hdr(skb);
			excl_start[4] = (uint8_t*)&uh->check;
			excl_end[4] = (uint8_t*)(&uh->check + 1);
		}
	}

	if (a != NULL) {
		switch(a->type) {
		case(OFPAT_SET_DL_SRC):
			if (memcmp(a->arg.dl_addr, eh->h_source, sizeof eh->h_source) != 0) {
				unit_fail("Source eth addr has not been set");
				return;
			}
			excl_start[0] = (uint8_t*)(&eh->h_source);
			excl_end[0] = (uint8_t*)(&eh->h_proto);
			break;
		case(OFPAT_SET_DL_DST):
			if (memcmp(a->arg.dl_addr, eh->h_dest, sizeof eh->h_dest) != 0) {
				unit_fail("Dest eth addr has not been set");
				return;
			}
			excl_start[0] = (uint8_t*)(&eh->h_dest);
			excl_end[0] = (uint8_t*)(&eh->h_source);
			break;
		case(OFPAT_SET_NW_SRC):
			if (ih != NULL) {
				if (a->arg.nw_addr != ih->saddr) {
					unit_fail("Source IP addr has not been set");
					return;
				}
				excl_start[2] = (uint8_t*)(&ih->saddr);
				excl_end[2] = (uint8_t*)(&ih->saddr + 1);
			}
			break;
		case(OFPAT_SET_NW_DST):
			if (ih != NULL) {
				if (a->arg.nw_addr != ih->daddr) {
					unit_fail("Dest IP addr has not been set");
					return;
				}
				excl_start[2] = (uint8_t*)(&ih->daddr);
				excl_end[2] = (uint8_t*)(&ih->daddr + 1);
			}
			break;
		case(OFPAT_SET_TP_SRC):
			if (th != NULL) {
				if (a->arg.tp != th->source) {
					unit_fail("Source port has not been set");
					return;
				}
				excl_start[3] = (uint8_t*)(&th->source);
				excl_end[3] = (uint8_t*)(&th->source + 1);
			} else if (uh != NULL) {
				if (a->arg.tp != uh->source) {
					unit_fail("Source port has not been set");
					return;
				}
				excl_start[3] = (uint8_t*)(&uh->source);
				excl_end[3] = (uint8_t*)(&uh->source + 1);
			}
			break;
		case(OFPAT_SET_TP_DST):
			if (th != NULL) {
				if (a->arg.tp != th->dest) {
					unit_fail("Dest port has not been set");
					return;
				}
				excl_start[3] = (uint8_t*)(&th->dest);
				excl_end[3] = (uint8_t*)(&th->dest + 1);
			} else if (uh != NULL) {
				if (a->arg.tp != uh->dest) {
					unit_fail("Dest port has not been set");
					return;
				}
				excl_start[3] = (uint8_t*)(&uh->dest);
				excl_end[3] = (uint8_t*)(&uh->dest + 1);
			}
			break;
		default:
			BUG();
		}
	}

	compare(skb->data, p->data, p->len, excl_start, excl_end, 5);
	if (unit_failed())
		return;

	if (ih == NULL)
		return;

	check_IP_csum(ih);
	if (unit_failed())
		return;

	if (th == NULL && uh == NULL)
		return;

	check_transport_csum(ih, th, uh);
}

/*
 * Layers 3 & 4 Tests:  Given packets in forward_t.h, executes all actions 
 * with random data, checking for consistency described in check_packet().
 */

void
test_l3_l4(void)
{
	struct ofp_action action;
	struct sk_buff *skb;
	struct sw_flow_key key;
	unsigned int i, j;
	uint16_t eth_proto;
	int ret = 0;

	for (i = 0; i < num_packets; i++) {
		skb = alloc_skb(packets[i].len, GFP_KERNEL);
		if (!skb) {
			unit_fail("Couldn't allocate %uth skb", i);
			return;
		}

		memcpy(skb_put(skb, packets[i].len), packets[i].data,
					packets[i].len);

		skb_set_mac_header(skb, 0);
		flow_extract(skb, 0, &key);
		eth_proto = ntohs(key.dl_type);

		check_packet(skb, NULL, packets+i);
		if (unit_failed())
			return;

		for (action.type = OFPAT_SET_DL_SRC;
			 action.type <= OFPAT_SET_TP_DST;
			 action.type++)
		{
			set_action_data(skb, NULL, &action);
			for(j = 0; j < 2; j++) {
				skb = execute_setter(skb, eth_proto, &key, &action);
				check_packet(skb, &action, packets+i);
				if (unit_failed()) {
					unit_fail("Packet %u inconsistent "
						  "after setter on action "
						  "type %d, iteration %u",
						  i, action.type, j);
					return;
				}
				set_action_data(skb, &key, &action);
			}
		}

		kfree_skb(skb);

		if (ret != 0)
			break;
	}
}

int
test_vlan(void)
{
	struct ofp_action action;
	struct sk_buff *skb;
	struct sw_flow_key key;
	unsigned int i;
	uint16_t eth_proto;
	int ret = 0;
	struct vlan_ethhdr *vh;
	struct ethhdr *eh;
	struct net_device dev;
	uint16_t new_id, orig_id;


	memset((char *)&dev, '\0', sizeof(dev));

	printk("Testing vlan\n");
	for (i = 0; i < num_packets; i++) {
		skb = alloc_skb(packets[i].len, GFP_KERNEL);
		if (!skb) {
			unit_fail("Couldn't allocate %uth skb", i);
			return -ENOMEM;
		}

		memcpy(skb_put(skb, packets[i].len), packets[i].data,
					packets[i].len);
		skb->dev = &dev;

		skb_set_mac_header(skb, 0);
		flow_extract(skb, 0, &key);
		eth_proto = ntohs(key.dl_type);

#if 0
		if ((ret = check_packet(skb, NULL, packets+i)) < 0) {
			unit_fail("Packet %u has incorrect checksum unmodified",
					i);
			goto free_skb;
		}
#endif

		eh = eth_hdr(skb);
		orig_id = eh->h_proto;

		action.type = OFPAT_SET_DL_VLAN;

		// Add a random vlan tag
		new_id = (uint16_t) random32() & VLAN_VID_MASK;
		action.arg.vlan_id = new_id;
		skb = execute_setter(skb, eth_proto, &key, &action);
		vh = vlan_eth_hdr(skb);
		if (ntohs(vh->h_vlan_TCI) != new_id) {
			unit_fail("add: vlan id doesn't match: %#x != %#x", 
					ntohs(vh->h_vlan_TCI), new_id);
			return -1;
		}
		flow_extract(skb, 0, &key);
#if 0
		if ((ret = check_packet(skb, NULL, packets+i)) < 0) {
			unit_fail("Packet %u has incorrect checksum after adding vlan",
				  i);
			goto free_skb;
		}
#endif

		// Modify the tag
		new_id = (uint16_t) random32() & VLAN_VID_MASK;
		action.arg.vlan_id = new_id;
		skb = execute_setter(skb, eth_proto, &key, &action);
		vh = vlan_eth_hdr(skb);
		if (ntohs(vh->h_vlan_TCI) != new_id) {
			unit_fail("mod: vlan id doesn't match: %#x != %#x", 
					ntohs(vh->h_vlan_TCI), new_id);
			return -1;
		}
		flow_extract(skb, 0, &key);
#if 0
		if ((ret = check_packet(skb, NULL, packets+i)) < 0) {
			unit_fail("Packet %u has incorrect checksum after modifying vlan",
				  i);
			goto free_skb;
		}
#endif

		// Remove the tag
		action.arg.vlan_id = OFP_VLAN_NONE;
		skb = execute_setter(skb, eth_proto, &key, &action);

		eh = eth_hdr(skb);

		if (eh->h_proto != orig_id) {
			unit_fail("del: vlan id doesn't match: %#x != %#x", 
			  ntohs(eh->h_proto), ntohs(orig_id));
			return -1;
		}
#if 0
		if ((ret = check_packet(skb, NULL, packets+i)) < 0) {
			unit_fail("Packet %u has incorrect checksum after removing vlan",
				  i);
			goto free_skb;
		}

	free_skb:
#endif

		kfree_skb(skb);

		if (ret != 0)
			break;
	}

	if (ret == 0)
		printk("\nVLAN actions test passed.\n");

	return ret;


}

/*
 * Actual test:  Given packets in forward_t.h, executes all actions with random
 * data, checking for consistency described in check_packet().
 */

void
run_forward_t(void)
{
	test_vlan();
	test_l3_l4();
}
