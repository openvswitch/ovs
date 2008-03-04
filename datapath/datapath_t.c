#include "datapath_t.h"
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/rcupdate.h>

#include "datapath.h"

static struct sk_buff *
gen_sk_buff(struct datapath *dp, uint32_t packet_size)
{
	int in_port;
	struct sk_buff *skb;
	struct ethhdr *eh;
	struct iphdr *ih;
	struct udphdr *uh;

	for (in_port = 0; in_port < OFPP_MAX; in_port++) {
		if (dp->ports[in_port] != NULL)
			break;
	}

	if (in_port == OFPP_MAX) {
		printk("benchmark: no in_port to send packets as\n");
		return NULL;
	}

	skb = alloc_skb(packet_size, GFP_ATOMIC);
	if (!skb) {
		printk("benchmark: cannot allocate skb for benchmark\n");
		return NULL;
	}

	skb_put(skb, packet_size);
	skb_set_mac_header(skb, 0);
	eh = eth_hdr(skb);
	memcpy(eh->h_dest, "\x12\x34\x56\x78\x9a\xbc", ETH_ALEN);
	memcpy(eh->h_source, "\xab\xcd\xef\x12\x34\x56", ETH_ALEN);
	eh->h_proto = htons(ETH_P_IP);
	skb_set_network_header(skb, sizeof(*eh));
	ih = ip_hdr(skb);
	ih->ihl = 5;
	ih->version = IPVERSION;
	ih->tos = 0;
	ih->tot_len = htons(packet_size - sizeof(*eh));
	ih->id = htons(12345);
	ih->frag_off = 0;
	ih->ttl = IPDEFTTL;
	ih->protocol = IPPROTO_UDP;
	ih->check = 0; /* want this to be right?! */
	ih->saddr = 0x12345678;
	ih->daddr = 0x1234abcd;
	skb_set_transport_header(skb, sizeof(*eh) + sizeof(*ih));
	uh = udp_hdr(skb);
	uh->source = htons(1234);
	uh->dest = htons(5678);
	uh->len = htons(packet_size - sizeof(*eh) - sizeof(*ih));
	uh->check = 0;
	if (dp_set_origin(dp, in_port, skb)) {
		printk("benchmark: could not set origin\n");
		kfree_skb(skb);
		return NULL;
	}

	return skb;
}

int
dp_genl_benchmark_nl(struct sk_buff *skb, struct genl_info *info)
{
	struct datapath *dp;
	uint32_t num_packets = 0;
	int i, err = 0;
	struct sk_buff *skb2;

	if (!info->attrs[DP_GENL_A_DP_IDX] || !info->attrs[DP_GENL_A_NPACKETS]
			|| !info->attrs[DP_GENL_A_PSIZE])
		return -EINVAL;

	num_packets = nla_get_u32((info->attrs[DP_GENL_A_NPACKETS]));

	rcu_read_lock();
	dp = dp_get(nla_get_u32((info->attrs[DP_GENL_A_DP_IDX])));
	if (!dp)
		err = -ENOENT;
	else {
		if (num_packets == 0)
			goto benchmark_unlock;

		skb2 = gen_sk_buff(dp, nla_get_u32((info->attrs[DP_GENL_A_PSIZE])));
		if (skb2 == NULL) {
			err = -ENOMEM;
			goto benchmark_unlock;
		}

		for (i = 0; i < num_packets; i++) {
			struct sk_buff *copy = skb_get(skb2);
			if (copy == NULL) {
				printk("benchmark: skb_get failed\n");
				err = -ENOMEM;
				break;
			}
			if ((err = dp_output_control(dp, copy, -1,
						0, OFPR_ACTION)))
			{
				printk("benchmark: output control ret %d on iter %d\n", err, i);
				break;
			}
		}
		kfree_skb(skb2);
	}

benchmark_unlock:
	rcu_read_unlock();
	return err;
}
