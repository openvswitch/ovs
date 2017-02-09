#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <net/mpls.h>

#include "gso.h"

#ifdef OVS_USE_COMPAT_GSO_SEGMENTATION
struct sk_buff *rpl__skb_gso_segment(struct sk_buff *skb,
				    netdev_features_t features,
				    bool tx_path)
{
	int vlan_depth = ETH_HLEN;
	__be16 type = skb->protocol;
	__be16 skb_proto;
	struct sk_buff *skb_gso;

	while (type == htons(ETH_P_8021Q)) {
		struct vlan_hdr *vh;

		if (unlikely(!pskb_may_pull(skb, vlan_depth + VLAN_HLEN)))
			return ERR_PTR(-EINVAL);

		vh = (struct vlan_hdr *)(skb->data + vlan_depth);
		type = vh->h_vlan_encapsulated_proto;
		vlan_depth += VLAN_HLEN;
	}

	if (eth_p_mpls(type))
		type = ovs_skb_get_inner_protocol(skb);

	/* this hack needed to get regular skb_gso_segment() */
	skb_proto = skb->protocol;
	skb->protocol = type;

#ifdef HAVE___SKB_GSO_SEGMENT
#undef __skb_gso_segment
	skb_gso = __skb_gso_segment(skb, features, tx_path);
#else
#undef skb_gso_segment
	skb_gso = skb_gso_segment(skb, features);
#endif

	skb->protocol = skb_proto;
	return skb_gso;
}
EXPORT_SYMBOL_GPL(rpl__skb_gso_segment);

#endif	/* OVS_USE_COMPAT_GSO_SEGMENTATION */

#ifdef HAVE_UDP_OFFLOAD
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
struct sk_buff **rpl_eth_gro_receive(struct sk_buff **head,
				 struct sk_buff *skb)
{
	struct sk_buff *p, **pp = NULL;
	struct ethhdr *eh, *eh2;
	unsigned int hlen, off_eth;
	const struct packet_offload *ptype;
	__be16 type;
	int flush = 1;

	off_eth = skb_gro_offset(skb);
	hlen = off_eth + sizeof(*eh);
	eh = skb_gro_header_fast(skb, off_eth);
	if (skb_gro_header_hard(skb, hlen)) {
		eh = skb_gro_header_slow(skb, hlen, off_eth);
		if (unlikely(!eh))
			goto out;
	}

	flush = 0;

	for (p = *head; p; p = p->next) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		eh2 = (struct ethhdr *)(p->data + off_eth);
		if (compare_ether_header(eh, eh2)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}
	}

	type = eh->h_proto;

	rcu_read_lock();
	ptype = gro_find_receive_by_type(type);
	if (ptype == NULL) {
		flush = 1;
		goto out_unlock;
	}

	skb_gro_pull(skb, sizeof(*eh));
	skb_gro_postpull_rcsum(skb, eh, sizeof(*eh));
	pp = ptype->callbacks.gro_receive(head, skb);

out_unlock:
	rcu_read_unlock();
out:
	NAPI_GRO_CB(skb)->flush |= flush;

	return pp;
}

int rpl_eth_gro_complete(struct sk_buff *skb, int nhoff)
{
	struct ethhdr *eh = (struct ethhdr *)(skb->data + nhoff);
	__be16 type = eh->h_proto;
	struct packet_offload *ptype;
	int err = -ENOSYS;

	if (skb->encapsulation)
		skb_set_inner_mac_header(skb, nhoff);

	rcu_read_lock();
	ptype = gro_find_complete_by_type(type);
	if (ptype != NULL)
		err = ptype->callbacks.gro_complete(skb, nhoff +
						    sizeof(struct ethhdr));

	rcu_read_unlock();
	return err;
}

#endif
#endif /* HAVE_UDP_OFFLOAD */

#ifndef HAVE_RTNL_LINK_STATS64
#undef dev_get_stats
struct rtnl_link_stats64 *rpl_dev_get_stats(struct net_device *dev,
					struct rtnl_link_stats64 *storage)
{
	const struct net_device_stats *stats = dev_get_stats(dev);

#define copy(s)	storage->s = stats->s

	copy(rx_packets);
	copy(tx_packets);
	copy(rx_bytes);
	copy(tx_bytes);
	copy(rx_errors);
	copy(tx_errors);
	copy(rx_dropped);
	copy(tx_dropped);
	copy(multicast);
	copy(collisions);

	copy(rx_length_errors);
	copy(rx_over_errors);
	copy(rx_crc_errors);
	copy(rx_frame_errors);
	copy(rx_fifo_errors);
	copy(rx_missed_errors);

	copy(tx_aborted_errors);
	copy(tx_carrier_errors);
	copy(tx_fifo_errors);
	copy(tx_heartbeat_errors);
	copy(tx_window_errors);

	copy(rx_compressed);
	copy(tx_compressed);

#undef copy
	return storage;
}
#endif
