#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <net/mpls.h>

#include "gso.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
#ifndef HAVE_CAN_CHECKSUM_PROTOCOL
static bool can_checksum_protocol(netdev_features_t features, __be16 protocol)
{
	return  ((features & NETIF_F_GEN_CSUM) ||
		((features & NETIF_F_V4_CSUM) &&
				protocol == htons(ETH_P_IP)) ||
		((features & NETIF_F_V6_CSUM) &&
				protocol == htons(ETH_P_IPV6)) ||
		((features & NETIF_F_FCOE_CRC) &&
				protocol == htons(ETH_P_FCOE)));
}
#endif

static inline int illegal_highdma(struct net_device *dev, struct sk_buff *skb)
{
#ifdef CONFIG_HIGHMEM
	int i;

	if (dev->features & NETIF_F_HIGHDMA)
		return 0;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
		if (PageHighMem(skb_shinfo(skb)->frags[i].page))
			return 1;

#endif
	return 0;
}

static netdev_features_t harmonize_features(struct sk_buff *skb,
					    __be16 protocol,
					    netdev_features_t features)
{
	if (!can_checksum_protocol(features, protocol)) {
		features &= ~NETIF_F_ALL_CSUM;
		features &= ~NETIF_F_SG;
	} else if (illegal_highdma(skb->dev, skb)) {
		features &= ~NETIF_F_SG;
	}

	return features;
}

netdev_features_t rpl_netif_skb_features(struct sk_buff *skb)
{
	unsigned long vlan_features = skb->dev->vlan_features;

	__be16 protocol = skb->protocol;
	netdev_features_t features = skb->dev->features;

	if (protocol == htons(ETH_P_8021Q)) {
		struct vlan_ethhdr *veh = (struct vlan_ethhdr *)skb->data;
		protocol = veh->h_vlan_encapsulated_proto;
	} else if (!skb_vlan_tag_present(skb)) {
		return harmonize_features(skb, protocol, features);
	}

	features &= (vlan_features | NETIF_F_HW_VLAN_TX);

	if (protocol != htons(ETH_P_8021Q)) {
		return harmonize_features(skb, protocol, features);
	} else {
		features &= NETIF_F_SG | NETIF_F_HIGHDMA | NETIF_F_FRAGLIST |
			NETIF_F_GEN_CSUM | NETIF_F_HW_VLAN_TX;
		return harmonize_features(skb, protocol, features);
	}
}
EXPORT_SYMBOL_GPL(rpl_netif_skb_features);
#endif	/* kernel version < 2.6.38 */

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
