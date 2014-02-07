#ifndef __LINUX_GSO_WRAPPER_H
#define __LINUX_GSO_WRAPPER_H

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)

#include <linux/skbuff.h>
#include <net/protocol.h>

#include "datapath.h"

struct ovs_gso_cb {
	struct ovs_skb_cb dp_cb;
	sk_buff_data_t	inner_network_header;
	sk_buff_data_t	inner_mac_header;
	void (*fix_segment)(struct sk_buff *);
};
#define OVS_GSO_CB(skb) ((struct ovs_gso_cb *)(skb)->cb)

#define skb_inner_network_header rpl_skb_inner_network_header

#ifdef NET_SKBUFF_DATA_USES_OFFSET
#define skb_inner_network_header rpl_skb_inner_network_header
static inline unsigned char *skb_inner_network_header(const struct sk_buff *skb)
{
	return skb->head + OVS_GSO_CB(skb)->inner_network_header;
}

#define skb_inner_mac_header rpl_skb_inner_mac_header
static inline unsigned char *skb_inner_mac_header(const struct sk_buff *skb)
{
	return skb->head + OVS_GSO_CB(skb)->inner_mac_header;
}

#else

#define skb_inner_network_header rpl_skb_inner_network_header
static inline unsigned char *skb_inner_network_header(const struct sk_buff *skb)
{
	return OVS_GSO_CB(skb)->inner_network_header;
}

#define skb_inner_mac_header rpl_skb_inner_mac_header
static inline unsigned char *skb_inner_mac_header(const struct sk_buff *skb)
{
	return OVS_GSO_CB(skb)->inner_mac_header;
}

#endif

#define skb_inner_network_offset rpl_skb_inner_network_offset
static inline int skb_inner_network_offset(const struct sk_buff *skb)
{
	return skb_inner_network_header(skb) - skb->data;
}

#define skb_inner_mac_offset rpl_skb_inner_mac_offset
static inline int skb_inner_mac_offset(const struct sk_buff *skb)
{
	return skb_inner_mac_header(skb) - skb->data;
}

#define skb_reset_inner_headers rpl_skb_reset_inner_headers
static inline void skb_reset_inner_headers(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct ovs_gso_cb) > FIELD_SIZEOF(struct sk_buff, cb));
	OVS_GSO_CB(skb)->inner_network_header = skb->network_header;
	OVS_GSO_CB(skb)->inner_mac_header = skb->mac_header;

	OVS_GSO_CB(skb)->fix_segment = NULL;
}

#define ip_local_out rpl_ip_local_out
int ip_local_out(struct sk_buff *skb);

#endif /* 3.12 */
#endif
