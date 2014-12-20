#ifndef __LINUX_GSO_WRAPPER_H
#define __LINUX_GSO_WRAPPER_H

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/protocol.h>

#include "datapath.h"
typedef void (*gso_fix_segment_t)(struct sk_buff *);

struct ovs_gso_cb {
	struct ovs_skb_cb dp_cb;
	gso_fix_segment_t fix_segment;
	sk_buff_data_t	inner_mac_header;	/* Offset from skb->head */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
	__be16		inner_protocol;
#endif
	u16		inner_network_header;	/* Offset from
						 * inner_mac_header */
};
#define OVS_GSO_CB(skb) ((struct ovs_gso_cb *)(skb)->cb)

#define skb_inner_network_header rpl_skb_inner_network_header

#ifdef NET_SKBUFF_DATA_USES_OFFSET
#define skb_inner_mac_header rpl_skb_inner_mac_header
static inline unsigned char *skb_inner_mac_header(const struct sk_buff *skb)
{
	return skb->head + OVS_GSO_CB(skb)->inner_mac_header;
}

#else

#define skb_inner_mac_header rpl_skb_inner_mac_header
static inline unsigned char *skb_inner_mac_header(const struct sk_buff *skb)
{
	return OVS_GSO_CB(skb)->inner_mac_header;
}

#endif

#define skb_inner_network_header rpl_skb_inner_network_header
static inline unsigned char *skb_inner_network_header(const struct sk_buff *skb)
{
	return skb_inner_mac_header(skb) +
		OVS_GSO_CB(skb)->inner_network_header;
}

#define skb_inner_network_offset rpl_skb_inner_network_offset
static inline int skb_inner_network_offset(const struct sk_buff *skb)
{
	return skb_inner_network_header(skb) - skb->data;
}

#define skb_reset_inner_headers rpl_skb_reset_inner_headers
static inline void skb_reset_inner_headers(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct ovs_gso_cb) > FIELD_SIZEOF(struct sk_buff, cb));
	OVS_GSO_CB(skb)->inner_network_header = skb->network_header -
		skb->mac_header;
	OVS_GSO_CB(skb)->inner_mac_header = skb->mac_header;

	OVS_GSO_CB(skb)->fix_segment = NULL;
}

struct sk_buff *ovs_iptunnel_handle_offloads(struct sk_buff *skb,
                                             bool csum_help,
					     gso_fix_segment_t fix_segment);


#endif /* 3.12 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
#define ip_local_out rpl_ip_local_out
int ip_local_out(struct sk_buff *skb);

#define skb_inner_mac_offset rpl_skb_inner_mac_offset
static inline int skb_inner_mac_offset(const struct sk_buff *skb)
{
	return skb_inner_mac_header(skb) - skb->data;
}
#endif /* 3.16 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
static inline void ovs_skb_init_inner_protocol(struct sk_buff *skb) {
	OVS_GSO_CB(skb)->inner_protocol = htons(0);
}

static inline void ovs_skb_set_inner_protocol(struct sk_buff *skb,
					      __be16 ethertype) {
	OVS_GSO_CB(skb)->inner_protocol = ethertype;
}

static inline __be16 ovs_skb_get_inner_protocol(struct sk_buff *skb)
{
	return OVS_GSO_CB(skb)->inner_protocol;
}

#else

static inline void ovs_skb_init_inner_protocol(struct sk_buff *skb) {
	/* Nothing to do. The inner_protocol is either zero or
	 * has been set to a value by another user.
	 * Either way it may be considered initialised.
	 */
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
static inline void ovs_skb_set_inner_protocol(struct sk_buff *skb,
					      __be16 ethertype)
{
	skb->inner_protocol = ethertype;
}
#else
static inline void ovs_skb_set_inner_protocol(struct sk_buff *skb,
					      __be16 ethertype)
{
	skb_set_inner_protocol(skb, ethertype);
}
#endif

static inline __be16 ovs_skb_get_inner_protocol(struct sk_buff *skb)
{
	return skb->inner_protocol;
}
#endif /* 3.11 */
#endif
