#ifndef __LINUX_GSO_WRAPPER_H
#define __LINUX_GSO_WRAPPER_H

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/protocol.h>

#include "datapath.h"
typedef void (*gso_fix_segment_t)(struct sk_buff *);

struct ovs_gso_cb {
	struct ovs_skb_cb dp_cb;
	gso_fix_segment_t fix_segment;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
	__be16		inner_protocol;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	unsigned int	inner_mac_header;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
	unsigned int	inner_network_header;
#endif
};
#define OVS_GSO_CB(skb) ((struct ovs_gso_cb *)(skb)->cb)

static inline void skb_clear_ovs_gso_cb(struct sk_buff *skb)
{
	OVS_GSO_CB(skb)->fix_segment = NULL;
}
#else
static inline void skb_clear_ovs_gso_cb(struct sk_buff *skb)
{

}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static inline unsigned char *skb_inner_mac_header(const struct sk_buff *skb)
{
	return skb->head + OVS_GSO_CB(skb)->inner_mac_header;
}

static inline void skb_set_inner_mac_header(const struct sk_buff *skb,
					    int offset)
{
	OVS_GSO_CB(skb)->inner_mac_header = (skb->data - skb->head) + offset;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
static inline unsigned char *skb_inner_network_header(const struct sk_buff *skb)
{
	return skb->head + OVS_GSO_CB(skb)->inner_network_header;
}

static inline int skb_inner_network_offset(const struct sk_buff *skb)
{
	return skb_inner_network_header(skb) - skb->data;
}

/* We don't actually store the transport offset on backports because
 * we don't use it anywhere. Slightly rename this version to avoid
 * future users from picking it up accidentially.
 */
static inline int ovs_skb_inner_transport_offset(const struct sk_buff *skb)
{
	return 0;
}

static inline void skb_set_inner_network_header(const struct sk_buff *skb,
						int offset)
{
	OVS_GSO_CB(skb)->inner_network_header = (skb->data - skb->head)
						+ offset;
}

static inline void skb_set_inner_transport_header(const struct sk_buff *skb,
						  int offset)
{ }

#else

static inline int ovs_skb_inner_transport_offset(const struct sk_buff *skb)
{
	return skb_inner_transport_header(skb) - skb->data;
}

#endif

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
#define ip_local_out rpl_ip_local_out
int rpl_ip_local_out(struct sk_buff *skb);

static inline int skb_inner_mac_offset(const struct sk_buff *skb)
{
	return skb_inner_mac_header(skb) - skb->data;
}

#define skb_reset_inner_headers rpl_skb_reset_inner_headers
static inline void skb_reset_inner_headers(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct ovs_gso_cb) > FIELD_SIZEOF(struct sk_buff, cb));
	skb_set_inner_mac_header(skb, skb_mac_header(skb) - skb->data);
	skb_set_inner_network_header(skb, skb_network_offset(skb));
	skb_set_inner_transport_header(skb, skb_transport_offset(skb));
}
#endif /* 3.18 */

#endif
