#ifndef __LINUX_IF_VLAN_WRAPPER_H
#define __LINUX_IF_VLAN_WRAPPER_H 1

#include_next <linux/if_vlan.h>

#ifdef __KERNEL__
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/version.h>

static inline struct vlan_ethhdr *vlan_eth_hdr(const struct sk_buff *skb)
{
	return (struct vlan_ethhdr *)skb_mac_header(skb);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,26)
static inline struct sk_buff *vlan_put_tag(struct sk_buff *skb, unsigned short tag)
{
	struct vlan_ethhdr *veth;

	if (skb_headroom(skb) < VLAN_HLEN) {
		struct sk_buff *sk_tmp = skb;
		skb = skb_realloc_headroom(sk_tmp, VLAN_HLEN);
		kfree_skb(sk_tmp);
		if (!skb) {
			printk(KERN_ERR "vlan: failed to realloc headroom\n");
			return NULL;
		}
	} else {
		skb = skb_unshare(skb, GFP_ATOMIC);
		if (!skb) {
			printk(KERN_ERR "vlan: failed to unshare skbuff\n");
			return NULL;
		}
	}

	veth = (struct vlan_ethhdr *)skb_push(skb, VLAN_HLEN);

	/* Move the mac addresses to the beginning of the new header. */
	memmove(skb->data, skb->data + VLAN_HLEN, 2 * VLAN_ETH_ALEN);

	/* first, the ethernet type */
	veth->h_vlan_proto = htons(ETH_P_8021Q);

	/* now, the tag */
	veth->h_vlan_TCI = htons(tag);

	skb_reset_mac_header(skb);

	return skb;
}

#else

#define vlan_put_tag(x,y) fix_vlan_put_tag((x),(y));

/* For some reason, older versions of vlan_put_tag do not adjust the
 * pointer to the beginning of the MAC header.  We get around that by
 * this hack.  Ugh.  */
static inline struct sk_buff *fix_vlan_put_tag(struct sk_buff *skb, unsigned short tag)
{
	skb = (vlan_put_tag)(skb, tag);
	skb_reset_mac_header(skb);

	return skb;
}
#endif

#endif

#endif
