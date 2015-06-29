#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>

#include "gso.h"

#if !defined(HAVE_SKB_WARN_LRO) && defined(NETIF_F_LRO)

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

void __skb_warn_lro_forwarding(const struct sk_buff *skb)
{
	if (net_ratelimit())
		pr_warn("%s: received packets cannot be forwarded while LRO is enabled\n",
			skb->dev->name);
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)

static inline bool head_frag(const struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	return skb->head_frag;
#else
	return false;
#endif
}

 /**
 *	skb_zerocopy_headlen - Calculate headroom needed for skb_zerocopy()
 *	@from: source buffer
 *
 *	Calculates the amount of linear headroom needed in the 'to' skb passed
 *	into skb_zerocopy().
 */
unsigned int
rpl_skb_zerocopy_headlen(const struct sk_buff *from)
{
	unsigned int hlen = 0;

	if (!head_frag(from) ||
	    skb_headlen(from) < L1_CACHE_BYTES ||
	    skb_shinfo(from)->nr_frags >= MAX_SKB_FRAGS)
		hlen = skb_headlen(from);

	if (skb_has_frag_list(from))
		hlen = from->len;

	return hlen;
}
EXPORT_SYMBOL_GPL(rpl_skb_zerocopy_headlen);

#ifndef HAVE_SKB_ZEROCOPY
/**
 *	skb_zerocopy - Zero copy skb to skb
 *	@to: destination buffer
 *	@source: source buffer
 *	@len: number of bytes to copy from source buffer
 *	@hlen: size of linear headroom in destination buffer
 *
 *	Copies up to `len` bytes from `from` to `to` by creating references
 *	to the frags in the source buffer.
 *
 *	The `hlen` as calculated by skb_zerocopy_headlen() specifies the
 *	headroom in the `to` buffer.
 *
 *	Return value:
 *	0: everything is OK
 *	-ENOMEM: couldn't orphan frags of @from due to lack of memory
 *	-EFAULT: skb_copy_bits() found some problem with skb geometry
 */
int
rpl_skb_zerocopy(struct sk_buff *to, struct sk_buff *from, int len, int hlen)
{
	int i, j = 0;
	int plen = 0; /* length of skb->head fragment */
	int ret;
	struct page *page;
	unsigned int offset;

	BUG_ON(!head_frag(from) && !hlen);

	/* dont bother with small payloads */
	if (len <= skb_tailroom(to))
		return skb_copy_bits(from, 0, skb_put(to, len), len);

	if (hlen) {
		ret = skb_copy_bits(from, 0, skb_put(to, hlen), hlen);
		if (unlikely(ret))
			return ret;
		len -= hlen;
	} else {
		plen = min_t(int, skb_headlen(from), len);
		if (plen) {
			page = virt_to_head_page(from->head);
			offset = from->data - (unsigned char *)page_address(page);
			__skb_fill_page_desc(to, 0, page, offset, plen);
			get_page(page);
			j = 1;
			len -= plen;
		}
	}

	to->truesize += len + plen;
	to->len += len + plen;
	to->data_len += len + plen;

	if (unlikely(skb_orphan_frags(from, GFP_ATOMIC))) {
		skb_tx_error(from);
		return -ENOMEM;
	}

	for (i = 0; i < skb_shinfo(from)->nr_frags; i++) {
		if (!len)
			break;
		skb_shinfo(to)->frags[j] = skb_shinfo(from)->frags[i];
		skb_shinfo(to)->frags[j].size = min_t(int, skb_shinfo(to)->frags[j].size, len);
		len -= skb_shinfo(to)->frags[j].size;
		skb_frag_ref(to, j);
		j++;
	}
	skb_shinfo(to)->nr_frags = j;

	return 0;
}
EXPORT_SYMBOL_GPL(rpl_skb_zerocopy);
#endif
#endif

#ifndef HAVE_SKB_ENSURE_WRITABLE
int rpl_skb_ensure_writable(struct sk_buff *skb, int write_len)
{
	if (!pskb_may_pull(skb, write_len))
		return -ENOMEM;

	if (!skb_cloned(skb) || skb_clone_writable(skb, write_len))
		return 0;

	return pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
}
EXPORT_SYMBOL_GPL(rpl_skb_ensure_writable);
#endif

#ifndef HAVE_SKB_VLAN_POP
/* remove VLAN header from packet and update csum accordingly. */
static int __skb_vlan_pop(struct sk_buff *skb, u16 *vlan_tci)
{
	struct vlan_hdr *vhdr;
	unsigned int offset = skb->data - skb_mac_header(skb);
	int err;

	__skb_push(skb, offset);
	err = skb_ensure_writable(skb, VLAN_ETH_HLEN);
	if (unlikely(err))
		goto pull;

	skb_postpull_rcsum(skb, skb->data + (2 * ETH_ALEN), VLAN_HLEN);

	vhdr = (struct vlan_hdr *)(skb->data + ETH_HLEN);
	*vlan_tci = ntohs(vhdr->h_vlan_TCI);

	memmove(skb->data + VLAN_HLEN, skb->data, 2 * ETH_ALEN);
	__skb_pull(skb, VLAN_HLEN);

	vlan_set_encap_proto(skb, vhdr);
	skb->mac_header += VLAN_HLEN;

	if (skb_network_offset(skb) < ETH_HLEN)
		skb_set_network_header(skb, ETH_HLEN);

	skb_reset_mac_len(skb);
pull:
	__skb_pull(skb, offset);

	return err;
}

int rpl_skb_vlan_pop(struct sk_buff *skb)
{
	u16 vlan_tci;
	__be16 vlan_proto;
	int err;

	if (likely(skb_vlan_tag_present(skb))) {
		skb->vlan_tci = 0;
	} else {
		if (unlikely((skb->protocol != htons(ETH_P_8021Q) &&
			      skb->protocol != htons(ETH_P_8021AD)) ||
			     skb->len < VLAN_ETH_HLEN))
			return 0;

		err = __skb_vlan_pop(skb, &vlan_tci);
		if (err)
			return err;
	}
	/* move next vlan tag to hw accel tag */
	if (likely((skb->protocol != htons(ETH_P_8021Q) &&
		    skb->protocol != htons(ETH_P_8021AD)) ||
		   skb->len < VLAN_ETH_HLEN))
		return 0;

	vlan_proto = htons(ETH_P_8021Q);
	err = __skb_vlan_pop(skb, &vlan_tci);
	if (unlikely(err))
		return err;

	__vlan_hwaccel_put_tag(skb, vlan_proto, vlan_tci);
	return 0;
}
EXPORT_SYMBOL_GPL(rpl_skb_vlan_pop);
#endif

#ifndef HAVE_SKB_VLAN_PUSH
int rpl_skb_vlan_push(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci)
{
	if (skb_vlan_tag_present(skb)) {
		unsigned int offset = skb->data - skb_mac_header(skb);
		int err;

		/* __vlan_insert_tag expect skb->data pointing to mac header.
		 * So change skb->data before calling it and change back to
		 * original position later
		 */
		__skb_push(skb, offset);
		err = __vlan_insert_tag(skb, skb->vlan_proto,
					skb_vlan_tag_get(skb));
		if (err)
			return err;
		skb->mac_len += VLAN_HLEN;
		__skb_pull(skb, offset);

		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->csum = csum_add(skb->csum, csum_partial(skb->data
					+ (2 * ETH_ALEN), VLAN_HLEN, 0));
	}
	__vlan_hwaccel_put_tag(skb, vlan_proto, vlan_tci);
	return 0;
}
EXPORT_SYMBOL_GPL(rpl_skb_vlan_push);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
int rpl_pskb_expand_head(struct sk_buff *skb, int nhead, int ntail,
			 gfp_t gfp_mask)
{
	int err;
	int inner_mac_offset, inner_nw_offset, inner_transport_offset;

	inner_mac_offset = skb_inner_mac_offset(skb);
	inner_nw_offset = skb_inner_network_offset(skb);
	inner_transport_offset = ovs_skb_inner_transport_offset(skb);

#undef pskb_expand_head
	err = pskb_expand_head(skb, nhead, ntail, gfp_mask);
	if (err)
		return err;

	skb_set_inner_mac_header(skb, inner_mac_offset);
	skb_set_inner_network_header(skb, inner_nw_offset);
	skb_set_inner_transport_header(skb, inner_transport_offset);

	return 0;
}
EXPORT_SYMBOL(rpl_pskb_expand_head);

#endif

#ifndef HAVE_KFREE_SKB_LIST
void rpl_kfree_skb_list(struct sk_buff *segs)
{
	while (segs) {
		struct sk_buff *next = segs->next;

		kfree_skb(segs);
		segs = next;
	}
}
EXPORT_SYMBOL(rpl_kfree_skb_list);
#endif
