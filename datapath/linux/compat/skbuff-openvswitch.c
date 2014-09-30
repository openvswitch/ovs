#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

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
skb_zerocopy_headlen(const struct sk_buff *from)
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
skb_zerocopy(struct sk_buff *to, struct sk_buff *from, int len, int hlen)
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
#endif
#endif
