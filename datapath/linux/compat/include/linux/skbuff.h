#ifndef __LINUX_SKBUFF_WRAPPER_H
#define __LINUX_SKBUFF_WRAPPER_H 1

#include <linux/version.h>
#include <linux/types.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
/* This should be before skbuff.h to make sure that we rewrite
 * the calls there. */
struct sk_buff;

int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail,
		     gfp_t gfp_mask);
#define pskb_expand_head rpl_pskb_expand_head
#endif

#include_next <linux/skbuff.h>
#include <linux/jhash.h>

#ifndef HAVE_IGNORE_DF_RENAME
#define ignore_df local_df
#endif


#ifndef HAVE_NULL_COMPUTE_PSEUDO
static inline __wsum null_compute_pseudo(struct sk_buff *skb, int proto)
{
	return 0;
}
#endif

#ifndef HAVE_SKB_CHECKSUM_CONVERT
static inline bool __skb_checksum_convert_check(struct sk_buff *skb)
{
#ifdef HAVE_SKBUFF_CSUM_VALID
	return (skb->ip_summed == CHECKSUM_NONE && skb->csum_valid);
#else
	return skb->ip_summed == CHECKSUM_NONE;
#endif
}

static inline void __skb_checksum_convert(struct sk_buff *skb,
					  __sum16 check, __wsum pseudo)
{
	skb->csum = ~pseudo;
	skb->ip_summed = CHECKSUM_COMPLETE;
}

#define skb_checksum_try_convert(skb, proto, check, compute_pseudo)	\
do {									\
	if (__skb_checksum_convert_check(skb))				\
		__skb_checksum_convert(skb, check,			\
				       compute_pseudo(skb, proto));	\
} while (0)

#endif

#ifndef SKB_CHECKSUM_SIMPLE_VALIDATE

#ifndef __skb_checksum_validate
#define __skb_checksum_validate(skb, proto, complete,			\
				zero_okay, check, compute_pseudo)	\
({									\
	__sum16 __ret = 0;						\
	__ret;								\
})
#endif

#define skb_checksum_simple_validate(skb)				\
	__skb_checksum_validate(skb, 0, true, false, 0, null_compute_pseudo)
#endif

#ifndef HAVE_SKB_COPY_FROM_LINEAR_DATA_OFFSET
static inline void skb_copy_from_linear_data_offset(const struct sk_buff *skb,
						    const int offset, void *to,
						    const unsigned int len)
{
	memcpy(to, skb->data + offset, len);
}

static inline void skb_copy_to_linear_data_offset(struct sk_buff *skb,
						  const int offset,
						  const void *from,
						  const unsigned int len)
{
	memcpy(skb->data + offset, from, len);
}

#endif	/* !HAVE_SKB_COPY_FROM_LINEAR_DATA_OFFSET */

#ifndef HAVE_SKB_INNER_TRANSPORT_OFFSET
static inline int skb_inner_transport_offset(const struct sk_buff *skb)
{
	return skb_inner_transport_header(skb) - skb->data;
}
#endif

#ifndef HAVE_SKB_RESET_TAIL_POINTER
static inline void skb_reset_tail_pointer(struct sk_buff *skb)
{
	skb->tail = skb->data;
}
#endif
/*
 * The networking layer reserves some headroom in skb data (via
 * dev_alloc_skb). This is used to avoid having to reallocate skb data when
 * the header has to grow. In the default case, if the header has to grow
 * 16 bytes or less we avoid the reallocation.
 *
 * Unfortunately this headroom changes the DMA alignment of the resulting
 * network packet. As for NET_IP_ALIGN, this unaligned DMA is expensive
 * on some architectures. An architecture can override this value,
 * perhaps setting it to a cacheline in size (since that will maintain
 * cacheline alignment of the DMA). It must be a power of 2.
 *
 * Various parts of the networking layer expect at least 16 bytes of
 * headroom, you should not reduce this.
 */
#ifndef NET_SKB_PAD
#define NET_SKB_PAD	16
#endif

#ifndef HAVE_SKB_COW_HEAD
static inline int __skb_cow(struct sk_buff *skb, unsigned int headroom,
			    int cloned)
{
	int delta = 0;

	if (headroom < NET_SKB_PAD)
		headroom = NET_SKB_PAD;
	if (headroom > skb_headroom(skb))
		delta = headroom - skb_headroom(skb);

	if (delta || cloned)
		return pskb_expand_head(skb, ALIGN(delta, NET_SKB_PAD), 0,
					GFP_ATOMIC);
	return 0;
}

static inline int skb_cow_head(struct sk_buff *skb, unsigned int headroom)
{
	return __skb_cow(skb, headroom, skb_header_cloned(skb));
}
#endif	/* !HAVE_SKB_COW_HEAD */

#ifndef HAVE_SKB_DST_ACCESSOR_FUNCS
static inline struct dst_entry *skb_dst(const struct sk_buff *skb)
{
	return (struct dst_entry *)skb->dst;
}

static inline void skb_dst_set(struct sk_buff *skb, struct dst_entry *dst)
{
	skb->dst = dst;
}

static inline struct rtable *skb_rtable(const struct sk_buff *skb)
{
	return (struct rtable *)skb->dst;
}
#endif

#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#endif
#ifndef CHECKSUM_COMPLETE
#define CHECKSUM_COMPLETE CHECKSUM_HW
#endif

#ifndef HAVE_SKB_WARN_LRO
#ifndef NETIF_F_LRO
static inline bool skb_warn_if_lro(const struct sk_buff *skb)
{
	return false;
}
#else
extern void __skb_warn_lro_forwarding(const struct sk_buff *skb);

static inline bool skb_warn_if_lro(const struct sk_buff *skb)
{
	/* LRO sets gso_size but not gso_type, whereas if GSO is really
	 * wanted then gso_type will be set. */
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	if (shinfo->gso_size != 0 && unlikely(shinfo->gso_type == 0)) {
		__skb_warn_lro_forwarding(skb);
		return true;
	}
	return false;
}
#endif /* NETIF_F_LRO */
#endif /* HAVE_SKB_WARN_LRO */

#ifndef HAVE_CONSUME_SKB
#define consume_skb kfree_skb
#endif

#ifndef HAVE_SKB_FRAG_PAGE
#include <linux/mm.h>

static inline struct page *skb_frag_page(const skb_frag_t *frag)
{
	return frag->page;
}

static inline void __skb_frag_set_page(skb_frag_t *frag, struct page *page)
{
	frag->page = page;
}
static inline void skb_frag_size_set(skb_frag_t *frag, unsigned int size)
{
	frag->size = size;
}
static inline void __skb_frag_ref(skb_frag_t *frag)
{
	get_page(skb_frag_page(frag));
}
static inline void __skb_frag_unref(skb_frag_t *frag)
{
	put_page(skb_frag_page(frag));
}

static inline void skb_frag_ref(struct sk_buff *skb, int f)
{
	__skb_frag_ref(&skb_shinfo(skb)->frags[f]);
}

static inline void skb_frag_unref(struct sk_buff *skb, int f)
{
	__skb_frag_unref(&skb_shinfo(skb)->frags[f]);
}

#endif

#ifndef HAVE_SKB_RESET_MAC_LEN
static inline void skb_reset_mac_len(struct sk_buff *skb)
{
	skb->mac_len = skb->network_header - skb->mac_header;
}
#endif

#ifndef HAVE_SKB_UNCLONE
static inline int skb_unclone(struct sk_buff *skb, gfp_t pri)
{
	might_sleep_if(pri & __GFP_WAIT);

	if (skb_cloned(skb))
		return pskb_expand_head(skb, 0, 0, pri);

	return 0;
}
#endif

#ifndef HAVE_SKB_ORPHAN_FRAGS
static inline int skb_orphan_frags(struct sk_buff *skb, gfp_t gfp_mask)
{
	return 0;
}
#endif

#ifndef HAVE_SKB_GET_HASH
#define skb_get_hash skb_get_rxhash
#endif /* HAVE_SKB_GET_HASH */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
#define skb_zerocopy_headlen rpl_skb_zerocopy_headlen
unsigned int rpl_skb_zerocopy_headlen(const struct sk_buff *from);
#endif

#ifndef HAVE_SKB_ZEROCOPY
#define skb_zerocopy rpl_skb_zerocopy
int rpl_skb_zerocopy(struct sk_buff *to, struct sk_buff *from, int len,
		     int hlen);
#endif

#ifndef HAVE_SKB_CLEAR_HASH
static inline void skb_clear_hash(struct sk_buff *skb)
{
#ifdef HAVE_RXHASH
	skb->rxhash = 0;
#endif
#if defined(HAVE_L4_RXHASH) && !defined(HAVE_RHEL_OVS_HOOK)
	skb->l4_rxhash = 0;
#endif
}
#endif

#ifndef HAVE_SKB_HAS_FRAG_LIST
#define skb_has_frag_list skb_has_frags
#endif

#ifndef HAVE___SKB_FILL_PAGE_DESC
static inline void __skb_fill_page_desc(struct sk_buff *skb, int i,
					struct page *page, int off, int size)
{
	skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

	__skb_frag_set_page(frag, page);
	frag->page_offset	= off;
	skb_frag_size_set(frag, size);
}
#endif

#ifndef HAVE_SKB_ENSURE_WRITABLE
#define skb_ensure_writable rpl_skb_ensure_writable
int rpl_skb_ensure_writable(struct sk_buff *skb, int write_len);
#endif

#ifndef HAVE___SKB_VLAN_POP
#define __skb_vlan_pop rpl___skb_vlan_pop
int rpl___skb_vlan_pop(struct sk_buff *skb, u16 *vlan_tci);
#endif

#ifndef HAVE_SKB_VLAN_POP
#define skb_vlan_pop rpl_skb_vlan_pop
int rpl_skb_vlan_pop(struct sk_buff *skb);
#endif

#ifndef HAVE_SKB_VLAN_PUSH
#define skb_vlan_push rpl_skb_vlan_push
int rpl_skb_vlan_push(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci);
#endif

#ifndef HAVE_KFREE_SKB_LIST
void rpl_kfree_skb_list(struct sk_buff *segs);
#define kfree_skb_list rpl_kfree_skb_list
#endif

#ifndef HAVE_SKB_CHECKSUM_START_OFFSET
static inline int skb_checksum_start_offset(const struct sk_buff *skb)
{
	return skb->csum_start - skb_headroom(skb);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
#define skb_postpull_rcsum rpl_skb_postpull_rcsum
static inline void skb_postpull_rcsum(struct sk_buff *skb,
				      const void *start, unsigned int len)
{
	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->csum = csum_sub(skb->csum, csum_partial(start, len, 0));
	else if (skb->ip_summed == CHECKSUM_PARTIAL &&
			skb_checksum_start_offset(skb) < 0)
		skb->ip_summed = CHECKSUM_NONE;
}

#define skb_pull_rcsum rpl_skb_pull_rcsum
static inline unsigned char *skb_pull_rcsum(struct sk_buff *skb, unsigned int len)
{
	unsigned char *data = skb->data;

	BUG_ON(len > skb->len);
	__skb_pull(skb, len);
	skb_postpull_rcsum(skb, data, len);
	return skb->data;
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
#define skb_scrub_packet rpl_skb_scrub_packet
void rpl_skb_scrub_packet(struct sk_buff *skb, bool xnet);
#endif

#define skb_pop_mac_header rpl_skb_pop_mac_header
static inline void skb_pop_mac_header(struct sk_buff *skb)
{
	skb->mac_header = skb->network_header;
}

#ifndef HAVE_SKB_CLEAR_HASH_IF_NOT_L4
static inline void skb_clear_hash_if_not_l4(struct sk_buff *skb)
{
	if (!skb->l4_rxhash)
		skb_clear_hash(skb);
}
#endif

#ifndef HAVE_SKB_POSTPUSH_RCSUM
static inline void skb_postpush_rcsum(struct sk_buff *skb,
				      const void *start, unsigned int len)
{
	/* For performing the reverse operation to skb_postpull_rcsum(),
	 * we can instead of ...
	 *
	 *   skb->csum = csum_add(skb->csum, csum_partial(start, len, 0));
	 *
	 * ... just use this equivalent version here to save a few
	 * instructions. Feeding csum of 0 in csum_partial() and later
	 * on adding skb->csum is equivalent to feed skb->csum in the
	 * first place.
	 */
	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->csum = csum_partial(start, len, skb->csum);
}
#endif

#define skb_checksum_start rpl_skb_checksum_start
static inline unsigned char *skb_checksum_start(const struct sk_buff *skb)
{
	return skb->head + skb->csum_start;
}

#ifndef HAVE_LCO_CSUM
static inline __wsum lco_csum(struct sk_buff *skb)
{
	unsigned char *csum_start = skb_checksum_start(skb);
	unsigned char *l4_hdr = skb_transport_header(skb);
	__wsum partial;

	/* Start with complement of inner checksum adjustment */
	partial = ~csum_unfold(*(__force __sum16 *)(csum_start +
				skb->csum_offset));

	/* Add in checksum of our headers (incl. outer checksum
	 * adjustment filled in by caller) and return result.
	 */
	return csum_partial(l4_hdr, csum_start - l4_hdr, partial);
}
#endif

#ifndef HAVE_SKB_NFCT
static inline struct nf_conntrack *skb_nfct(const struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
       return skb->nfct;
#else
       return NULL;
#endif
}
#endif

#ifndef HAVE_SKB_PUT_ZERO
static inline void *skb_put_zero(struct sk_buff *skb, unsigned int len)
{
	void *tmp = skb_put(skb, len);

	memset(tmp, 0, len);

	return tmp;
}
#endif

#ifndef HAVE_SKB_GSO_IPXIP6
#define SKB_GSO_IPXIP6 (1 << 10)
#endif

#ifndef HAVE_SKB_SET_INNER_IPPROTO
static inline void skb_set_inner_ipproto(struct sk_buff *skb,
					 __u8 ipproto)
{
}
#endif

#ifndef HAVE_NF_RESET_CT
#define nf_reset_ct nf_reset
#endif

#endif
