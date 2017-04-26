#ifndef _NF_CONNTRACK_LABELS_WRAPPER_H
#define _NF_CONNTRACK_LABELS_WRAPPER_H

#include <linux/kconfig.h>
#include <linux/version.h>
#include_next <net/netfilter/nf_conntrack_labels.h>

#ifndef NF_CT_LABELS_MAX_SIZE
#define NF_CT_LABELS_MAX_SIZE ((XT_CONNLABEL_MAXBIT + 1) / BITS_PER_BYTE)
#endif

#ifndef HAVE_NF_CONNLABELS_GET_TAKES_BIT
#if IS_ENABLED(CONFIG_NF_CONNTRACK_LABELS)

/* XXX: This doesn't lock others out from doing the same configuration
 *	simultaneously. */
static inline int rpl_nf_connlabels_get(struct net *net, unsigned int bits)
{
#ifndef HAVE_NF_CONNLABELS_GET
	size_t words;

	words = BIT_WORD(bits) + 1;
	if (words > NF_CT_LABELS_MAX_SIZE / sizeof(long))
		return -ERANGE;

	net->ct.labels_used++;
	if (words > net->ct.label_words)
		net->ct.label_words = words;

	return 0;
#else
	return nf_connlabels_get(net, bits + 1);
#endif /* HAVE_NF_CONNLABELS_GET */
}
#define nf_connlabels_get rpl_nf_connlabels_get

static inline void rpl_nf_connlabels_put(struct net *net)
{
#ifndef HAVE_NF_CONNLABELS_GET
	net->ct.labels_used--;
	if (net->ct.labels_used == 0)
		net->ct.label_words = 0;
#else
	nf_connlabels_put(net);
#endif /* HAVE_NF_CONNLABELS_GET */
}
#define nf_connlabels_put rpl_nf_connlabels_put

#else /* CONFIG_NF_CONNTRACK_LABELS */
#define nf_connlabels_get rpl_nf_connlabels_get
static inline int nf_connlabels_get(struct net *net, unsigned int bits)
{
	return -ERANGE;
}

#define nf_connlabels_put rpl_nf_connlabels_put
static inline void nf_connlabels_put(struct net *net) { }
#endif /* CONFIG_NF_CONNTRACK_LABELS */
#endif /* HAVE_NF_CONNLABELS_GET_TAKES_BIT */

/* Upstream commit 5a8145f7b222 ("netfilter: labels: don't emit ct event if
 * labels were not changed"), released in Linux 4.7, introduced a functional
 * change to trigger conntrack event for a label change only when the labels
 * actually changed.  There is no way we can detect this from the headers, so
 * provide replacements that work the same for OVS (where labels size is 128
 * bits == 16 bytes == 4 4-byte words). */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
static int replace_u32(u32 *address, u32 mask, u32 new)
{
	u32 old, tmp;

	do {
		old = *address;
		tmp = (old & mask) ^ new;
		if (old == tmp)
			return 0;
	} while (cmpxchg(address, old, tmp) != old);

	return 1;
}

static int rpl_nf_connlabels_replace(struct nf_conn *ct,
				     const u32 *data,
				     const u32 *mask, unsigned int words32)
{
	struct nf_conn_labels *labels;
	unsigned int i;
	int changed = 0;
	u32 *dst;

	labels = nf_ct_labels_find(ct);
	if (!labels)
		return -ENOSPC;

	dst = (u32 *) labels->bits;
	for (i = 0; i < words32; i++)
		changed |= replace_u32(&dst[i], mask ? ~mask[i] : 0, data[i]);

	if (changed)
		nf_conntrack_event_cache(IPCT_LABEL, ct);

	return 0;
}
#define nf_connlabels_replace rpl_nf_connlabels_replace
#endif

#endif /* _NF_CONNTRACK_LABELS_WRAPPER_H */
