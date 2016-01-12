#ifndef _NF_CONNTRACK_LABELS_WRAPPER_H
#define _NF_CONNTRACK_LABELS_WRAPPER_H

#include <linux/kconfig.h>
#include <linux/version.h>
#include_next <net/netfilter/nf_conntrack_labels.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
#if IS_ENABLED(CONFIG_NF_CONNTRACK_LABELS)

#ifndef NF_CT_LABELS_MAX_SIZE
#define NF_CT_LABELS_MAX_SIZE ((XT_CONNLABEL_MAXBIT + 1) / BITS_PER_BYTE)
#endif

/* XXX: This doesn't lock others out from doing the same configuration
 *	simultaneously. */
static inline int nf_connlabels_get(struct net *net, unsigned int n_bits)
{
	size_t words;

	if (n_bits > (NF_CT_LABELS_MAX_SIZE * BITS_PER_BYTE))
		return -ERANGE;

	words = BITS_TO_LONGS(n_bits);

	net->ct.labels_used++;
	if (words > net->ct.label_words)
		net->ct.label_words = words;

	return 0;
}

static inline void nf_connlabels_put(struct net *net)
{
	net->ct.labels_used--;
	if (net->ct.labels_used == 0)
		net->ct.label_words = 0;
}

#else /* CONFIG_NF_CONNTRACK_LABELS */
static inline int nf_connlabels_get(struct net *net, unsigned int n_bits)
{
	return -ERANGE;
}

static inline void nf_connlabels_put(struct net *net) { }
#endif /* CONFIG_NF_CONNTRACK_LABELS */
#endif /* 4.3 */
#endif /* _NF_CONNTRACK_LABELS_WRAPPER_H */
