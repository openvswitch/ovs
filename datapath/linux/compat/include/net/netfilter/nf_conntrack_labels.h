#ifndef _NF_CONNTRACK_LABELS_WRAPPER_H
#define _NF_CONNTRACK_LABELS_WRAPPER_H

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
#ifdef CONFIG_NF_CONNTRACK_LABELS

#include_next <net/netfilter/nf_conntrack_labels.h>

#ifndef NF_CT_LABELS_MAX_SIZE
#define NF_CT_LABELS_MAX_SIZE ((XT_CONNLABEL_MAXBIT + 1) / BITS_PER_BYTE)
#endif

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

#endif /* CONFIG_NF_CONNTRACK_LABELS */
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0) */
#endif /* _NF_CONNTRACK_LABELS_WRAPPER_H */
