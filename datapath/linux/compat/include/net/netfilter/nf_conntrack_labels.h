#ifndef _NF_CONNTRACK_LABELS_WRAPPER_H
#define _NF_CONNTRACK_LABELS_WRAPPER_H

#include <linux/kconfig.h>
#include <linux/version.h>
#include_next <net/netfilter/nf_conntrack_labels.h>

#ifndef HAVE_NF_CONNLABELS_GET_TAKES_BIT
#if IS_ENABLED(CONFIG_NF_CONNTRACK_LABELS)

#ifndef NF_CT_LABELS_MAX_SIZE
#define NF_CT_LABELS_MAX_SIZE ((XT_CONNLABEL_MAXBIT + 1) / BITS_PER_BYTE)
#endif

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
#endif /* _NF_CONNTRACK_LABELS_WRAPPER_H */
