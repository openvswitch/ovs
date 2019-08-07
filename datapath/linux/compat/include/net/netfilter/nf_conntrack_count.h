#ifndef _NF_CONNTRACK_COUNT_WRAPPER_H
#define _NF_CONNTRACK_COUNT_WRAPPER_H

#include <linux/list.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_zones.h>

#ifdef HAVE_UPSTREAM_NF_CONNCOUNT
#include_next <net/netfilter/nf_conntrack_count.h>

static inline int rpl_nf_conncount_modinit(void)
{
    return 0;
}

static inline void rpl_nf_conncount_modexit(void)
{
}

#else
#define CONFIG_NETFILTER_CONNCOUNT 1
struct nf_conncount_data;

struct nf_conncount_list {
	spinlock_t list_lock;
	struct list_head head;	/* connections with the same filtering key */
	unsigned int count;	/* length of list */
};

struct nf_conncount_data
*rpl_nf_conncount_init(struct net *net, unsigned int family,
		       unsigned int keylen);

void rpl_nf_conncount_destroy(struct net *net, unsigned int family,
			      struct nf_conncount_data *data);

unsigned int rpl_nf_conncount_count(struct net *net,
				    struct nf_conncount_data *data,
				    const u32 *key,
				    const struct nf_conntrack_tuple *tuple,
				    const struct nf_conntrack_zone *zone);

#define nf_conncount_init rpl_nf_conncount_init
#define nf_conncount_destroy rpl_nf_conncount_destroy
#define nf_conncount_count rpl_nf_conncount_count

int rpl_nf_conncount_modinit(void);
void rpl_nf_conncount_modexit(void);
#endif /* HAVE_UPSTREAM_NF_CONNCOUNT */

#define nf_conncount_mod_init rpl_nf_conncount_modinit
#define nf_conncount_modexit rpl_nf_conncount_modexit

#endif /* _NF_CONNTRACK_COUNT_WRAPPER_H */
