#ifndef __NET_INET_FRAG_WRAPPER_H
#define __NET_INET_FRAG_WRAPPER_H 1

#include <linux/version.h>
#include_next <net/inet_frag.h>

#ifdef HAVE_INET_FRAGS_LAST_IN
#define q_flags(q) (q->last_in)
#define qp_flags(qp) (qp->q.last_in)
#else
#define q_flags(q) (q->flags)
#define qp_flags(qp) (qp->q.flags)
#endif

#ifndef HAVE_INET_FRAG_EVICTING
static inline bool inet_frag_evicting(struct inet_frag_queue *q)
{
#ifdef HAVE_INET_FRAG_QUEUE_WITH_LIST_EVICTOR
	return !hlist_unhashed(&q->list_evictor);
#else
	return (q_flags(q) & INET_FRAG_FIRST_IN) && q->fragments != NULL;
#endif /* HAVE_INET_FRAG_QUEUE_WITH_LIST_EVICTOR */
}
#endif /* HAVE_INET_FRAG_EVICTING */

/* Upstream commit 3fd588eb90bf ("inet: frag: remove lru list") dropped this
 * function, but we call it from our compat code. Provide a noop version. */
#ifndef HAVE_INET_FRAG_LRU_MOVE
#define inet_frag_lru_move(q)
#endif

#ifndef HAVE_SUB_FRAG_MEM_LIMIT_ARG_STRUCT_NETNS_FRAGS
static inline void rpl_sub_frag_mem_limit(struct netns_frags *nf, int i)
{
	__percpu_counter_add(&nf->mem, -i, frag_percpu_counter_batch);
}
#define sub_frag_mem_limit rpl_sub_frag_mem_limit

static inline void rpl_add_frag_mem_limit(struct netns_frags *nf, int i)
{
	__percpu_counter_add(&nf->mem, i, frag_percpu_counter_batch);
}
#define add_frag_mem_limit rpl_add_frag_mem_limit
#endif

#ifdef HAVE_VOID_INET_FRAGS_INIT
static inline int rpl_inet_frags_init(struct inet_frags *frags)
{
	inet_frags_init(frags);
	return 0;
}
#define inet_frags_init rpl_inet_frags_init
#endif

#ifndef HAVE_CORRECT_MRU_HANDLING
/* We reuse the upstream inet_fragment.c common code for managing fragment
 * stores, However we actually store the fragments within our own 'inet_frags'
 * structures (in {ip_fragment,nf_conntrack_reasm}.c). When unloading the OVS
 * kernel module, we need to flush all of the remaining fragments from these
 * caches, or else we will panic with the following sequence of events:
 *
 * 1) A fragment for a packet arrives and is cached in inet_frags. This
 *    starts a timer to ensure the fragment does not hang around forever.
 * 2) openvswitch module is unloaded.
 * 3) The timer for the fragment fires, calling into backported OVS code
 *    to free the fragment.
 * 4) BUG: unable to handle kernel paging request at ffffffffc03c01e0
 */
void rpl_inet_frags_exit_net(struct netns_frags *nf, struct inet_frags *f);
#define inet_frags_exit_net rpl_inet_frags_exit_net
#endif

#endif /* inet_frag.h */
