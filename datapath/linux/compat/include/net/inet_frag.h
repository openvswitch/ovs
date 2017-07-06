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

#endif /* inet_frag.h */
