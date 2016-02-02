#ifndef __NET_INET_FRAG_WRAPPER_H
#define __NET_INET_FRAG_WRAPPER_H 1

#include <linux/version.h>
#include_next <net/inet_frag.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#define inet_frag_evictor(nf, f, force)					\
	do {								\
		if (force || atomic_read(&nf->mem) > nf->high_thresh) { \
			inet_frag_evictor(nf, f);			\
		}							\
	} while (0)
#endif

#ifdef OVS_FRAGMENT_BACKPORT
#ifdef HAVE_INET_FRAGS_LAST_IN
#define q_flags(q) (q->last_in)
#define qp_flags(qp) (qp->q.last_in)
#else
#define q_flags(q) (q->flags)
#define qp_flags(qp) (qp->q.flags)
#endif

#ifndef HAVE_INET_FRAG_QUEUE_WITH_LIST_EVICTOR
/**
 * struct ovs_inet_frag_queue - fragment queue
 *
 * Wrap the system inet_frag_queue to provide a list evictor.
 *
 * @list_evictor: list of queues to forcefully evict (e.g. due to low memory)
 */
struct ovs_inet_frag_queue {
	struct inet_frag_queue	fq;
	struct hlist_node	list_evictor;
};

static inline bool rpl_inet_frag_evicting(struct inet_frag_queue *q)
{
#ifdef HAVE_INET_FRAGS_WITH_FRAGS_WORK
	struct ovs_inet_frag_queue *ofq = (struct ovs_inet_frag_queue *)q;
	return !hlist_unhashed(&ofq->list_evictor);
#else
	return (q_flags(q) & INET_FRAG_FIRST_IN) && q->fragments != NULL;
#endif
}
#define inet_frag_evicting rpl_inet_frag_evicting
#else /* HAVE_INET_FRAG_QUEUE_WITH_LIST_EVICTOR */
#ifndef HAVE_INET_FRAG_EVICTING
static inline bool rpl_inet_frag_evicting(struct inet_frag_queue *q)
{
	return !hlist_unhashed(&q->list_evictor);
}
#define inet_frag_evicting rpl_inet_frag_evicting
#endif
#endif

#ifndef HAVE_CORRECT_MRU_HANDLING
static unsigned int rpl_frag_percpu_counter_batch = 130000;
#define frag_percpu_counter_batch rpl_frag_percpu_counter_batch

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

int rpl_inet_frags_init(struct inet_frags *f);
#define inet_frags_init rpl_inet_frags_init

void rpl_inet_frags_exit_net(struct netns_frags *nf, struct inet_frags *f);
#define inet_frags_exit_net rpl_inet_frags_exit_net

void rpl_inet_frag_destroy(struct inet_frag_queue *q, struct inet_frags *f);
#define inet_frag_destroy(q, f, work) rpl_inet_frag_destroy(q, f)
#endif /* !HAVE_CORRECT_MRU_HANDLING */
#endif /* OVS_FRAGMENT_BACKPORT */

#endif /* inet_frag.h */
