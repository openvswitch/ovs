/*
 * inet fragments management
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * 		Authors:	Pavel Emelyanov <xemul@openvz.org>
 *				Started as consolidation of ipv4/ip_fragment.c,
 *				ipv6/reassembly. and ipv6 nf conntrack reassembly
 */

#ifndef HAVE_CORRECT_MRU_HANDLING

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>

#include <net/sock.h>
#include <net/inet_frag.h>
#include <net/inet_ecn.h>

#ifdef HAVE_INET_FRAGS_WITH_FRAGS_WORK
static bool inet_fragq_should_evict(const struct inet_frag_queue *q)
{
	return q->net->low_thresh == 0 ||
	       frag_mem_limit(q->net) >= q->net->low_thresh;
}

static unsigned int
inet_evict_bucket(struct inet_frags *f, struct inet_frag_bucket *hb)
{
	struct inet_frag_queue *fq;
	struct hlist_node *n;
	unsigned int evicted = 0;
	HLIST_HEAD(expired);

	spin_lock(&hb->chain_lock);

	hlist_for_each_entry_safe(fq, n, &hb->chain, list) {
		if (!inet_fragq_should_evict(fq))
			continue;

		if (!del_timer(&fq->timer))
			continue;

#ifdef HAVE_INET_FRAG_QUEUE_WITH_LIST_EVICTOR
		hlist_add_head(&fq->list_evictor, &expired);
#else
		hlist_del(&fq->list);
		hlist_add_head(&fq->list, &expired);
#endif
		++evicted;
	}

	spin_unlock(&hb->chain_lock);

#ifdef HAVE_INET_FRAG_QUEUE_WITH_LIST_EVICTOR
	hlist_for_each_entry_safe(fq, n, &expired, list_evictor)
#else
	hlist_for_each_entry_safe(fq, n, &expired, list)
#endif
		f->frag_expire((unsigned long) fq);

	return evicted;
}

void inet_frags_exit_net(struct netns_frags *nf, struct inet_frags *f)
{
	int thresh = nf->low_thresh;
	unsigned int seq;
	int i;

	nf->low_thresh = 0;

evict_again:
	local_bh_disable();
	seq = read_seqbegin(&f->rnd_seqlock);

	for (i = 0; i < INETFRAGS_HASHSZ ; i++)
		inet_evict_bucket(f, &f->hash[i]);

	local_bh_enable();
	cond_resched();

	if (read_seqretry(&f->rnd_seqlock, seq) ||
	    percpu_counter_sum(&nf->mem))
		goto evict_again;

	nf->low_thresh = thresh;
}
#else /* HAVE_INET_FRAGS_WITH_FRAGS_WORK */
void inet_frags_exit_net(struct netns_frags *nf, struct inet_frags *f)
{
	int thresh = nf->low_thresh;

	nf->low_thresh = 0;

	local_bh_disable();
	inet_frag_evictor(nf, f, true);
	local_bh_enable();

	nf->low_thresh = thresh;
}
#endif /* HAVE_INET_FRAGS_WITH_FRAGS_WORK */

#endif /* !HAVE_CORRECT_MRU_HANDLING */
