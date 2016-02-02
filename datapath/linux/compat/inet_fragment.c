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

#include <linux/version.h>

#if !defined(HAVE_CORRECT_MRU_HANDLING) && defined(OVS_FRAGMENT_BACKPORT)

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

#define INETFRAGS_EVICT_BUCKETS   128
#define INETFRAGS_EVICT_MAX	  512

/* don't rebuild inetfrag table with new secret more often than this */
#define INETFRAGS_MIN_REBUILD_INTERVAL (5 * HZ)

/* Given the OR values of all fragments, apply RFC 3168 5.3 requirements
 * Value : 0xff if frame should be dropped.
 *         0 or INET_ECN_CE value, to be ORed in to final iph->tos field
 */
const u8 ip_frag_ecn_table[16] = {
	/* at least one fragment had CE, and others ECT_0 or ECT_1 */
	[IPFRAG_ECN_CE | IPFRAG_ECN_ECT_0]			= INET_ECN_CE,
	[IPFRAG_ECN_CE | IPFRAG_ECN_ECT_1]			= INET_ECN_CE,
	[IPFRAG_ECN_CE | IPFRAG_ECN_ECT_0 | IPFRAG_ECN_ECT_1]	= INET_ECN_CE,

	/* invalid combinations : drop frame */
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_CE] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_ECT_0] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_ECT_1] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_ECT_0 | IPFRAG_ECN_ECT_1] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_CE | IPFRAG_ECN_ECT_0] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_CE | IPFRAG_ECN_ECT_1] = 0xff,
	[IPFRAG_ECN_NOT_ECT | IPFRAG_ECN_CE | IPFRAG_ECN_ECT_0 | IPFRAG_ECN_ECT_1] = 0xff,
};

static unsigned int
inet_frag_hashfn(const struct inet_frags *f, struct inet_frag_queue *q)
{
	return f->hashfn(q) & (INETFRAGS_HASHSZ - 1);
}

#ifdef HAVE_INET_FRAGS_WITH_FRAGS_WORK
static bool inet_frag_may_rebuild(struct inet_frags *f)
{
	return time_after(jiffies,
	       f->last_rebuild_jiffies + INETFRAGS_MIN_REBUILD_INTERVAL);
}

static void inet_frag_secret_rebuild(struct inet_frags *f)
{
	int i;

	write_seqlock_bh(&f->rnd_seqlock);

	if (!inet_frag_may_rebuild(f))
		goto out;

	get_random_bytes(&f->rnd, sizeof(u32));

	for (i = 0; i < INETFRAGS_HASHSZ; i++) {
		struct inet_frag_bucket *hb;
		struct inet_frag_queue *q;
		struct hlist_node *n;

		hb = &f->hash[i];
		spin_lock(&hb->chain_lock);

		hlist_for_each_entry_safe(q, n, &hb->chain, list) {
			unsigned int hval = inet_frag_hashfn(f, q);

			if (hval != i) {
				struct inet_frag_bucket *hb_dest;

				hlist_del(&q->list);

				/* Relink to new hash chain. */
				hb_dest = &f->hash[hval];

				/* This is the only place where we take
				 * another chain_lock while already holding
				 * one.  As this will not run concurrently,
				 * we cannot deadlock on hb_dest lock below, if its
				 * already locked it will be released soon since
				 * other caller cannot be waiting for hb lock
				 * that we've taken above.
				 */
				spin_lock_nested(&hb_dest->chain_lock,
						 SINGLE_DEPTH_NESTING);
				hlist_add_head(&q->list, &hb_dest->chain);
				spin_unlock(&hb_dest->chain_lock);
			}
		}
		spin_unlock(&hb->chain_lock);
	}

	f->rebuild = false;
	f->last_rebuild_jiffies = jiffies;
out:
	write_sequnlock_bh(&f->rnd_seqlock);
}

static bool inet_fragq_should_evict(const struct inet_frag_queue *q)
{
	return q->net->low_thresh == 0 ||
	       frag_mem_limit(q->net) >= q->net->low_thresh;
}

static unsigned int
inet_evict_bucket(struct inet_frags *f, struct inet_frag_bucket *hb)
{
#ifndef HAVE_INET_FRAG_QUEUE_WITH_LIST_EVICTOR
	struct ovs_inet_frag_queue *ofq;
#endif
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
		ofq = (struct ovs_inet_frag_queue *)fq;
		hlist_add_head(&ofq->list_evictor, &expired);
#endif
		++evicted;
	}

	spin_unlock(&hb->chain_lock);

#ifdef HAVE_INET_FRAG_QUEUE_WITH_LIST_EVICTOR
	hlist_for_each_entry_safe(fq, n, &expired, list_evictor)
		f->frag_expire((unsigned long) fq);
#else
	hlist_for_each_entry_safe(ofq, n, &expired, list_evictor)
		f->frag_expire((unsigned long) &ofq->fq);
#endif

	return evicted;
}

static void inet_frag_worker(struct work_struct *work)
{
	unsigned int budget = INETFRAGS_EVICT_BUCKETS;
	unsigned int i, evicted = 0;
	struct inet_frags *f;

	f = container_of(work, struct inet_frags, frags_work);

	BUILD_BUG_ON(INETFRAGS_EVICT_BUCKETS >= INETFRAGS_HASHSZ);

	local_bh_disable();

	for (i = ACCESS_ONCE(f->next_bucket); budget; --budget) {
		evicted += inet_evict_bucket(f, &f->hash[i]);
		i = (i + 1) & (INETFRAGS_HASHSZ - 1);
		if (evicted > INETFRAGS_EVICT_MAX)
			break;
	}

	f->next_bucket = i;

	local_bh_enable();

	if (f->rebuild && inet_frag_may_rebuild(f))
		inet_frag_secret_rebuild(f);
}

static void inet_frag_schedule_worker(struct inet_frags *f)
{
	if (unlikely(!work_pending(&f->frags_work)))
		schedule_work(&f->frags_work);
}
#endif /* >= 3.17 */

int inet_frags_init(struct inet_frags *f)
{
	int i;

#ifdef HAVE_INET_FRAGS_WITH_FRAGS_WORK
	INIT_WORK(&f->frags_work, inet_frag_worker);
#endif

	for (i = 0; i < INETFRAGS_HASHSZ; i++) {
		struct inet_frag_bucket *hb = &f->hash[i];

		spin_lock_init(&hb->chain_lock);
		INIT_HLIST_HEAD(&hb->chain);
	}

#ifdef HAVE_INET_FRAGS_WITH_FRAGS_WORK
	seqlock_init(&f->rnd_seqlock);
	f->last_rebuild_jiffies = 0;
	f->frags_cachep = kmem_cache_create(f->frags_cache_name, f->qsize, 0, 0,
					    NULL);
	if (!f->frags_cachep)
		return -ENOMEM;
#else
	rwlock_init(&f->lock);
	f->secret_timer.expires = jiffies + f->secret_interval;
#endif

	return 0;
}

void inet_frags_fini(struct inet_frags *f)
{
#ifdef HAVE_INET_FRAGS_WITH_FRAGS_WORK
	cancel_work_sync(&f->frags_work);
	kmem_cache_destroy(f->frags_cachep);
#endif
}

int inet_frag_evictor(struct netns_frags *nf, struct inet_frags *f, bool force);

#ifdef HAVE_INET_FRAGS_WITH_FRAGS_WORK
void inet_frags_exit_net(struct netns_frags *nf, struct inet_frags *f)
{
	unsigned int seq;

evict_again:
	local_bh_disable();
	seq = read_seqbegin(&f->rnd_seqlock);

	inet_frag_evictor(nf, f, true);

	local_bh_enable();
	cond_resched();

	if (read_seqretry(&f->rnd_seqlock, seq) ||
	    percpu_counter_sum(&nf->mem))
		goto evict_again;
}
#else
void inet_frags_exit_net(struct netns_frags *nf, struct inet_frags *f)
{
	read_lock_bh(&f->lock);
	inet_frag_evictor(nf, f, true);
	read_unlock_bh(&f->lock);
}
#endif

static struct inet_frag_bucket *
get_frag_bucket_locked(struct inet_frag_queue *fq, struct inet_frags *f)
#ifdef HAVE_INET_FRAGS_WITH_RWLOCK
__acquires(f->lock)
#endif
__acquires(hb->chain_lock)
{
	struct inet_frag_bucket *hb;
	unsigned int hash;

#ifdef HAVE_INET_FRAGS_WITH_RWLOCK
	read_lock(&f->lock);
#else
	unsigned int seq;
 restart:
	seq = read_seqbegin(&f->rnd_seqlock);
#endif

	hash = inet_frag_hashfn(f, fq);
	hb = &f->hash[hash];

	spin_lock(&hb->chain_lock);

#ifndef HAVE_INET_FRAGS_WITH_RWLOCK
	if (read_seqretry(&f->rnd_seqlock, seq)) {
		spin_unlock(&hb->chain_lock);
		goto restart;
	}
#endif

	return hb;
}

static inline void fq_unlink(struct inet_frag_queue *fq, struct inet_frags *f)
#ifdef HAVE_INET_FRAGS_WITH_RWLOCK
__releases(f->lock)
#endif
__releases(hb->chain_lock)
{
	struct inet_frag_bucket *hb;

	hb = get_frag_bucket_locked(fq, f);
	hlist_del(&fq->list);
	q_flags(fq) |= INET_FRAG_COMPLETE;
	spin_unlock(&hb->chain_lock);

#ifdef HAVE_INET_FRAGS_WITH_RWLOCK
	read_unlock(&f->lock);
#endif
}

void inet_frag_kill(struct inet_frag_queue *fq, struct inet_frags *f)
{
	if (del_timer(&fq->timer))
		atomic_dec(&fq->refcnt);

	if (!(q_flags(fq) & INET_FRAG_COMPLETE)) {
		fq_unlink(fq, f);
		atomic_dec(&fq->refcnt);
	}
}

static inline void frag_kfree_skb(struct netns_frags *nf, struct inet_frags *f,
				  struct sk_buff *skb)
{
	if (f->skb_free)
		f->skb_free(skb);
	kfree_skb(skb);
}

void rpl_inet_frag_destroy(struct inet_frag_queue *q, struct inet_frags *f)
{
	struct sk_buff *fp;
	struct netns_frags *nf;
	unsigned int sum, sum_truesize = 0;

	WARN_ON(!(q_flags(q) & INET_FRAG_COMPLETE));
	WARN_ON(del_timer(&q->timer) != 0);

	/* Release all fragment data. */
	fp = q->fragments;
	nf = q->net;
	while (fp) {
		struct sk_buff *xp = fp->next;

		sum_truesize += fp->truesize;
		frag_kfree_skb(nf, f, fp);
		fp = xp;
	}
	sum = sum_truesize + f->qsize;

	if (f->destructor)
		f->destructor(q);
#ifdef HAVE_INET_FRAGS_WITH_FRAGS_WORK
	kmem_cache_free(f->frags_cachep, q);
#else
	kfree(q);
#endif

	sub_frag_mem_limit(nf, sum);
}

int inet_frag_evictor(struct netns_frags *nf, struct inet_frags *f, bool force)
{
#ifdef HAVE_INET_FRAGS_WITH_FRAGS_WORK
	int i;

	for (i = 0; i < INETFRAGS_HASHSZ ; i++)
		inet_evict_bucket(f, &f->hash[i]);

	return 0;
#else
	struct inet_frag_queue *q;
	int work, evicted = 0;

	work = frag_mem_limit(nf) - nf->low_thresh;
	while (work > 0 || force) {
		spin_lock(&nf->lru_lock);

		if (list_empty(&nf->lru_list)) {
			spin_unlock(&nf->lru_lock);
			break;
		}

		q = list_first_entry(&nf->lru_list,
				     struct inet_frag_queue, lru_list);
		atomic_inc(&q->refcnt);
		/* Remove q from list to avoid several CPUs grabbing it */
		list_del_init(&q->lru_list);

		spin_unlock(&nf->lru_lock);

		spin_lock(&q->lock);
		if (!(q->last_in & INET_FRAG_COMPLETE))
			inet_frag_kill(q, f);
		spin_unlock(&q->lock);

		if (atomic_dec_and_test(&q->refcnt))
			inet_frag_destroy(q, f, &work);
		evicted++;
	}

	return evicted;
#endif
}

static struct inet_frag_queue *inet_frag_intern(struct netns_frags *nf,
						struct inet_frag_queue *qp_in,
						struct inet_frags *f,
						void *arg)
{
	struct inet_frag_bucket *hb = get_frag_bucket_locked(qp_in, f);
	struct inet_frag_queue *qp;

#ifdef CONFIG_SMP
	/* With SMP race we have to recheck hash table, because
	 * such entry could have been created on other cpu before
	 * we acquired hash bucket lock.
	 */
	hlist_for_each_entry(qp, &hb->chain, list) {
		if (qp->net == nf && f->match(qp, arg)) {
			atomic_inc(&qp->refcnt);
			spin_unlock(&hb->chain_lock);
#ifdef HAVE_INET_FRAGS_WITH_RWLOCK
			read_unlock(&f->lock);
#endif
			q_flags(qp_in) |= INET_FRAG_COMPLETE;
			inet_frag_put(qp_in, f);
			return qp;
		}
	}
#endif /* CONFIG_SMP */
	qp = qp_in;
	if (!mod_timer(&qp->timer, jiffies + nf->timeout))
		atomic_inc(&qp->refcnt);

	atomic_inc(&qp->refcnt);
	hlist_add_head(&qp->list, &hb->chain);

	spin_unlock(&hb->chain_lock);
#ifdef HAVE_INET_FRAGS_WITH_RWLOCK
	read_unlock(&f->lock);
#endif

	return qp;
}

static struct inet_frag_queue *inet_frag_alloc(struct netns_frags *nf,
					       struct inet_frags *f,
					       void *arg)
{
	struct inet_frag_queue *q;

	if (frag_mem_limit(nf) > nf->high_thresh) {
#ifdef HAVE_INET_FRAGS_WITH_FRAGS_WORK
		inet_frag_schedule_worker(f);
#endif
		return NULL;
	}

#ifdef HAVE_INET_FRAGS_WITH_FRAGS_WORK
	q = kmem_cache_zalloc(f->frags_cachep, GFP_ATOMIC);
#else
	q = kzalloc(f->qsize, GFP_ATOMIC);
#endif
	if (!q)
		return NULL;

	q->net = nf;
	f->constructor(q, arg);
	add_frag_mem_limit(nf, f->qsize);

	setup_timer(&q->timer, f->frag_expire, (unsigned long)q);
	spin_lock_init(&q->lock);
	atomic_set(&q->refcnt, 1);

	return q;
}

static struct inet_frag_queue *inet_frag_create(struct netns_frags *nf,
						struct inet_frags *f,
						void *arg)
{
	struct inet_frag_queue *q;

	q = inet_frag_alloc(nf, f, arg);
	if (!q)
		return NULL;

	return inet_frag_intern(nf, q, f, arg);
}

struct inet_frag_queue *inet_frag_find(struct netns_frags *nf,
				       struct inet_frags *f, void *key,
				       unsigned int hash)
{
	struct inet_frag_bucket *hb;
	struct inet_frag_queue *q;
	int depth = 0;

#ifdef HAVE_INET_FRAGS_WITH_FRAGS_WORK
	if (frag_mem_limit(nf) > nf->low_thresh)
		inet_frag_schedule_worker(f);
#else
	if (frag_mem_limit(nf) > nf->high_thresh)
		inet_frag_evictor(nf, f, false);
#endif

	hash &= (INETFRAGS_HASHSZ - 1);
	hb = &f->hash[hash];

	spin_lock(&hb->chain_lock);
	hlist_for_each_entry(q, &hb->chain, list) {
		if (q->net == nf && f->match(q, key)) {
			atomic_inc(&q->refcnt);
			spin_unlock(&hb->chain_lock);
			return q;
		}
		depth++;
	}
	spin_unlock(&hb->chain_lock);

	if (depth <= INETFRAGS_MAXDEPTH)
		return inet_frag_create(nf, f, key);

#ifdef HAVE_INET_FRAGS_WITH_FRAGS_WORK
	if (inet_frag_may_rebuild(f)) {
		if (!f->rebuild)
			f->rebuild = true;
		inet_frag_schedule_worker(f);
	}
#endif

	return ERR_PTR(-ENOBUFS);
}

void inet_frag_maybe_warn_overflow(struct inet_frag_queue *q,
				   const char *prefix)
{
	static const char msg[] = "inet_frag_find: Fragment hash bucket"
		" list length grew over limit " __stringify(INETFRAGS_MAXDEPTH)
		". Dropping fragment.\n";

	if (PTR_ERR(q) == -ENOBUFS)
		net_dbg_ratelimited("%s%s", prefix, msg);
}

#endif /* !HAVE_CORRECT_MRU_HANDLING && OVS_FRAGMENT_BACKPORT */
