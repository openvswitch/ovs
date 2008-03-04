/*
 * Distributed under the terms of the GNU GPL version 2.
 */

#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/tqueue.h>
#include <linux/smp.h>
#include <linux/completion.h>

#include "compat24.h"

#ifdef CONFIG_SMP
#error "SMP configurations not supported for RCU backport."
#endif

static int default_blimit = 10;
static int blimit;
static int qhimark = 10000;
static int qlowmark = 100;

static struct rcu_head *head, **tail;
static int qlen = 0;

static struct tq_struct rcu_task;

/*
 * Invoke the completed RCU callbacks. They are expected to be in
 * a per-cpu list.
 */
static void rcu_task_routine(void *unused)
{
	struct rcu_head *list, *next;
	int count = 0;

	local_irq_disable();
	list = head;
	head = NULL;
	tail = &head;
	local_irq_enable();

	while (list) {
		next = list->next;
		prefetch(next);
		list->func(list);
		list = next;
		if (++count >= blimit)
			break;
	}

	local_irq_disable();
	qlen -= count;
	local_irq_enable();
	if (blimit == INT_MAX && qlen <= qlowmark)
		blimit = default_blimit;

	if (head)
		schedule_task(&rcu_task);
}


static inline void force_quiescent_state(void)
{
	current->need_resched = 1;
}

/**
 * call_rcu - Queue an RCU callback for invocation after a grace period.
 * @rcu: structure to be used for queueing the RCU updates.
 * @func: actual update function to be invoked after the grace period
 *
 * The update function will be invoked some time after a full grace
 * period elapses, in other words after all currently executing RCU
 * read-side critical sections have completed.  RCU read-side critical
 * sections are delimited by rcu_read_lock() and rcu_read_unlock(),
 * and may be nested.
 */
void call_rcu(struct rcu_head *rcu, void (*func)(struct rcu_head *rcu))
{
	unsigned long flags;

	/* FIXME?  Following may be mildly expensive, may be worthwhile to
	   optimize common case. */
	schedule_task(&rcu_task);

	rcu->func = func;
	rcu->next = NULL;
	local_irq_save(flags);
	*tail = rcu;
	tail = &rcu->next;
	if (unlikely(++qlen > qhimark)) {
		blimit = INT_MAX;
		force_quiescent_state();
	}
	local_irq_restore(flags);
}
EXPORT_SYMBOL(call_rcu);

void rcu_init(void) 
{
	head = NULL;
	tail = &head;
	blimit = default_blimit;
	rcu_task.routine = rcu_task_routine;
}

struct rcu_synchronize {
	struct rcu_head head;
	struct completion completion;
};

/* Because of FASTCALL declaration of complete, we use this wrapper */
static void wakeme_after_rcu(struct rcu_head  *head)
{
	struct rcu_synchronize *rcu;

	rcu = container_of(head, struct rcu_synchronize, head);
	complete(&rcu->completion);
}

/**
 * synchronize_rcu - wait until a grace period has elapsed.
 *
 * Control will return to the caller some time after a full grace
 * period has elapsed, in other words after all currently executing RCU
 * read-side critical sections have completed.  RCU read-side critical
 * sections are delimited by rcu_read_lock() and rcu_read_unlock(),
 * and may be nested.
 *
 * If your read-side code is not protected by rcu_read_lock(), do -not-
 * use synchronize_rcu().
 */
void synchronize_rcu(void)
{
	struct rcu_synchronize rcu;

	init_completion(&rcu.completion);
	/* Will wake me after RCU finished */
	call_rcu(&rcu.head, wakeme_after_rcu);

	/* Wait for it */
	wait_for_completion(&rcu.completion);
}
EXPORT_SYMBOL(synchronize_rcu);
