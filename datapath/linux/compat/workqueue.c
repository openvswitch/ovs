/*
 * Derived from the kernel/workqueue.c
 *
 * This is the generic async execution mechanism.  Work items as are
 * executed in process context.
 *
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/signal.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/hardirq.h>
#include <linux/mempolicy.h>
#include <linux/kallsyms.h>
#include <linux/debug_locks.h>
#include <linux/lockdep.h>
#include <linux/idr.h>

static spinlock_t wq_lock;
static struct list_head workq;
static wait_queue_head_t more_work;
static struct task_struct *workq_thread;
static struct work_struct *current_work;

static void queue_work(struct work_struct *work)
{
	unsigned long flags;

	spin_lock_irqsave(&wq_lock, flags);
	list_add_tail(&work->entry, &workq);
	wake_up(&more_work);
	spin_unlock_irqrestore(&wq_lock, flags);
}

static void _delayed_work_timer_fn(unsigned long __data)
{
	struct delayed_work *dwork = (struct delayed_work *)__data;
	queue_work(&dwork->work);
}

static void __queue_delayed_work(struct delayed_work *dwork,
		unsigned long delay)
{
	struct timer_list *timer = &dwork->timer;
	struct work_struct *work = &dwork->work;

	BUG_ON(timer_pending(timer));
	BUG_ON(!list_empty(&work->entry));

	timer->expires = jiffies + delay;
	timer->data = (unsigned long)dwork;
	timer->function = _delayed_work_timer_fn;

	add_timer(timer);
}

int schedule_delayed_work(struct delayed_work *dwork, unsigned long delay)
{
	if (test_and_set_bit(WORK_STRUCT_PENDING, work_data_bits(&dwork->work)))
		return 0;

	if (delay == 0)
		queue_work(&dwork->work);
	else
		__queue_delayed_work(dwork, delay);

	return 1;
}

struct wq_barrier {
	struct work_struct      work;
	struct completion       done;
};

static void wq_barrier_func(struct work_struct *work)
{
	struct wq_barrier *barr = container_of(work, struct wq_barrier, work);
	complete(&barr->done);
}

static void workqueue_barrier(struct work_struct *work)
{
	bool need_barrier;
	struct wq_barrier barr;

	spin_lock_irq(&wq_lock);
	if (current_work != work)
		need_barrier = false;
	else {
		INIT_WORK(&barr.work, wq_barrier_func);
		init_completion(&barr.done);
		list_add(&barr.work.entry, &workq);
		wake_up(&more_work);
		need_barrier = true;
	}
	spin_unlock_irq(&wq_lock);

	if (need_barrier)
		wait_for_completion(&barr.done);
}

static int try_to_grab_pending(struct work_struct *work)
{
	int ret;

	BUG_ON(in_interrupt());

	if (!test_and_set_bit(WORK_STRUCT_PENDING, work_data_bits(work)))
		return 0;

	spin_lock_irq(&wq_lock);
	if (!list_empty(&work->entry)) {
		list_del_init(&work->entry);
		ret = 0;
	} else
		/* Already executed, retry. */
		ret = -1;
	spin_unlock_irq(&wq_lock);

	return ret;
}

static int __cancel_work_timer(struct work_struct *work,
			       struct timer_list *timer)
{
	int ret;

	for (;;) {
		ret = (timer && likely(del_timer(timer)));
		if (ret) /* Was active timer, return true. */
			break;

		/* Inactive timer case */
		ret = try_to_grab_pending(work);
		if (!ret)
			break;
	}
	workqueue_barrier(work);
	work_clear_pending(work);
	return ret;
}

int cancel_delayed_work_sync(struct delayed_work *dwork)
{
	return __cancel_work_timer(&dwork->work, &dwork->timer);
}

static void run_workqueue(void)
{
	spin_lock_irq(&wq_lock);
	while (!list_empty(&workq)) {
		struct work_struct *work = list_entry(workq.next,
				struct work_struct, entry);

		work_func_t f = work->func;
		list_del_init(workq.next);
		current_work = work;
		spin_unlock_irq(&wq_lock);

		work_clear_pending(work);
		f(work);

		BUG_ON(in_interrupt());
		spin_lock_irq(&wq_lock);
		current_work = NULL;
	}
	spin_unlock_irq(&wq_lock);
}

static int worker_thread(void *dummy)
{
	for (;;) {
		wait_event_interruptible(more_work,
				(kthread_should_stop() || !list_empty(&workq)));

		if (kthread_should_stop())
			break;

		run_workqueue();
	}

	return 0;
}

int __init ovs_workqueues_init(void)
{
	spin_lock_init(&wq_lock);
	INIT_LIST_HEAD(&workq);
	init_waitqueue_head(&more_work);

	workq_thread = kthread_create(worker_thread, NULL, "ovs_workq");
	if (IS_ERR(workq_thread))
		return PTR_ERR(workq_thread);

	wake_up_process(workq_thread);
	return 0;
}

void  ovs_workqueues_exit(void)
{
	BUG_ON(!list_empty(&workq));
	kthread_stop(workq_thread);
}
