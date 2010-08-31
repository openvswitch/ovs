#ifndef __LINUX_WORKQUEUE_WRAPPER_H
#define __LINUX_WORKQUEUE_WRAPPER_H 1

#include_next <linux/workqueue.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)

/* Older kernels have an implementation of work queues with some very bad
 * characteristics when trying to cancel work (potential deadlocks, use after
 * free, etc.  Here we directly use timers instead for delayed work.  It's not
 * optimal but it is better than the alternative.  Note that work queues
 * normally run in process context but this will cause them to operate in
 * softirq context.
 */

#include <linux/timer.h>

#undef DECLARE_DELAYED_WORK
#define DECLARE_DELAYED_WORK(n, f) \
	struct timer_list n = TIMER_INITIALIZER((void (*)(unsigned long))f, 0, 0)

#define schedule_delayed_work rpl_schedule_delayed_work
static inline int schedule_delayed_work(struct timer_list *timer, unsigned long delay)
{
	if (timer_pending(timer))
		return 0;

	mod_timer(timer, jiffies + delay);
	return 1;
}

#define cancel_delayed_work_sync rpl_cancel_delayed_work_sync
static inline int cancel_delayed_work_sync(struct timer_list *timer)
{
	return del_timer_sync(timer);
}

#endif /* kernel version < 2.6.23 */

#endif
