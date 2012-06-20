#ifndef __LINUX_WORKQUEUE_WRAPPER_H
#define __LINUX_WORKQUEUE_WRAPPER_H 1

#include <linux/timer.h>

int __init ovs_workqueues_init(void);
void ovs_workqueues_exit(void);

/* Older kernels have an implementation of work queues with some very bad
 * characteristics when trying to cancel work (potential deadlocks, use after
 * free, etc.  Therefore we implement simple ovs specific work queue using
 * single worker thread. work-queue API are kept similar for compatibility.
 * It seems it is useful even on newer kernel. As it can avoid system wide
 * freeze in event of softlockup due to workq blocked on genl_lock.
 */

struct work_struct;

typedef void (*work_func_t)(struct work_struct *work);

#define work_data_bits(work) ((unsigned long *)(&(work)->data))

struct work_struct {
#define WORK_STRUCT_PENDING 0           /* T if work item pending execution */
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
#ifdef CONFIG_LOCKDEP
	struct lockdep_map lockdep_map;
#endif
};

#define WORK_DATA_INIT()        ATOMIC_LONG_INIT(0)

#define work_clear_pending(work)				\
	clear_bit(WORK_STRUCT_PENDING, work_data_bits(work))

struct delayed_work {
	struct work_struct work;
	struct timer_list timer;
};

#define __WORK_INITIALIZER(n, f) {				\
	.data = WORK_DATA_INIT(),				\
	.entry  = { &(n).entry, &(n).entry },			\
	.func = (f),						\
}

#define __DELAYED_WORK_INITIALIZER(n, f) {			\
	.work = __WORK_INITIALIZER((n).work, (f)),		\
	.timer = TIMER_INITIALIZER(NULL, 0, 0),			\
}

#define DECLARE_DELAYED_WORK(n, f)				\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f)

#define schedule_delayed_work rpl_schedule_delayed_work
int schedule_delayed_work(struct delayed_work *dwork, unsigned long delay);

#define cancel_delayed_work_sync rpl_cancel_delayed_work_sync
int cancel_delayed_work_sync(struct delayed_work *dwork);

#define INIT_WORK(_work, _func)					\
	do {							\
		(_work)->data = (atomic_long_t) WORK_DATA_INIT();	\
		INIT_LIST_HEAD(&(_work)->entry);		\
		(_work)->func = (_func);			\
	} while (0)

extern void flush_scheduled_work(void);

#endif
