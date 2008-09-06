#ifndef __LINUX_WORKQUEUE_WRAPPER_H
#define __LINUX_WORKQUEUE_WRAPPER_H 1

#include_next <linux/workqueue.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)

#ifdef __KERNEL__
/*
 * initialize a work-struct's func and data pointers:
 */
#undef PREPARE_WORK
#define PREPARE_WORK(_work, _func)                              \
        do {                                                    \
		(_work)->func = (void(*)(void*)) _func;		\
                (_work)->data = _work;				\
        } while (0)

/*
 * initialize all of a work-struct:
 */
#undef INIT_WORK
#define INIT_WORK(_work, _func)                                 \
        do {                                                    \
                INIT_LIST_HEAD(&(_work)->entry);                \
                (_work)->pending = 0;                           \
                PREPARE_WORK((_work), (_func));                 \
                init_timer(&(_work)->timer);                    \
        } while (0)

#endif /* __KERNEL__ */

#endif /* linux kernel < 2.6.20 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
/* There is no equivalent to cancel_work_sync() so just flush all
 * pending work. */
#define cancel_work_sync(_work) flush_scheduled_work()
#endif

#endif
