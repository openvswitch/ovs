#ifndef __LINUX_WORKQUEUE_H
#define __LINUX_WORKQUEUE_H 1

#include <linux/tqueue.h>

#define work_struct tq_struct

#define INIT_WORK(_work, _routine) \
	INIT_TQUEUE((_work), ((void *)_routine), (_work))

#define PREPARE_WORK(_work, _routine)    \
	PREPARE_TQUEUE((_work), ((void *)_routine), (_work))

#define schedule_work(_work) schedule_task(_work)

#define flush_scheduled_work() flush_scheduled_tasks()

/* There is no equivalent to cancel_work_sync() in 2.4, so just flush all 
 * pending tasks. */
#define cancel_work_sync(_work) flush_scheduled_tasks()

#endif 
