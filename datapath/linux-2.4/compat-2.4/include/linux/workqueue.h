#ifndef __LINUX_WORKQUEUE_H
#define __LINUX_WORKQUEUE_H 1

#include <linux/tqueue.h>

#define work_struct tq_struct
#define INIT_WORK(_work, _routine) \
	INIT_TQUEUE((_work), (_routine), (_work))
#define PREPARE_WORK(_work, _routine)    \
	PREPARE_TQUEUE((_work), (_routine), (_work))
#define schedule_work schedule_task
#define flush_scheduled_work flush_scheduled_tasks

#endif 
