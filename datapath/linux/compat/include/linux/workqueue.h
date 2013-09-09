#ifndef __LINUX_WORKQUEUE_WRAPPER_H
#define __LINUX_WORKQUEUE_WRAPPER_H 1

#include_next <linux/workqueue.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#define queue_work(wq, dw) schedule_work(dw);
#endif

#endif
