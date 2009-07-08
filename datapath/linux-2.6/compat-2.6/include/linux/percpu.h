#ifndef __LINUX_PERCPU_H_WRAPPER
#define __LINUX_PERCPU_H_WRAPPER 1

#include_next <linux/percpu.h>

#ifndef percpu_ptr
#define percpu_ptr per_cpu_ptr
#endif

#endif /* linux/percpu.h wrapper */
