#ifndef __LINUX_CPUMASK_WRAPPER_H
#define __LINUX_CPUMASK_WRAPPER_H

#include_next <linux/cpumask.h>

/* for_each_cpu was renamed for_each_possible_cpu in 2.6.18. */
#ifndef for_each_possible_cpu
#define for_each_possible_cpu for_each_cpu
#endif

#endif /* linux/cpumask.h wrapper */
