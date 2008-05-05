#ifndef __LINUX_SCHED_WRAPPER_H
#define __LINUX_SCHED_WRAPPER_H 1

#include_next <linux/sched.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,21)

#if CONFIG_SMP
extern void set_cpus_allowed(struct task_struct *p, unsigned long new_mask);
#else
# define set_cpus_allowed(p, new_mask) do { } while (0)
#endif

#endif	/* linux kernel < 2.4.21 */

#endif
