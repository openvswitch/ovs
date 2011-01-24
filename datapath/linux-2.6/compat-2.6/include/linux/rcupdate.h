#ifndef __RCUPDATE_WRAPPER_H
#define __RCUPDATE_WRAPPER_H 1

#include_next <linux/rcupdate.h>

#ifndef rcu_dereference_check
#define rcu_dereference_check(p, c) rcu_dereference(p)
#endif

#ifndef rcu_dereference_protected
#define rcu_dereference_protected(p, c) (p)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
static inline int rcu_read_lock_held(void)
{
	return 1;
}
#endif

#endif /* linux/rcupdate.h wrapper */
