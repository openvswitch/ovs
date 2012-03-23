#ifndef __GENETLINK_WRAPPER_H
#define __GENETLINK_WRAPPER_H 1

#include <linux/version.h>
#include_next <linux/genetlink.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
#ifdef CONFIG_PROVE_LOCKING
static inline int lockdep_genl_is_held(void)
{
	return 1;
}
#endif
#endif

#ifndef genl_dereference
#include <linux/rcupdate.h>

#define genl_dereference(p)					\
	rcu_dereference_protected(p, lockdep_genl_is_held())
#endif

#endif /* linux/genetlink.h wrapper */
