#ifndef __GENETLINK_WRAPPER_H
#define __GENETLINK_WRAPPER_H 1

#include_next <linux/genetlink.h>

#ifdef CONFIG_PROVE_LOCKING
/* No version of the kernel has this function, but our locking scheme depends
 * on genl_mutex so for clarity we use it where appropriate. */
static inline int lockdep_genl_is_held(void)
{
	return 1;
}
#endif

#endif /* linux/genetlink.h wrapper */
