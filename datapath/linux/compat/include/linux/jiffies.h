#ifndef __LINUX_JIFFIES_WRAPPER_H
#define __LINUX_JIFFIES_WRAPPER_H 1

#include_next <linux/jiffies.h>

#include <linux/version.h>

/* Same as above, but does so with platform independent 64bit types.
 * These must be used when utilizing jiffies_64 (i.e. return value of
 * get_jiffies_64() */

#ifndef time_after64
#define time_after64(a, b)       \
	(typecheck(__u64, a) && \
	typecheck(__u64, b) && \
	((__s64)(b) - (__s64)(a) < 0))
#endif

#ifndef time_before64
#define time_before64(a, b)      time_after64(b, a)
#endif

#ifndef time_after_eq64
#define time_after_eq64(a, b)    \
	(typecheck(__u64, a) && \
	typecheck(__u64, b) && \
	((__s64)(a) - (__s64)(b) >= 0))
#endif

#ifndef time_before_eq64
#define time_before_eq64(a, b)   time_after_eq64(b, a)
#endif

#endif
