#ifndef __LINUX_STDDEF_WRAPPER_H
#define __LINUX_STDDEF_WRAPPER_H 1

#include_next <linux/stddef.h>

#ifdef __KERNEL__

#ifndef offsetofend
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof(((TYPE *)0)->MEMBER))
#endif

#endif /* __KERNEL__ */

#endif
