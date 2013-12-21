#ifndef __LINUX_BUG_WRAPPER_H
#define __LINUX_BUG_WRAPPER_H 1

#include_next <linux/bug.h>

#ifdef __CHECKER__
#ifndef BUILD_BUG_ON_INVALID
#define  BUILD_BUG_ON_INVALID(e) (0)
#endif

#endif /* __CHECKER__ */

#endif
