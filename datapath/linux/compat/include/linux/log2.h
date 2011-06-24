#ifndef __LINUX_LOG2_WRAPPER
#define __LINUX_LOG2_WRAPPER

#ifdef HAVE_LOG2_H
#include_next <linux/log2.h>
#else
/* This is very stripped down because log2.h has far too many dependencies. */

extern __attribute__((const, noreturn))
int ____ilog2_NaN(void);

#define ilog2(n) ((n) == 4 ? 2 : \
		  (n) == 8 ? 3 : \
		  ____ilog2_NaN())
#endif

#endif
