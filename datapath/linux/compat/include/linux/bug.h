#ifndef __BUG_H_WRAPPER
#define __BUG_H_WRAPPER 1

#include_next <linux/bug.h>

#ifndef BUILD_BUG_ON_NOT_POWER_OF_2
/* Force a compilation error if a constant expression is not a power of 2 */
#define BUILD_BUG_ON_NOT_POWER_OF_2(n)			\
	BUILD_BUG_ON((n) == 0 || (((n) & ((n) - 1)) != 0))
#endif

#endif
