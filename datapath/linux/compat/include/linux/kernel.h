#ifndef __KERNEL_H_WRAPPER
#define __KERNEL_H_WRAPPER 1

#include_next <linux/kernel.h>
#ifndef HAVE_LOG2_H
#include <linux/log2.h>
#endif

#include <linux/version.h>

#ifndef USHRT_MAX
#define USHRT_MAX	((u16)(~0U))
#define SHRT_MAX	((s16)(USHRT_MAX>>1))
#define SHRT_MIN	((s16)(-SHRT_MAX - 1))
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

#ifndef rounddown
#define rounddown(x, y) (				\
{							\
	typeof(x) __x = (x);				\
	__x - (__x % (y));				\
}							\
)
#endif

/* U32_MAX was introduced in include/linux/kernel.h after version 3.14. */
#ifndef U32_MAX
#define U32_MAX		((u32)~0U)
#endif

#endif /* linux/kernel.h */
