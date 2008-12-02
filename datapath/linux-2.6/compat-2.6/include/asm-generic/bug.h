#ifndef __ASM_GENERIC_BUG_WRAPPER_H
#define __ASM_GENERIC_BUG_WRAPPER_H

#include_next <asm-generic/bug.h>

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)

#define WARN_ON_ONCE(condition)	({				\
	static int __warned;					\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once) && !__warned) {		\
		WARN_ON(1);					\
		__warned = 1;					\
	}							\
	unlikely(__ret_warn_once);				\
})

#endif /* linux kernel < 2.6.19 */

#endif
