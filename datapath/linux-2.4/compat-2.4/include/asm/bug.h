#ifndef _ASM_GENERIC_BUG_H
#define _ASM_GENERIC_BUG_H

#include <linux/compiler.h>

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

#endif
