#ifndef __ASM_GENERIC_BUG_WRAPPER_H
#define __ASM_GENERIC_BUG_WRAPPER_H

#include_next <asm-generic/bug.h>

#ifndef WARN_ON_ONCE
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

#endif
