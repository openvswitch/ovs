#ifndef __LINUX_COMPILER_WRAPPER_H
#define __LINUX_COMPILER_WRAPPER_H 1

#include_next <linux/compiler.h>

#ifndef __percpu
#define __percpu
#endif

#ifndef __rcu
#define __rcu
#endif

#ifndef READ_ONCE
#define READ_ONCE(x) (x)
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, val)						\
do {									\
	*(volatile typeof(x) *)&(x) = (val);				\
} while (0)
#endif


#endif
