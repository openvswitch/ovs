#ifndef __LINUX_COMPILER_WRAPPER_H
#define __LINUX_COMPILER_WRAPPER_H 1

#include_next <linux/compiler.h>

#ifndef __percpu
#define __percpu
#endif

#ifndef __rcu
#define __rcu
#endif

#endif
