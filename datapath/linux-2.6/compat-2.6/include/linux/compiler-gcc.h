#ifndef __LINUX_COMPILER_H
#error "Please don't include <linux/compiler-gcc.h> directly, include <linux/compiler.h> instead."
#endif

#include_next <linux/compiler-gcc.h>

#ifndef __packed
#define __packed __attribute__((packed))
#endif
