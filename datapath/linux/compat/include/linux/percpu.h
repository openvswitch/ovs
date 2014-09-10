#ifndef __LINUX_PERCPU_WRAPPER_H
#define __LINUX_PERCPU_WRAPPER_H 1

#include_next <linux/percpu.h>

#if !defined this_cpu_read
#define this_cpu_read(ptr) percpu_read(ptr)
#endif

#if !defined this_cpu_inc
#define this_cpu_inc(ptr) percpu_add(ptr, 1)
#endif

#if !defined this_cpu_dec
#define this_cpu_dec(ptr) percpu_sub(ptr, 1)
#endif

#endif
