#ifndef __ASM_PERCPU_WRAPPER_H
#define __ASM_PERCPU_WRAPPER_H 1

#include_next <asm/percpu.h>

#if !defined this_cpu_ptr && !defined HAVE_THIS_CPU_PTR
#define this_cpu_ptr(ptr) per_cpu_ptr(ptr, smp_processor_id())
#endif

#endif
