#ifndef __ASM_PERCPU_WRAPPER_H
#define __ASM_PERCPU_WRAPPER_H 1

#include_next <asm/percpu.h>

#ifndef this_cpu_ptr
#define this_cpu_ptr(ptr) per_cpu_ptr(ptr, smp_processor_id())
#endif

#endif
