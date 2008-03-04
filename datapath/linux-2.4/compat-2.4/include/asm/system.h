#ifndef __ASM_SYSTEM_WRAPPER_H
#define __ASM_SYSTEM_WRAPPER_H 1

#include_next <asm/system.h>

#ifdef CONFIG_ALPHA
#define read_barrier_depends __asm__ __volatile__("mb": : :"memory")
#else
#define read_barrier_depends()	do { } while(0)
#endif

#ifdef CONFIG_SMP
#define smp_read_barrier_depends()	read_barrier_depends()
#else
#define smp_read_barrier_depends()	do { } while(0)
#endif

#endif
