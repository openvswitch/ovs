#ifndef __ASM_MIPS_BARRIER_H_WRAPPER
#define __ASM_MIPS_BARRIER_H_WRAPPER 1

#include <asm/system.h>

/* Not sure whether these really need to be defined, but the conservative
 * choice seems to be to define them. */
#define CONFIG_WEAK_ORDERING 1
#define CONFIG_WEAK_REORDERING_BEYOND_LLSC 1

#if defined(CONFIG_WEAK_ORDERING) && defined(CONFIG_SMP)
#define __WEAK_ORDERING_MB	"       sync	\n"
#else
#define __WEAK_ORDERING_MB	"		\n"
#endif
#if defined(CONFIG_WEAK_REORDERING_BEYOND_LLSC) && defined(CONFIG_SMP)
#define __WEAK_LLSC_MB		"       sync	\n"
#else
#define __WEAK_LLSC_MB		"		\n"
#endif

#define smp_mb()	__asm__ __volatile__(__WEAK_ORDERING_MB : : :"memory")
#define smp_rmb()	__asm__ __volatile__(__WEAK_ORDERING_MB : : :"memory")
#define smp_wmb()	__asm__ __volatile__(__WEAK_ORDERING_MB : : :"memory")


#endif /* asm/barrier.h */
