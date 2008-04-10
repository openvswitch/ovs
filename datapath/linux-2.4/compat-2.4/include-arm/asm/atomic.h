#ifndef __ASM_ARM_ATOMIC_H_WRAPPER
#define __ASM_ARM_ATOMIC_H_WRAPPER 1

#include_next <asm/atomic.h>

#ifdef __KERNEL__

#if __LINUX_ARM_ARCH__ >= 6

static inline int atomic_cmpxchg(atomic_t *ptr, int old, int new)
{
	unsigned long oldval, res;

	do {
		__asm__ __volatile__("@ atomic_cmpxchg\n"
		"ldrex	%1, [%2]\n"
		"mov	%0, #0\n"
		"teq	%1, %3\n"
		"strexeq %0, %4, [%2]\n"
		    : "=&r" (res), "=&r" (oldval)
		    : "r" (&ptr->counter), "Ir" (old), "r" (new)
		    : "cc");
	} while (res);

	return oldval;
}

#else /* ARM_ARCH_6 */

#include <asm/system.h>

#ifdef CONFIG_SMP
#error SMP not supported on pre-ARMv6 CPUs
#endif

static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
	int ret;
	unsigned long flags;

	local_irq_save(flags);
	ret = v->counter;
	if (likely(ret == old))
		v->counter = new;
	local_irq_restore(flags);

	return ret;
}

#endif /* __LINUX_ARM_ARCH__ */

#endif /* __KERNEL__ */

#endif /* asm/atomic.h */
