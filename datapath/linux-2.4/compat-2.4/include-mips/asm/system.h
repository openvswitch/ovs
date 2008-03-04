#ifndef __ASM_MIPS_SYSTEM_H_WRAPPER
#define __ASM_MIPS_SYSTEM_H_WRAPPER 1

#include_next <asm/system.h>

#error "Cribbed from linux-2.6/include/asm-mips/system.h but untested."

#define __HAVE_ARCH_CMPXCHG 1

static inline unsigned long __cmpxchg_u32(volatile int * m, unsigned long old,
	unsigned long new)
{
	__u32 retval;

	if (cpu_has_llsc && R10000_LLSC_WAR) {
		__asm__ __volatile__(
		"	.set	push					\n"
		"	.set	noat					\n"
		"	.set	mips3					\n"
		"1:	ll	%0, %2			# __cmpxchg_u32	\n"
		"	bne	%0, %z3, 2f				\n"
		"	.set	mips0					\n"
		"	move	$1, %z4					\n"
		"	.set	mips3					\n"
		"	sc	$1, %1					\n"
		"	beqzl	$1, 1b					\n"
		"2:							\n"
		"	.set	pop					\n"
		: "=&r" (retval), "=R" (*m)
		: "R" (*m), "Jr" (old), "Jr" (new)
		: "memory");
	} else if (cpu_has_llsc) {
		__asm__ __volatile__(
		"	.set	push					\n"
		"	.set	noat					\n"
		"	.set	mips3					\n"
		"1:	ll	%0, %2			# __cmpxchg_u32	\n"
		"	bne	%0, %z3, 2f				\n"
		"	.set	mips0					\n"
		"	move	$1, %z4					\n"
		"	.set	mips3					\n"
		"	sc	$1, %1					\n"
		"	beqz	$1, 3f					\n"
		"2:							\n"
		"	.subsection 2					\n"
		"3:	b	1b					\n"
		"	.previous					\n"
		"	.set	pop					\n"
		: "=&r" (retval), "=R" (*m)
		: "R" (*m), "Jr" (old), "Jr" (new)
		: "memory");
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		retval = *m;
		if (retval == old)
			*m = new;
		raw_local_irq_restore(flags);	/* implies memory barrier  */
	}

	smp_llsc_mb();

	return retval;
}

static inline unsigned long __cmpxchg_u32_local(volatile int * m,
	unsigned long old, unsigned long new)
{
	__u32 retval;

	if (cpu_has_llsc && R10000_LLSC_WAR) {
		__asm__ __volatile__(
		"	.set	push					\n"
		"	.set	noat					\n"
		"	.set	mips3					\n"
		"1:	ll	%0, %2			# __cmpxchg_u32	\n"
		"	bne	%0, %z3, 2f				\n"
		"	.set	mips0					\n"
		"	move	$1, %z4					\n"
		"	.set	mips3					\n"
		"	sc	$1, %1					\n"
		"	beqzl	$1, 1b					\n"
		"2:							\n"
		"	.set	pop					\n"
		: "=&r" (retval), "=R" (*m)
		: "R" (*m), "Jr" (old), "Jr" (new)
		: "memory");
	} else if (cpu_has_llsc) {
		__asm__ __volatile__(
		"	.set	push					\n"
		"	.set	noat					\n"
		"	.set	mips3					\n"
		"1:	ll	%0, %2			# __cmpxchg_u32	\n"
		"	bne	%0, %z3, 2f				\n"
		"	.set	mips0					\n"
		"	move	$1, %z4					\n"
		"	.set	mips3					\n"
		"	sc	$1, %1					\n"
		"	beqz	$1, 1b					\n"
		"2:							\n"
		"	.set	pop					\n"
		: "=&r" (retval), "=R" (*m)
		: "R" (*m), "Jr" (old), "Jr" (new)
		: "memory");
	} else {
		unsigned long flags;

		local_irq_save(flags);
		retval = *m;
		if (retval == old)
			*m = new;
		local_irq_restore(flags);	/* implies memory barrier  */
	}

	return retval;
}

#ifdef CONFIG_64BIT
static inline unsigned long __cmpxchg_u64(volatile int * m, unsigned long old,
	unsigned long new)
{
	__u64 retval;

	if (cpu_has_llsc && R10000_LLSC_WAR) {
		__asm__ __volatile__(
		"	.set	push					\n"
		"	.set	noat					\n"
		"	.set	mips3					\n"
		"1:	lld	%0, %2			# __cmpxchg_u64	\n"
		"	bne	%0, %z3, 2f				\n"
		"	move	$1, %z4					\n"
		"	scd	$1, %1					\n"
		"	beqzl	$1, 1b					\n"
		"2:							\n"
		"	.set	pop					\n"
		: "=&r" (retval), "=R" (*m)
		: "R" (*m), "Jr" (old), "Jr" (new)
		: "memory");
	} else if (cpu_has_llsc) {
		__asm__ __volatile__(
		"	.set	push					\n"
		"	.set	noat					\n"
		"	.set	mips3					\n"
		"1:	lld	%0, %2			# __cmpxchg_u64	\n"
		"	bne	%0, %z3, 2f				\n"
		"	move	$1, %z4					\n"
		"	scd	$1, %1					\n"
		"	beqz	$1, 3f					\n"
		"2:							\n"
		"	.subsection 2					\n"
		"3:	b	1b					\n"
		"	.previous					\n"
		"	.set	pop					\n"
		: "=&r" (retval), "=R" (*m)
		: "R" (*m), "Jr" (old), "Jr" (new)
		: "memory");
	} else {
		unsigned long flags;

		raw_local_irq_save(flags);
		retval = *m;
		if (retval == old)
			*m = new;
		raw_local_irq_restore(flags);	/* implies memory barrier  */
	}

	smp_llsc_mb();

	return retval;
}

static inline unsigned long __cmpxchg_u64_local(volatile int * m,
	unsigned long old, unsigned long new)
{
	__u64 retval;

	if (cpu_has_llsc && R10000_LLSC_WAR) {
		__asm__ __volatile__(
		"	.set	push					\n"
		"	.set	noat					\n"
		"	.set	mips3					\n"
		"1:	lld	%0, %2			# __cmpxchg_u64	\n"
		"	bne	%0, %z3, 2f				\n"
		"	move	$1, %z4					\n"
		"	scd	$1, %1					\n"
		"	beqzl	$1, 1b					\n"
		"2:							\n"
		"	.set	pop					\n"
		: "=&r" (retval), "=R" (*m)
		: "R" (*m), "Jr" (old), "Jr" (new)
		: "memory");
	} else if (cpu_has_llsc) {
		__asm__ __volatile__(
		"	.set	push					\n"
		"	.set	noat					\n"
		"	.set	mips3					\n"
		"1:	lld	%0, %2			# __cmpxchg_u64	\n"
		"	bne	%0, %z3, 2f				\n"
		"	move	$1, %z4					\n"
		"	scd	$1, %1					\n"
		"	beqz	$1, 1b					\n"
		"2:							\n"
		"	.set	pop					\n"
		: "=&r" (retval), "=R" (*m)
		: "R" (*m), "Jr" (old), "Jr" (new)
		: "memory");
	} else {
		unsigned long flags;

		local_irq_save(flags);
		retval = *m;
		if (retval == old)
			*m = new;
		local_irq_restore(flags);	/* implies memory barrier  */
	}

	return retval;
}

#else
extern unsigned long __cmpxchg_u64_unsupported_on_32bit_kernels(
	volatile int * m, unsigned long old, unsigned long new);
#define __cmpxchg_u64 __cmpxchg_u64_unsupported_on_32bit_kernels
extern unsigned long __cmpxchg_u64_local_unsupported_on_32bit_kernels(
	volatile int * m, unsigned long old, unsigned long new);
#define __cmpxchg_u64_local __cmpxchg_u64_local_unsupported_on_32bit_kernels
#endif

/* This function doesn't exist, so you'll get a linker error
   if something tries to do an invalid cmpxchg().  */
extern void __cmpxchg_called_with_bad_pointer(void);

static inline unsigned long __cmpxchg(volatile void * ptr, unsigned long old,
	unsigned long new, int size)
{
	switch (size) {
	case 4:
		return __cmpxchg_u32(ptr, old, new);
	case 8:
		return __cmpxchg_u64(ptr, old, new);
	}
	__cmpxchg_called_with_bad_pointer();
	return old;
}

static inline unsigned long __cmpxchg_local(volatile void * ptr,
	unsigned long old, unsigned long new, int size)
{
	switch (size) {
	case 4:
		return __cmpxchg_u32_local(ptr, old, new);
	case 8:
		return __cmpxchg_u64_local(ptr, old, new);
	}
	__cmpxchg_called_with_bad_pointer();
	return old;
}

#define cmpxchg(ptr,old,new) \
	((__typeof__(*(ptr)))__cmpxchg((ptr), \
		(unsigned long)(old), (unsigned long)(new),sizeof(*(ptr))))

#define cmpxchg_local(ptr,old,new) \
	((__typeof__(*(ptr)))__cmpxchg_local((ptr), \
		(unsigned long)(old), (unsigned long)(new),sizeof(*(ptr))))

#endif /* asm/system.h */
