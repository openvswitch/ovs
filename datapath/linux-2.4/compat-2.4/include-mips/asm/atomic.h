#ifndef __ASM_MIPS_ATOMIC_H_WRAPPER
#define __ASM_MIPS_ATOMIC_H_WRAPPER 1

#include_next <asm/atomic.h>
#include <asm/system.h>

#error "Cribbed from linux-2.6/include/asm-mips but not tested."

#define atomic_cmpxchg(v, o, n) (cmpxchg(&((v)->counter), (o), (n)))

#endif /* asm/atomic.h */
