#ifndef __ASM_I386_ATOMIC_WRAPPER_H
#define __ASM_I386_ATOMIC_WRAPPER_H 1

#include_next <asm/atomic.h>

#include <asm/system.h>

#define atomic_cmpxchg(v, old, new) (cmpxchg(&((v)->counter), (old), (new)))

#endif /* atomic.h */
