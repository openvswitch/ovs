#ifndef _ASM_HASH_WRAPPER_H
#define _ASM_HASH_WRAPPER_H

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#include_next <asm/hash.h>
#else

struct fast_hash_ops;
#ifdef CONFIG_X86
extern void setup_arch_fast_hash(struct fast_hash_ops *ops);
#else
static inline void setup_arch_fast_hash(struct fast_hash_ops *ops) { }
#endif

#endif /* < 3.14 */

#endif /* _ASM_HASH_WRAPPER_H */
