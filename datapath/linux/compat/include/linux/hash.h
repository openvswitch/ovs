#ifndef _LINUX_HASH_WRAPPER_H
#define _LINUX_HASH_WRAPPER_H

#include_next <linux/hash.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
#include <asm/hash.h>

struct fast_hash_ops {
	u32 (*hash)(const void *data, u32 len, u32 seed);
	u32 (*hash2)(const u32 *data, u32 len, u32 seed);
};

/**
 *	arch_fast_hash - Caclulates a hash over a given buffer that can have
 *			 arbitrary size. This function will eventually use an
 *			 architecture-optimized hashing implementation if
 *			 available, and trades off distribution for speed.
 *
 *	@data: buffer to hash
 *	@len: length of buffer in bytes
 *	@seed: start seed
 *
 *	Returns 32bit hash.
 */
extern u32 arch_fast_hash(const void *data, u32 len, u32 seed);

/**
 *	arch_fast_hash2 - Caclulates a hash over a given buffer that has a
 *			  size that is of a multiple of 32bit words. This
 *			  function will eventually use an architecture-
 *			  optimized hashing implementation if available,
 *			  and trades off distribution for speed.
 *
 *	@data: buffer to hash (must be 32bit padded)
 *	@len: number of 32bit words
 *	@seed: start seed
 *
 *	Returns 32bit hash.
 */
extern u32 arch_fast_hash2(const u32 *data, u32 len, u32 seed);
#endif /* < 3.14 */

#endif /* _LINUX_HASH_WRAPPER_H */
