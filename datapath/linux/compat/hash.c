/* General purpose hashing library
 *
 * That's a start of a kernel hashing library, which can be extended
 * with further algorithms in future. arch_fast_hash{2,}() will
 * eventually resolve to an architecture optimized implementation.
 *
 * Copyright 2013 Francesco Fusco <ffusco@redhat.com>
 * Copyright 2013 Daniel Borkmann <dborkman@redhat.com>
 * Copyright 2013 Thomas Graf <tgraf@redhat.com>
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)

#include <linux/cache.h>
#include <linux/compiler.h>
#include <linux/jhash.h>
#include <linux/hash.h>
#include <linux/kernel.h>

static struct fast_hash_ops arch_hash_ops __read_mostly = {
	.hash  = jhash,
	.hash2 = jhash2,
};

static bool arch_inited __read_mostly;
static void init_arch(void)
{
	if (likely(arch_inited))
		return;

	setup_arch_fast_hash(&arch_hash_ops);
	arch_inited = true;
}

u32 arch_fast_hash(const void *data, u32 len, u32 seed)
{
	init_arch();

	return arch_hash_ops.hash(data, len, seed);
}

u32 arch_fast_hash2(const u32 *data, u32 len, u32 seed)
{
	init_arch();

	return arch_hash_ops.hash2(data, len, seed);
}

#endif /* < 3.14 */
