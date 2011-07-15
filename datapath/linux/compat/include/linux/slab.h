#ifndef __LINUX_SLAB_WRAPPER_H
#define __LINUX_SLAB_WRAPPER_H 1

#include_next <linux/slab.h>

#ifndef HAVE_KMEMDUP
extern void *kmemdup(const void *src, size_t len, gfp_t gfp);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#define kmem_cache_create(n, s, a, f, c) kmem_cache_create(n, s, a, f, c, NULL)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
static inline void *rpl_kzalloc(size_t size, gfp_t flags)
{
	return kzalloc(size, flags & ~__GFP_ZERO);
}
#define kzalloc rpl_kzalloc

static inline void *rpl_kmalloc(size_t size, gfp_t flags)
{
	if (flags & __GFP_ZERO)
		return kzalloc(size, flags);

	return kmalloc(size, flags);
}
#define kmalloc rpl_kmalloc
#endif

#endif
