#ifndef __LINUX_SLAB_WRAPPER_H
#define __LINUX_SLAB_WRAPPER_H 1

/* Kluge to let "struct kmem_cache" work in both 2.4 and 2.6. */
#define kmem_cache_s kmem_cache

#include_next <linux/slab.h>

static inline void *kzalloc(size_t size, gfp_t flags)
{
	void *p = kmalloc(size, flags);
	if (p)
		memset(p, 0, size);
	return p;
}

/* Mega-kluge to wrap 2.4 kmem_cache_create for compatibility with 2.6. */
#ifdef kmem_cache_create
#undef kmem_cache_create
#define kmem_cache_create(name, size, align, flags, ctor) \
	compat_kmem_cache_create(name, size, align, flags, ctor)
static inline struct kmem_cache *
compat_kmem_cache_create(const char *name, size_t size,
			 size_t align, unsigned long flags,
			 void (*ctor)(void *, struct kmem_cache *,
					unsigned long)) 
{
	return (_set_ver(kmem_cache_create))(name, size, align, flags, ctor,
					NULL);
}
#else
#define kmem_cache_create(name, size, align, flags, ctor) \
	kmem_cache_create(name, size, align, flags, ctor, NULL)
#endif /* kmem_cache_create */

static inline void *kmem_cache_zalloc(struct kmem_cache *k, gfp_t flags)
{
	void *p = kmem_cache_alloc(k, flags);
	if (p)
		memset(p, 0, kmem_cache_size(k));
	return p;
}

#endif
