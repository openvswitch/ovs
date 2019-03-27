#ifndef OVS_MM_H
#define OVS_MM_H

#include <linux/overflow.h>

#ifndef HAVE_KVMALLOC_ARRAY
#ifndef HAVE_KVMALLOC_NODE
extern void *vmalloc_node(unsigned long size, int node);
#define kvmalloc_node(a, b, c) vmalloc_node(a, c)
#else
extern void *kvmalloc_node(size_t size, gfp_t flags, int node);
#endif /* HAVE_KVMALLOC_NODE */
static inline void *kvmalloc(size_t size, gfp_t flags)
{
	return kvmalloc_node(size, flags, NUMA_NO_NODE);
}
static inline void *kvzalloc_node(size_t size, gfp_t flags, int node)
{
	return kvmalloc_node(size, flags | __GFP_ZERO, node);
}
static inline void *kvzalloc(size_t size, gfp_t flags)
{
	return kvmalloc(size, flags | __GFP_ZERO);
}

static inline void *kvmalloc_array(size_t n, size_t size, gfp_t flags)
{
	size_t bytes;

	if (unlikely(check_mul_overflow(n, size, &bytes)))
		return NULL;

	return kvmalloc(bytes, flags);
}

static inline void *kvcalloc(size_t n, size_t size, gfp_t flags)
{
	return kvmalloc_array(n, size, flags | __GFP_ZERO);
}

#endif
#include_next <linux/mm.h>
#endif /* OVS_MM_H */

