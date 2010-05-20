#ifndef __LINUX_SLAB_WRAPPER_H
#define __LINUX_SLAB_WRAPPER_H 1

#include_next <linux/slab.h>

#ifndef HAVE_KMEMDUP
extern void *kmemdup(const void *src, size_t len, gfp_t gfp);
#endif

#endif
