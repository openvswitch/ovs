#ifndef __LINUX_CACHE_WRAPPER_H
#define __LINUX_CACHE_WRAPPER_H 1

#include_next <linux/cache.h>

/* Upstream commit c74ba8b3480d ("arch: Introduce post-init read-only memory")
 * introduced the __ro_after_init attribute, however it wasn't applied to
 * generic netlink sockets until commit 34158151d2aa ("netfilter: cttimeout:
 * use nf_ct_iterate_cleanup_net to unlink timeout objs"). Using it on
 * genetlink before the latter commit leads to crash on module unload.
 * For kernels < 4.10, define it as empty. */
#ifdef HAVE_GENL_FAMILY_LIST
#ifdef __ro_after_init
#undef __ro_after_init
#endif /* #ifdef __ro_after_init */
#define __ro_after_init
#else
#ifndef __ro_after_init
#define __ro_after_init
#endif /* #ifndef __ro_after_init */
#endif /* #ifdef HAVE_GENL_FAMILY_LIST */

#endif
