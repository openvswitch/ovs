#ifndef __COMPAT26_H
#define __COMPAT26_H 1

#include <linux/version.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
/*----------------------------------------------------------------------------
 * In 2.6.24, a namespace argument became required for dev_get_by_name. */
#define net_init NULL

#define dev_get_by_name(net, name) \
		dev_get_by_name((name))

#endif /* linux kernel <= 2.6.23 */


#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,22)
/*----------------------------------------------------------------------------
 * In 2.6.23, the last argument was dropped from kmem_cache_create. */
#define kmem_cache_create(n, s, a, f, c) \
		kmem_cache_create((n), (s), (a), (f), (c), NULL)

#endif /* linux kernel <= 2.6.22 */

#endif /* compat26.h */
