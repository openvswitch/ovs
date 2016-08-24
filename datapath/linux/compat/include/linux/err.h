#ifndef __LINUX_ERR_WRAPPER_H
#define __LINUX_ERR_WRAPPER_H 1

#include_next <linux/err.h>

#ifndef HAVE_ERR_CAST
/**
 * ERR_CAST - Explicitly cast an error-valued pointer to another pointer type
 * @ptr: The pointer to cast.
 *
 * Explicitly cast an error-valued pointer to another pointer type in such a
 * way as to make it clear that's what's going on.
 */
static inline void *ERR_CAST(const void *ptr)
{
	/* cast away the const */
	return (void *) ptr;
}
#endif /* HAVE_ERR_CAST */

#ifndef HAVE_IS_ERR_OR_NULL
static inline bool __must_check IS_ERR_OR_NULL(__force const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}
#endif

#ifndef HAVE_PTR_ERR_OR_ZERO
static inline int __must_check PTR_ERR_OR_ZERO(__force const void *ptr)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	else
		return 0;
}
#endif
#endif
