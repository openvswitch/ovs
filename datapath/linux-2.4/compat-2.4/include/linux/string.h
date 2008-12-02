#ifndef __LINUX_STRING_WRAPPER_H
#define __LINUX_STRING_WRAPPER_H 1

#include_next <linux/string.h>

#ifndef __HAVE_ARCH_STRCSPN
size_t strcspn(const char *s, const char *reject);
#endif

size_t strlcpy(char *, const char *, size_t);

#endif /* linux/string.h */
