#ifndef COMPAT_H
#define COMPAT_H 1

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

#include "compat26.h"

#else

#include "compat24.h"

#endif


#endif /* compat.h */
