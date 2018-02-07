#ifndef _LINUX_TIMEKEEPING_WRAPPER_H
#define _LINUX_TIMEKEEPING_WRAPPER_H

#ifndef HAVE_KTIME_GET_TS64
#define ktime_get_ts64 ktime_get_ts
#define timespec64 timespec
#else
#include_next <linux/timekeeping.h>
#endif

#endif
