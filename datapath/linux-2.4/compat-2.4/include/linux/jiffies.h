#ifndef __LINUX_JIFFIES_WRAPPER_H
#define __LINUX_JIFFIES_WRAPPER_H 1

#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/timer.h>

extern unsigned long volatile jiffies;

/* 'jiffies_64' are not supported in 2.4 kernels.  Here we fake 
 * compatibility by always just returning the plain 'jiffies' value.
 * This means jiffies will wrap every 49 days. */
#define get_jiffies_64(void) ((u64)jiffies)

/* Same as above, but does so with platform independent 64bit types.
 * These must be used when utilizing jiffies_64 (i.e. return value of
 * get_jiffies_64() */
#define time_after64(a,b)       \
        (typecheck(__u64, a) && \
         typecheck(__u64, b) && \
         ((__s64)(b) - (__s64)(a) < 0))
#define time_before64(a,b)      time_after64(b,a)

#define time_after_eq64(a,b)    \
        (typecheck(__u64, a) && \
         typecheck(__u64, b) && \
         ((__s64)(a) - (__s64)(b) >= 0))
#define time_before_eq64(a,b)   time_after_eq64(b,a)

#endif
