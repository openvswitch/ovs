#ifndef __LINUX_SPINLOCK_WRAPPER_H
#define __LINUX_SPINLOCK_WRAPPER_H 1

#include_next <linux/spinlock.h>

#define DEFINE_SPINLOCK(x)	spinlock_t x = SPIN_LOCK_UNLOCKED

#endif /* linux/spinlock.h */
