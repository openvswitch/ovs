#ifndef __LINUX_DELAY_WRAPPER_H
#define __LINUX_DELAY_WRAPPER_H 1

#include_next <linux/delay.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,29)
#include <linux/time.h>
#include <linux/sched.h>
#include <asm/param.h>
/*
 * We define MAX_MSEC_OFFSET as the maximal value that can be accepted by
 * msecs_to_jiffies() without risking a multiply overflow. This function
 * returns MAX_JIFFY_OFFSET for arguments above those values.
 */

#if HZ <= 1000 && !(1000 % HZ)
#  define MAX_MSEC_OFFSET \
	(ULONG_MAX - (1000 / HZ) + 1)
#elif HZ > 1000 && !(HZ % 1000)
#  define MAX_MSEC_OFFSET \
	(ULONG_MAX / (HZ / 1000))
#else
#  define MAX_MSEC_OFFSET \
	((ULONG_MAX - 999) / HZ)
#endif

/*
 * Convert jiffies to milliseconds and back.
 *
 * Avoid unnecessary multiplications/divisions in the
 * two most common HZ cases:
 */
static inline unsigned int jiffies_to_msecs(const unsigned long j)
{
#if HZ <= 1000 && !(1000 % HZ)
	return (1000 / HZ) * j;
#elif HZ > 1000 && !(HZ % 1000)
	return (j + (HZ / 1000) - 1)/(HZ / 1000);
#else
	return (j * 1000) / HZ;
#endif
}

static inline unsigned long msecs_to_jiffies(const unsigned int m)
{
	if (MAX_MSEC_OFFSET < UINT_MAX && m > (unsigned int)MAX_MSEC_OFFSET)
		return MAX_JIFFY_OFFSET;
#if HZ <= 1000 && !(1000 % HZ)
	return ((unsigned long)m + (1000 / HZ) - 1) / (1000 / HZ);
#elif HZ > 1000 && !(HZ % 1000)
	return (unsigned long)m * (HZ / 1000);
#else
	return ((unsigned long)m * HZ + 999) / 1000;
#endif
}

#endif /* linux kernel < 2.4.29 */

/**
 * msleep_interruptible - sleep waiting for waitqueue interruptions
 * @msecs: Time in milliseconds to sleep for
 */
static inline unsigned long msleep_interruptible(unsigned int msecs)
{
       unsigned long timeout = msecs_to_jiffies(msecs);

       while (timeout && !signal_pending(current)) {
               set_current_state(TASK_INTERRUPTIBLE);
               timeout = schedule_timeout(timeout);
       }
       return jiffies_to_msecs(timeout);
}

#endif
