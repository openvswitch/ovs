#ifndef __LINUX_BH_WRAPPER_H
#define __LINUX_BH_WRAPPER_H 1

#include_next <linux/bottom_half.h>

/* This is not, strictly speaking, compatibility code in the sense that it is
 * not needed by older kernels.  However, it is used on kernels with the
 * realtime patchset applied to create an environment more similar to what we
 * would see on normal kernels.
 */

#ifdef CONFIG_PREEMPT_HARDIRQS
#undef local_bh_disable
#define local_bh_disable preempt_disable
#undef local_bh_enable
#define local_bh_enable preempt_enable
#endif

#endif
