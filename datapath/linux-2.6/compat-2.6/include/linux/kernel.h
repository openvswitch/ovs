#ifndef __KERNEL_H_WRAPPER
#define __KERNEL_H_WRAPPER 1

#include_next <linux/kernel.h>
#ifndef HAVE_LOG2_H
#include <linux/log2.h>
#endif

#endif /* linux/kernel.h */
