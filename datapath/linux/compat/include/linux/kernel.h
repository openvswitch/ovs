#ifndef __KERNEL_H_WRAPPER
#define __KERNEL_H_WRAPPER 1

#include_next <linux/kernel.h>
#ifndef HAVE_LOG2_H
#include <linux/log2.h>
#endif

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#undef pr_emerg
#define pr_emerg(fmt, ...) \
	printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#undef pr_alert
#define pr_alert(fmt, ...) \
	printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#undef pr_crit
#define pr_crit(fmt, ...) \
	printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#undef pr_err
#define pr_err(fmt, ...) \
	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#undef pr_warning
#define pr_warning(fmt, ...) \
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#undef pr_notice
#define pr_notice(fmt, ...) \
	printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#undef pr_info
#define pr_info(fmt, ...) \
	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#undef pr_cont
#define pr_cont(fmt, ...) \
	printk(KERN_CONT fmt, ##__VA_ARGS__)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
#define pr_warn pr_warning
#endif

#if defined(CONFIG_PREEMPT) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
#error "CONFIG_PREEMPT is broken before 2.6.21--see commit 4498121ca3, \"[NET]: Handle disabled preemption in gfp_any()\""
#endif

#ifndef USHRT_MAX
#define USHRT_MAX	((u16)(~0U))
#define SHRT_MAX	((s16)(USHRT_MAX>>1))
#define SHRT_MIN	((s16)(-SHRT_MAX - 1))
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

#endif /* linux/kernel.h */
