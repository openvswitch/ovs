/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2010, 2011 Nicira Networks.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/hardirq.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/sched.h>

#include "loop_counter.h"

int loop_suppress(struct datapath *dp, struct sw_flow_actions *actions)
{
	if (net_ratelimit())
		pr_warn("%s: flow looped %d times, dropping\n",
			dp_name(dp), MAX_LOOPS);
	actions->actions_len = 0;
	return -ELOOP;
}

#ifndef CONFIG_PREEMPT_RT

/* We use a separate counter for each CPU for both interrupt and non-interrupt
 * context in order to keep the limit deterministic for a given packet.
 */
struct percpu_loop_counters {
	struct loop_counter counters[2];
};

static DEFINE_PER_CPU(struct percpu_loop_counters, loop_counters);

struct loop_counter *loop_get_counter(void)
{
	return &get_cpu_var(loop_counters).counters[!!in_interrupt()];
}

void loop_put_counter(void)
{
	put_cpu_var(loop_counters);
}

#else /* !CONFIG_PREEMPT_RT */

struct loop_counter *loop_get_counter(void)
{
	WARN_ON(in_interrupt());

	/* Only two bits of the extra_flags field in struct task_struct are
	 * used and it's an unsigned int.  We hijack the most significant bits
	 * to be our counter structure.  On RT kernels softirqs always run in
	 * process context so we are guaranteed to have a valid task_struct.
	 */

#ifdef __LITTLE_ENDIAN
	return (void *)(&current->extra_flags + 1) -
		sizeof(struct loop_counter);
#elif __BIG_ENDIAN
	return (struct loop_counter *)&current->extra_flags;
#else
#error "Please fix <asm/byteorder.h>."
#endif
}

void loop_put_counter(void) { }

#endif /* CONFIG_PREEMPT_RT */
