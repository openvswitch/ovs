/*
 * Distributed under the terms of the GNU GPL version 2.
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/hardirq.h>

int vprintk(const char *msg, ...)
{
#define BUFFER_SIZE 1024
	char *buffer = kmalloc(BUFFER_SIZE, GFP_ATOMIC);
	int retval;
	if (buffer) {
		va_list args;
		va_start(args, msg);
		vsnprintf(buffer, BUFFER_SIZE, msg, args);
		va_end(args);
		retval = printk("%s", buffer);
		kfree(buffer);
	} else {
		retval = printk("<<vprintk allocation failure>> %s", msg);
	}
	return retval;
}

EXPORT_SYMBOL(vprintk);

#ifdef CONFIG_DEBUG_SPINLOCK
void __might_sleep(char *file, int line)
{
	static unsigned long prev_jiffy;	/* ratelimiting */

	if ((in_interrupt()) && !oops_in_progress) {
		if (time_before(jiffies, prev_jiffy + HZ) && prev_jiffy)
			return;
		prev_jiffy = jiffies;
		printk(KERN_ERR "BUG: sleeping function called from invalid"
				" context at %s:%d\n", file, line);
		dump_stack();
	}
}
EXPORT_SYMBOL(__might_sleep);
#endif
