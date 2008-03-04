/*
 * Distributed under the terms of the GNU GPL version 2.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

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
