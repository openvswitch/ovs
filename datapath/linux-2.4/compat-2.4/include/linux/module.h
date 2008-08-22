#ifndef __LINUX_MODULE_WRAPPER_H
#define __LINUX_MODULE_WRAPPER_H 1

#include <linux/kernel.h>
#include_next <linux/module.h>

static inline int try_module_get(struct module *module)
{
	if (module) {
		if (module == THIS_MODULE)
			MOD_INC_USE_COUNT;
		else 
			printk("warning: try_module_get: module(%p) != THIS_MODULE(%p)\n", 
					module, THIS_MODULE);
	}
	return 1;
}

static inline void module_put(struct module *module) 
{
	if (module) {
		if (module == THIS_MODULE)
			MOD_DEC_USE_COUNT;
		else 
			printk("warning: module_put: module(%p) != THIS_MODULE(%p)\n", 
					module, THIS_MODULE);
	}
}

#endif /* module.h */
