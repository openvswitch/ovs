#ifndef __LINUX_MODULE_WRAPPER_H
#define __LINUX_MODULE_WRAPPER_H 1

#include <linux/kernel.h>
#include_next <linux/module.h>

static inline int try_module_get(struct module *module)
{
	BUG_ON(module != THIS_MODULE);
	MOD_INC_USE_COUNT;
	return 1;
}

static inline void module_put(struct module *module) 
{
	BUG_ON(module != THIS_MODULE);
	MOD_DEC_USE_COUNT;
}

#endif /* module.h */
