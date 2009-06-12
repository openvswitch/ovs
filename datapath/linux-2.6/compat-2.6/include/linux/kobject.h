#ifndef __LINUX_KOBJECT_WRAPPER_H
#define __LINUX_KOBJECT_WRAPPER_H 1

#include_next <linux/kobject.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
static inline int kobject_init_and_add(struct kobject *kobj,
					struct kobj_type *ktype,
					struct kobject *parent,
					const char *name)
{
	kobject_init(kobj);
	kobject_set_name(kobj, "%s", name);
	kobj->ktype = ktype;
	kobj->kset = NULL;
	kobj->parent = parent;

	return kobject_add(kobj);
}
#endif

#endif /* linux/kobject.h wrapper */
