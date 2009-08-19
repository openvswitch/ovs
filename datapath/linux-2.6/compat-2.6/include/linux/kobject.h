#ifndef __LINUX_KOBJECT_WRAPPER_H
#define __LINUX_KOBJECT_WRAPPER_H 1

#include_next <linux/kobject.h>

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define kobject_init(kobj, ktype) rpl_kobject_init(kobj, ktype)
static inline void rpl_kobject_init(struct kobject *kobj, struct kobj_type *ktype)
{
	kobj->ktype = ktype;
	(kobject_init)(kobj);
}

#define kobject_add(kobj, parent, name) rpl_kobject_add(kobj, parent, name)
static inline int rpl_kobject_add(struct kobject *kobj,
				  struct kobject *parent,
				  const char *name)
{
	int err = kobject_set_name(kobj, "%s", name);
	if (err)
		return err;
	kobj->parent = parent;
	return (kobject_add)(kobj);
}
#endif


#endif /* linux/kobject.h wrapper */
