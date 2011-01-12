/* -*- c -*- */

#include <net/genetlink.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#include <linux/mutex.h>

static DEFINE_MUTEX(mc_group_mutex);

int genl_register_mc_group(struct genl_family *family,
			   struct genl_multicast_group *grp)
{
	static int next_group = GENL_FIRST_MCGROUP;

	mutex_lock(&mc_group_mutex);
	grp->id = next_group;
	grp->family = family;

	if (++next_group > GENL_LAST_MCGROUP)
		next_group = GENL_FIRST_MCGROUP;
	mutex_unlock(&mc_group_mutex);

	return 0;
}
#endif /* kernel < 2.6.23 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
/**
 * genl_register_family_with_ops - register a generic netlink family
 * @family: generic netlink family
 * @ops: operations to be registered
 * @n_ops: number of elements to register
 *
 * Registers the specified family and operations from the specified table.
 * Only one family may be registered with the same family name or identifier.
 *
 * The family id may equal GENL_ID_GENERATE causing an unique id to
 * be automatically generated and assigned.
 *
 * Either a doit or dumpit callback must be specified for every registered
 * operation or the function will fail. Only one operation structure per
 * command identifier may be registered.
 *
 * See include/net/genetlink.h for more documenation on the operations
 * structure.
 *
 * This is equivalent to calling genl_register_family() followed by
 * genl_register_ops() for every operation entry in the table taking
 * care to unregister the family on error path.
 *
 * Return 0 on success or a negative error code.
 */
int genl_register_family_with_ops(struct genl_family *family,
	struct genl_ops *ops, size_t n_ops)
{
	int err, i;

	err = genl_register_family(family);
	if (err)
		return err;

	for (i = 0; i < n_ops; ++i, ++ops) {
		err = genl_register_ops(family, ops);
		if (err)
			goto err_out;
	}
	return 0;
err_out:
	genl_unregister_family(family);
	return err;
}
#endif
