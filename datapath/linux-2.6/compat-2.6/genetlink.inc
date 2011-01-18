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
