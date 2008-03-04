#include "net/genetlink.h"

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)

int genl_register_mc_group(struct genl_family *family,
        struct genl_multicast_group *grp)
{
	grp->id = 1;
	grp->family = family;

	return 0;
}

#endif /* kernel < 2.6.23 */
