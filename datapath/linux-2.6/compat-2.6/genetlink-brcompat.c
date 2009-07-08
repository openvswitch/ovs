#include "net/genetlink.h"

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)

/* We fix grp->id to 32 so that it doesn't collide with any of the multicast
 * groups selected by openvswitch_mod, which uses groups 16 through 31.
 * Collision isn't fatal--multicast listeners should check that the family is
 * the one that they want and discard others--but it wastes time and memory to
 * receive unwanted messages. */
int genl_register_mc_group(struct genl_family *family,
			   struct genl_multicast_group *grp)
{
	grp->id = 32;
	grp->family = family;

	return 0;
}

#endif /* kernel < 2.6.23 */
