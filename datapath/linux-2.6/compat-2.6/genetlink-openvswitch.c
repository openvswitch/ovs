#include "net/genetlink.h"

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)

/* We use multicast groups 16 through 31 to avoid colliding with the multicast
 * group selected by brcompat_mod, which uses groups 32.  Collision isn't
 * fatal--multicast listeners should check that the family is the one that they
 * want and discard others--but it wastes time and memory to receive unwanted
 * messages. */
int genl_register_mc_group(struct genl_family *family,
			   struct genl_multicast_group *grp)
{
	/* This code is called single-threaded. */
	static unsigned int next_id = 0;
	grp->id = next_id++ % 16 + 16;
	grp->family = family;

	return 0;
}

#endif /* kernel < 2.6.23 */
