#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)

#include <net/netfilter/nf_conntrack_zones.h>

/* Built-in default zone used e.g. by modules. */
const struct nf_conntrack_zone nf_ct_zone_dflt = {
	.id	= NF_CT_DEFAULT_ZONE_ID,
	.dir	= NF_CT_DEFAULT_ZONE_DIR,
};

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0) */
