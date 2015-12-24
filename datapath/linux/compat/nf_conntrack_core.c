#include <linux/version.h>

#ifndef HAVE_NF_CT_ZONE_INIT

#include <net/netfilter/nf_conntrack_zones.h>

/* Built-in default zone used e.g. by modules. */
const struct nf_conntrack_zone nf_ct_zone_dflt = {
	.id	= NF_CT_DEFAULT_ZONE_ID,
	.dir	= NF_CT_DEFAULT_ZONE_DIR,
};

#endif /* HAVE_NF_CT_ZONE_INIT */
