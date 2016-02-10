#ifndef _NF_CONNTRACK_ZONES_WRAPPER_H
#define _NF_CONNTRACK_ZONES_WRAPPER_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
#include_next <net/netfilter/nf_conntrack_zones.h>
#endif

#ifndef HAVE_NF_CT_ZONE_INIT

#include <linux/kconfig.h>
#include <linux/types.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>

#define NF_CT_DEFAULT_ZONE_ID   0

#define NF_CT_ZONE_DIR_ORIG     (1 << IP_CT_DIR_ORIGINAL)
#define NF_CT_ZONE_DIR_REPL     (1 << IP_CT_DIR_REPLY)

#define NF_CT_DEFAULT_ZONE_DIR  (NF_CT_ZONE_DIR_ORIG | NF_CT_ZONE_DIR_REPL)

#define NF_CT_FLAG_MARK	 1

struct rpl_nf_conntrack_zone {
	u16     id;
	u8      flags;
	u8      dir;
};
#define nf_conntrack_zone rpl_nf_conntrack_zone

extern const struct nf_conntrack_zone nf_ct_zone_dflt;

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#include <net/netfilter/nf_conntrack_extend.h>

static inline const struct nf_conntrack_zone *
rpl_nf_ct_zone(const struct nf_conn *ct)
{
	const struct nf_conntrack_zone *nf_ct_zone = NULL;

#ifdef CONFIG_NF_CONNTRACK_ZONES
	nf_ct_zone = nf_ct_ext_find(ct, NF_CT_EXT_ZONE);
#endif
	return nf_ct_zone ? nf_ct_zone : &nf_ct_zone_dflt;
}
#define nf_ct_zone rpl_nf_ct_zone

static inline const struct nf_conntrack_zone *
nf_ct_zone_init(struct nf_conntrack_zone *zone, u16 id, u8 dir, u8 flags)
{
	zone->id = id;
	zone->flags = flags;
	zone->dir = dir;

	return zone;
}

static inline int nf_ct_zone_add(struct nf_conn *ct, gfp_t flags,
				 const struct nf_conntrack_zone *info)
{
#ifdef CONFIG_NF_CONNTRACK_ZONES
	struct nf_conntrack_zone *nf_ct_zone;

	nf_ct_zone = nf_ct_ext_add(ct, NF_CT_EXT_ZONE, flags);
	if (!nf_ct_zone)
		return -ENOMEM;

	nf_ct_zone_init(nf_ct_zone, info->id, info->dir,
			info->flags);
#endif
	return 0;
}

static inline bool nf_ct_zone_matches_dir(const struct nf_conntrack_zone *zone,
					  enum ip_conntrack_dir dir)
{
	return zone->dir & (1 << dir);
}

static inline u16 nf_ct_zone_id(const struct nf_conntrack_zone *zone,
				enum ip_conntrack_dir dir)
{
	return nf_ct_zone_matches_dir(zone, dir) ?
	       zone->id : NF_CT_DEFAULT_ZONE_ID;
}

static inline bool nf_ct_zone_equal(const struct nf_conn *a,
				    const struct nf_conntrack_zone *b,
				    enum ip_conntrack_dir dir)
{
	return nf_ct_zone_id(nf_ct_zone(a), dir) ==
	       nf_ct_zone_id(b, dir);
}

static inline bool nf_ct_zone_equal_any(const struct nf_conn *a,
					const struct nf_conntrack_zone *b)
{
	return nf_ct_zone(a)->id == b->id;
}
#endif /* IS_ENABLED(CONFIG_NF_CONNTRACK) */
#endif /* HAVE_NF_CT_ZONE_INIT */
#endif /* _NF_CONNTRACK_ZONES_WRAPPER_H */
