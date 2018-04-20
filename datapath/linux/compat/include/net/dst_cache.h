#ifndef _NET_DST_CACHE_WRAPPER_H
#define _NET_DST_CACHE_WRAPPER_H

#ifdef USE_BUILTIN_DST_CACHE
#include_next <net/dst_cache.h>
#else

#include <linux/jiffies.h>
#include <net/dst.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ip6_fib.h>
#endif

#ifdef USE_UPSTREAM_TUNNEL
#include_next <net/dst_cache.h>

#else
struct dst_cache {
	struct dst_cache_pcpu __percpu *cache;
	unsigned long reset_ts;
};

/**
 *	dst_cache_get - perform cache lookup
 *	@dst_cache: the cache
 *
 *	The caller should use dst_cache_get_ip4() if it need to retrieve the
 *	source address to be used when xmitting to the cached dst.
 *	local BH must be disabled.
 */
#define rpl_dst_cache_get dst_cache_get
struct dst_entry *rpl_dst_cache_get(struct dst_cache *dst_cache);

/**
 *	dst_cache_get_ip4 - perform cache lookup and fetch ipv4 source address
 *	@dst_cache: the cache
 *	@saddr: return value for the retrieved source address
 *
 *	local BH must be disabled.
 */
#define rpl_dst_cache_get_ip4 dst_cache_get_ip4
struct rtable *rpl_dst_cache_get_ip4(struct dst_cache *dst_cache, __be32 *saddr);

/**
 *	dst_cache_set_ip4 - store the ipv4 dst into the cache
 *	@dst_cache: the cache
 *	@dst: the entry to be cached
 *	@saddr: the source address to be stored inside the cache
 *
 *	local BH must be disabled.
 */
#define rpl_dst_cache_set_ip4 dst_cache_set_ip4
void rpl_dst_cache_set_ip4(struct dst_cache *dst_cache, struct dst_entry *dst,
		       __be32 saddr);

#if IS_ENABLED(CONFIG_IPV6)

/**
 *	dst_cache_set_ip6 - store the ipv6 dst into the cache
 *	@dst_cache: the cache
 *	@dst: the entry to be cached
 *	@saddr: the source address to be stored inside the cache
 *
 *	local BH must be disabled.
 */
#define rpl_dst_cache_set_ip6 dst_cache_set_ip6
void rpl_dst_cache_set_ip6(struct dst_cache *dst_cache, struct dst_entry *dst,
		       const struct in6_addr *addr);

/**
 *	dst_cache_get_ip6 - perform cache lookup and fetch ipv6 source address
 *	@dst_cache: the cache
 *	@saddr: return value for the retrieved source address
 *
 *	local BH must be disabled.
 */
#define rpl_dst_cache_get_ip6 dst_cache_get_ip6
struct dst_entry *rpl_dst_cache_get_ip6(struct dst_cache *dst_cache,
				    struct in6_addr *saddr);
#endif

/**
 *	dst_cache_reset - invalidate the cache contents
 *	@dst_cache: the cache
 *
 *	This do not free the cached dst to avoid races and contentions.
 *	the dst will be freed on later cache lookup.
 */
static inline void dst_cache_reset(struct dst_cache *dst_cache)
{
	dst_cache->reset_ts = jiffies;
}

/**
 *	dst_cache_init - initialize the cache, allocating the required storage
 *	@dst_cache: the cache
 *	@gfp: allocation flags
 */
#define rpl_dst_cache_init dst_cache_init
int rpl_dst_cache_init(struct dst_cache *dst_cache, gfp_t gfp);

/**
 *	dst_cache_destroy - empty the cache and free the allocated storage
 *	@dst_cache: the cache
 *
 *	No synchronization is enforced: it must be called only when the cache
 *	is unsed.
 */
#define rpl_dst_cache_destroy dst_cache_destroy
void rpl_dst_cache_destroy(struct dst_cache *dst_cache);

#endif /* USE_UPSTREAM_TUNNEL */
#endif /* USE_BUILTIN_DST_CACHE */
#endif
