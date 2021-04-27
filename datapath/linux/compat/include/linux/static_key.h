#ifndef _STATIC_KEY_WRAPPER_H
#define _STATIC_KEY_WRAPPER_H

#include <linux/atomic.h>
#include_next <linux/static_key.h>
#ifndef HAVE_UPSTREAM_STATIC_KEY
/*
 * This backport is based on upstream net-next commit 11276d5306b8
 * ("locking/static_keys: Add a new static_key interface").
 *
 * For kernel that does not support the new static key interface,
 * we do not backport the jump label support but the fall back version
 * of static key that is simply a conditional branch.
 */

struct static_key_true {
	struct static_key key;
};

struct static_key_false {
	struct static_key key;
};

#define rpl_STATIC_KEY_INIT_TRUE	{ .enabled = ATOMIC_INIT(1) }
#define rpl_STATIC_KEY_INIT_FALSE	{ .enabled = ATOMIC_INIT(0) }

#define rpl_STATIC_KEY_TRUE_INIT	\
	(struct static_key_true) { .key = rpl_STATIC_KEY_INIT_TRUE,  }
#define rpl_STATIC_KEY_FALSE_INIT	\
	(struct static_key_false){ .key = rpl_STATIC_KEY_INIT_FALSE, }

#define rpl_DEFINE_STATIC_KEY_TRUE(name)	\
	struct static_key_true name = rpl_STATIC_KEY_TRUE_INIT

#define rpl_DEFINE_STATIC_KEY_FALSE(name)	\
	struct static_key_false name = rpl_STATIC_KEY_FALSE_INIT

static inline int rpl_static_key_count(struct static_key *key)
{
	return atomic_read(&key->enabled);
}

static inline void rpl_static_key_enable(struct static_key *key)
{
	int count = rpl_static_key_count(key);

	WARN_ON_ONCE(count < 0 || count > 1);

	if (!count)
		static_key_slow_inc(key);
}

static inline void rpl_static_key_disable(struct static_key *key)
{
	int count = rpl_static_key_count(key);

	WARN_ON_ONCE(count < 0 || count > 1);

	if (count)
		static_key_slow_dec(key);
}

#ifdef	HAVE_DEFINE_STATIC_KEY
#undef	DEFINE_STATIC_KEY_TRUE
#undef	DEFINE_STATIC_KEY_FALSE
#endif

#define DEFINE_STATIC_KEY_TRUE		rpl_DEFINE_STATIC_KEY_TRUE
#define DEFINE_STATIC_KEY_FALSE		rpl_DEFINE_STATIC_KEY_FALSE

#define static_branch_likely(x)		likely(static_key_enabled(&(x)->key))
#define static_branch_unlikely(x)	unlikely(static_key_enabled(&(x)->key))

#define static_branch_enable(x)		rpl_static_key_enable(&(x)->key)
#define static_branch_disable(x)	rpl_static_key_disable(&(x)->key)

#ifndef HAVE_DECLARE_STATIC_KEY
#define DECLARE_STATIC_KEY_TRUE(name)   \
        extern struct static_key_true name
#define DECLARE_STATIC_KEY_FALSE(name)  \
        extern struct static_key_false name
#endif

#endif /* HAVE_UPSTREAM_STATIC_KEY */

#endif /* _STATIC_KEY_WRAPPER_H */
