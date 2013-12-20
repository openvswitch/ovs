#ifndef __RTNETLINK_WRAPPER_H
#define __RTNETLINK_WRAPPER_H 1

#include_next <linux/rtnetlink.h>

#ifndef HAVE_LOCKDEP_RTNL_IS_HELD
#ifdef CONFIG_PROVE_LOCKING
static inline int lockdep_rtnl_is_held(void)
{
	return 1;
}
#endif
#endif

#ifndef rcu_dereference_rtnl
/**
 * rcu_dereference_rtnl - rcu_dereference with debug checking
 * @p: The pointer to read, prior to dereferencing
 *
 * Do an rcu_dereference(p), but check caller either holds rcu_read_lock()
 * or RTNL. Note : Please prefer rtnl_dereference() or rcu_dereference()
 */
#define rcu_dereference_rtnl(p)					\
	rcu_dereference_check(p, rcu_read_lock_held() ||	\
				 lockdep_rtnl_is_held())
#endif

#ifndef rtnl_dereference
/**
 * rtnl_dereference - fetch RCU pointer when updates are prevented by RTNL
 * @p: The pointer to read, prior to dereferencing
 *
 * Return the value of the specified RCU-protected pointer, but omit
 * both the smp_read_barrier_depends() and the ACCESS_ONCE(), because
 * caller holds RTNL.
 */
#define rtnl_dereference(p)					\
	rcu_dereference_protected(p, lockdep_rtnl_is_held())
#endif

#endif /* linux/rtnetlink.h wrapper */
