#ifndef __RTNETLINK_WRAPPER_H
#define __RTNETLINK_WRAPPER_H 1

#include_next <linux/rtnetlink.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static inline void rtnl_notify(struct sk_buff *skb, u32 portid, u32 group,
			       struct nlmsghdr *nlh, gfp_t flags)
{
	BUG_ON(nlh != NULL);		/* not implemented */
	if (group) {
		/* errors reported via destination sk->sk_err */
		nlmsg_multicast(rtnl, skb, 0, group, flags);
	}
}

static inline void rtnl_set_sk_err(u32 group, int error)
{
	netlink_set_err(rtnl, 0, group, error);
}
#endif

/* No 'net' parameter in these versions. */
#define rtnl_notify(skb, net, portid, group, nlh, flags) \
		    ((void) rtnl_notify(skb, portid, group, nlh, flags))
#define rtnl_set_sk_err(net, group, error) \
			(rtnl_set_sk_err(group, error))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
/* Make the return type effectively 'void' to match Linux 2.6.30+. */
#define rtnl_notify(skb, net, portid, group, nlh, flags) \
	((void) rtnl_notify(skb, net, portid, group, nlh, flags))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static inline int rtnl_is_locked(void)
{
	if (unlikely(rtnl_trylock())) {
		rtnl_unlock();
		return 0;
	}

	return 1;
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
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
