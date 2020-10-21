#ifndef __LINUX_RCULIST_WRAPPER_H
#define __LINUX_RCULIST_WRAPPER_H

#include_next <linux/rculist.h>

#ifndef hlist_first_rcu
#define hlist_first_rcu(head)   (*((struct hlist_node __rcu **)(&(head)->first)))
#define hlist_next_rcu(node)    (*((struct hlist_node __rcu **)(&(node)->next)))
#define hlist_pprev_rcu(node)   (*((struct hlist_node __rcu **)((node)->pprev)))
#endif

/*
 * Check during list traversal that we are within an RCU reader
 */

#define check_arg_count_one(dummy)

#ifdef CONFIG_PROVE_RCU_LIST
#define __list_check_rcu(dummy, cond, extra...)				\
	({								\
	check_arg_count_one(extra);					\
	RCU_LOCKDEP_WARN(!cond && !rcu_read_lock_any_held(),		\
			 "RCU-list traversed in non-reader section!");	\
	 })
#else
#define __list_check_rcu(dummy, cond, extra...)				\
	({ check_arg_count_one(extra); })
#endif

#undef hlist_for_each_entry_rcu
#define hlist_for_each_entry_rcu(pos, head, member, cond...)		\
	for (__list_check_rcu(dummy, ## cond, 0),			\
	     pos = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))

#endif
