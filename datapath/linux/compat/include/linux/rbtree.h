#ifndef __LINUX_RBTREE_WRAPPER_H
#define __LINUX_RBTREE_WRAPPER_H 1

#include_next <linux/rbtree.h>

#ifndef HAVE_RBTREE_RB_LINK_NODE_RCU
#include <linux/rcupdate.h>

static inline void rb_link_node_rcu(struct rb_node *node, struct rb_node *parent,
				    struct rb_node **rb_link)
{
	node->__rb_parent_color = (unsigned long)parent;
	node->rb_left = node->rb_right = NULL;

	rcu_assign_pointer(*rb_link, node);
}
#endif

#endif /* __LINUX_RBTREE_WRAPPER_H */
