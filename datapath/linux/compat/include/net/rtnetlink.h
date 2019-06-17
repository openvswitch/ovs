#ifndef __NET_RTNETLINK_WRAPPER_H
#define __NET_RTNETLINK_WRAPPER_H
#include_next <net/rtnetlink.h>

#define rtnl_delete_link rpl_rtnl_delete_link
int rpl_rtnl_delete_link(struct net_device *dev);

#ifndef HAVE_NAME_ASSIGN_TYPE
#ifdef HAVE_RTNL_CREATE_LINK_SRC_NET
static inline struct net_device *rpl_rtnl_create_link(struct net *net, const char *ifname,
						      unsigned char name_assign_type,
						      const struct rtnl_link_ops *ops,
						      struct nlattr *tb[])
{
	return rtnl_create_link(net, net, (char *)ifname, ops, tb);
}

#else
static inline struct net_device *rpl_rtnl_create_link(struct net *net, const char *ifname,
						      unsigned char name_assign_type,
						      const struct rtnl_link_ops *ops,
						      struct nlattr *tb[])
{
	return rtnl_create_link(net, (char *)ifname, ops, tb);
}
#endif
#else
/* This function is only defined to avoid warning related to ifname. Some backported
 * function did not changed the name to const type. */
static inline struct net_device *rpl_rtnl_create_link(struct net *net, const char *ifname,
                                    unsigned char name_assign_type,
                                    const struct rtnl_link_ops *ops,
                                    struct nlattr *tb[])
{
#ifdef HAVE_RTNL_CREATE_LINK_TAKES_EXTACK
	return rtnl_create_link(net, (char *) ifname, name_assign_type, ops, tb, NULL);
#else
	return rtnl_create_link(net, (char *) ifname, name_assign_type, ops, tb);
#endif
}
#endif

#define rtnl_create_link rpl_rtnl_create_link
#endif
