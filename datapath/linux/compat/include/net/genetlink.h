#ifndef __NET_GENERIC_NETLINK_WRAPPER_H
#define __NET_GENERIC_NETLINK_WRAPPER_H 1

#include <linux/version.h>
#include <linux/netlink.h>
#include <net/net_namespace.h>
#include_next <net/genetlink.h>

/*
 * 15e473046cb6e5d18a4d0057e61d76315230382b renames pid to portid
 * the affected structures are
 * netlink_skb_parms::pid -> portid
 * genl_info::snd_pid -> snd_portid
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#define snd_portid snd_pid
#define portid pid
#endif

#ifndef HAVE_GENL_NOTIFY_TAKES_FAMILY
struct rpl_genl_family {
	struct genl_family	compat_family;
	unsigned int            id;
	unsigned int            hdrsize;
	char                    name[GENL_NAMSIZ];
	unsigned int            version;
	unsigned int            maxattr;
	bool                    netnsok;
	bool                    parallel_ops;
	int                     (*pre_doit)(const struct genl_ops *ops,
					    struct sk_buff *skb,
					    struct genl_info *info);
	void                    (*post_doit)(const struct genl_ops *ops,
					     struct sk_buff *skb,
					     struct genl_info *info);
	struct nlattr **        attrbuf;        /* private */
	const struct genl_ops * ops;            /* private */
	const struct genl_multicast_group *mcgrps; /* private */
	unsigned int            n_ops;          /* private */
	unsigned int            n_mcgrps;       /* private */
	unsigned int            mcgrp_offset;   /* private */
	struct list_head        family_list;    /* private */
	struct module           *module;
};

#define genl_family rpl_genl_family
static inline void *rpl_genlmsg_put(struct sk_buff *skb, u32 portid, u32 seq,
				    struct genl_family *family, int flags, u8 cmd)
{
	return genlmsg_put(skb, portid, seq, &family->compat_family, flags, cmd);
}

#define genlmsg_put rpl_genlmsg_put

static inline int rpl_genl_unregister_family(struct genl_family *family)
{
	return genl_unregister_family(&family->compat_family);
}
#define genl_unregister_family rpl_genl_unregister_family

#define genl_set_err rpl_genl_set_err
static inline int genl_set_err(struct genl_family *family, struct net *net,
			       u32 portid, u32 group, int code)
{
#ifdef HAVE_VOID_NETLINK_SET_ERR
	netlink_set_err(net->genl_sock, portid, group, code);
	return 0;
#else
	return netlink_set_err(net->genl_sock, portid, group, code);
#endif
}

#define genlmsg_multicast_netns rpl_genlmsg_multicast_netns
static inline int genlmsg_multicast_netns(struct genl_family *family,
					  struct net *net, struct sk_buff *skb,
					  u32 portid, unsigned int group, gfp_t flags)
{
	return nlmsg_multicast(net->genl_sock, skb, portid, group, flags);
}


#define __genl_register_family rpl___genl_register_family
int rpl___genl_register_family(struct genl_family *family);

#define genl_register_family rpl_genl_register_family
static inline int rpl_genl_register_family(struct genl_family *family)
{
	family->module = THIS_MODULE;
	return rpl___genl_register_family(family);
}
#endif

#ifdef HAVE_GENL_NOTIFY_TAKES_NET
#define genl_notify rpl_genl_notify
void rpl_genl_notify(struct genl_family *family, struct sk_buff *skb,
		     struct genl_info *info , u32 group, gfp_t flags);
#endif

#ifndef HAVE_GENL_HAS_LISTENERS
static inline int genl_has_listeners(struct genl_family *family,
				     struct net *net, unsigned int group)
{
#ifdef HAVE_MCGRP_OFFSET
	if (WARN_ON_ONCE(group >= family->n_mcgrps))
		return -EINVAL;
	group = family->mcgrp_offset + group;
#endif
	return netlink_has_listeners(net->genl_sock, group);
}
#else

#ifndef HAVE_GENL_HAS_LISTENERS_TAKES_NET
static inline int rpl_genl_has_listeners(struct genl_family *family,
				         struct net *net, unsigned int group)
{
#ifdef HAVE_GENL_NOTIFY_TAKES_FAMILY
    return genl_has_listeners(family, net->genl_sock, group);
#else
    return genl_has_listeners(&family->compat_family, net->genl_sock, group);
#endif
}

#define genl_has_listeners rpl_genl_has_listeners
#endif

#endif /* HAVE_GENL_HAS_LISTENERS */

#ifndef HAVE_NETLINK_EXT_ACK
struct netlink_ext_ack;

static inline int rpl_genlmsg_parse(const struct nlmsghdr *nlh,
				    const struct genl_family *family,
				    struct nlattr *tb[], int maxtype,
				    const struct nla_policy *policy,
				    struct netlink_ext_ack *extack)
{
#ifdef HAVE_GENLMSG_PARSE
	return genlmsg_parse(nlh, family, tb, maxtype, policy);
#else
	return nlmsg_parse(nlh, family->hdrsize + GENL_HDRLEN, tb, maxtype,
			   policy);
#endif
}
#define genlmsg_parse rpl_genlmsg_parse
#endif

#endif /* genetlink.h */
