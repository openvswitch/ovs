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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
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
#define genl_notify rpl_genl_notify
void genl_notify(struct genl_family *family,
		 struct sk_buff *skb, struct net *net, u32 portid, u32 group,
		 struct nlmsghdr *nlh, gfp_t flags);

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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
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

#ifndef HAVE_GENLMSG_NEW_UNICAST
static inline struct sk_buff *genlmsg_new_unicast(size_t payload,
						  struct genl_info *info,
						  gfp_t flags)
{
	return genlmsg_new(payload, flags);
}
#endif

#endif /* genetlink.h */
