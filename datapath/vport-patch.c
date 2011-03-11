/*
 * Copyright (c) 2010, 2011 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#include <linux/dcache.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rtnetlink.h>

#include "compat.h"
#include "datapath.h"
#include "vport.h"
#include "vport-generic.h"

struct patch_config {
	struct rcu_head rcu;

	char peer_name[IFNAMSIZ];
	unsigned char eth_addr[ETH_ALEN];
};

struct patch_vport {
	struct rcu_head rcu;

	char name[IFNAMSIZ];

	/* Protected by RTNL lock. */
	struct hlist_node hash_node;

	struct vport __rcu *peer;
	struct patch_config __rcu *patchconf;
};

/* Protected by RTNL lock. */
static struct hlist_head *peer_table;
#define PEER_HASH_BUCKETS 256

static void update_peers(const char *name, struct vport *);

static inline struct patch_vport *patch_vport_priv(const struct vport *vport)
{
	return vport_priv(vport);
}

/* RCU callback. */
static void free_config(struct rcu_head *rcu)
{
	struct patch_config *c = container_of(rcu, struct patch_config, rcu);
	kfree(c);
}

static void assign_config_rcu(struct vport *vport,
			      struct patch_config *new_config)
{
	struct patch_vport *patch_vport = patch_vport_priv(vport);
	struct patch_config *old_config;

	old_config = rtnl_dereference(patch_vport->patchconf);
	rcu_assign_pointer(patch_vport->patchconf, new_config);
	call_rcu(&old_config->rcu, free_config);
}

static struct hlist_head *hash_bucket(const char *name)
{
	unsigned int hash = full_name_hash(name, strlen(name));
	return &peer_table[hash & (PEER_HASH_BUCKETS - 1)];
}

static int patch_init(void)
{
	peer_table = kzalloc(PEER_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (!peer_table)
		return -ENOMEM;

	return 0;
}

static void patch_exit(void)
{
	kfree(peer_table);
}

static const struct nla_policy patch_policy[ODP_PATCH_ATTR_MAX + 1] = {
#ifdef HAVE_NLA_NUL_STRING
	[ODP_PATCH_ATTR_PEER] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
#endif
};

static int patch_set_config(struct vport *vport, const struct nlattr *options,
			    struct patch_config *patchconf)
{
	struct patch_vport *patch_vport = patch_vport_priv(vport);
	struct nlattr *a[ODP_PATCH_ATTR_MAX + 1];
	const char *peer_name;
	int err;

	if (!options)
		return -EINVAL;

	err = nla_parse_nested(a, ODP_PATCH_ATTR_MAX, options, patch_policy);
	if (err)
		return err;

	if (!a[ODP_PATCH_ATTR_PEER] ||
	    CHECK_NUL_STRING(a[ODP_PATCH_ATTR_PEER], IFNAMSIZ - 1))
		return -EINVAL;

	peer_name = nla_data(a[ODP_PATCH_ATTR_PEER]);
	if (!strcmp(patch_vport->name, peer_name))
		return -EINVAL;

	strcpy(patchconf->peer_name, peer_name);

	return 0;
}

static struct vport *patch_create(const struct vport_parms *parms)
{
	struct vport *vport;
	struct patch_vport *patch_vport;
	const char *peer_name;
	struct patch_config *patchconf;
	int err;

	vport = vport_alloc(sizeof(struct patch_vport), &patch_vport_ops, parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	patch_vport = patch_vport_priv(vport);

	strcpy(patch_vport->name, parms->name);

	patchconf = kmalloc(sizeof(struct patch_config), GFP_KERNEL);
	if (!patchconf) {
		err = -ENOMEM;
		goto error_free_vport;
	}

	err = patch_set_config(vport, parms->options, patchconf);
	if (err)
		goto error_free_patchconf;

	vport_gen_rand_ether_addr(patchconf->eth_addr);

	rcu_assign_pointer(patch_vport->patchconf, patchconf);

	peer_name = patchconf->peer_name;
	hlist_add_head(&patch_vport->hash_node, hash_bucket(peer_name));
	rcu_assign_pointer(patch_vport->peer, vport_locate(peer_name));
	update_peers(patch_vport->name, vport);

	return vport;

error_free_patchconf:
	kfree(patchconf);
error_free_vport:
	vport_free(vport);
error:
	return ERR_PTR(err);
}

static void free_port_rcu(struct rcu_head *rcu)
{
	struct patch_vport *patch_vport = container_of(rcu,
					  struct patch_vport, rcu);

	kfree((struct patch_config __force *)patch_vport->patchconf);
	vport_free(vport_from_priv(patch_vport));
}

static int patch_destroy(struct vport *vport)
{
	struct patch_vport *patch_vport = patch_vport_priv(vport);

	update_peers(patch_vport->name, NULL);
	hlist_del(&patch_vport->hash_node);
	call_rcu(&patch_vport->rcu, free_port_rcu);

	return 0;
}

static int patch_set_options(struct vport *vport, struct nlattr *options)
{
	struct patch_vport *patch_vport = patch_vport_priv(vport);
	struct patch_config *patchconf;
	int err;

	patchconf = kmemdup(rtnl_dereference(patch_vport->patchconf),
			  sizeof(struct patch_config), GFP_KERNEL);
	if (!patchconf) {
		err = -ENOMEM;
		goto error;
	}

	err = patch_set_config(vport, options, patchconf);
	if (err)
		goto error_free;

	assign_config_rcu(vport, patchconf);

	hlist_del(&patch_vport->hash_node);

	rcu_assign_pointer(patch_vport->peer, vport_locate(patchconf->peer_name));
	hlist_add_head(&patch_vport->hash_node, hash_bucket(patchconf->peer_name));

	return 0;

error_free:
	kfree(patchconf);
error:
	return err;
}

static void update_peers(const char *name, struct vport *vport)
{
	struct hlist_head *bucket = hash_bucket(name);
	struct patch_vport *peer_vport;
	struct hlist_node *node;

	hlist_for_each_entry(peer_vport, node, bucket, hash_node) {
		const char *peer_name;

		peer_name = rtnl_dereference(peer_vport->patchconf)->peer_name;
		if (!strcmp(peer_name, name))
			rcu_assign_pointer(peer_vport->peer, vport);
	}
}

static int patch_set_addr(struct vport *vport, const unsigned char *addr)
{
	struct patch_vport *patch_vport = patch_vport_priv(vport);
	struct patch_config *patchconf;

	patchconf = kmemdup(rtnl_dereference(patch_vport->patchconf),
			  sizeof(struct patch_config), GFP_KERNEL);
	if (!patchconf)
		return -ENOMEM;

	memcpy(patchconf->eth_addr, addr, ETH_ALEN);
	assign_config_rcu(vport, patchconf);

	return 0;
}


static const char *patch_get_name(const struct vport *vport)
{
	const struct patch_vport *patch_vport = patch_vport_priv(vport);
	return patch_vport->name;
}

static const unsigned char *patch_get_addr(const struct vport *vport)
{
	const struct patch_vport *patch_vport = patch_vport_priv(vport);
	return rcu_dereference_rtnl(patch_vport->patchconf)->eth_addr;
}

static int patch_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct patch_vport *patch_vport = patch_vport_priv(vport);
	struct patch_config *patchconf = rcu_dereference_rtnl(patch_vport->patchconf);

	return nla_put_string(skb, ODP_PATCH_ATTR_PEER, patchconf->peer_name);
}

static int patch_send(struct vport *vport, struct sk_buff *skb)
{
	struct patch_vport *patch_vport = patch_vport_priv(vport);
	struct vport *peer = rcu_dereference(patch_vport->peer);
	int skb_len = skb->len;

	if (!peer) {
		kfree_skb(skb);
		vport_record_error(vport, VPORT_E_TX_DROPPED);

		return 0;
	}

	vport_receive(peer, skb);
	return skb_len;
}

const struct vport_ops patch_vport_ops = {
	.type		= ODP_VPORT_TYPE_PATCH,
	.flags		= VPORT_F_GEN_STATS,
	.init		= patch_init,
	.exit		= patch_exit,
	.create		= patch_create,
	.destroy	= patch_destroy,
	.set_addr	= patch_set_addr,
	.get_name	= patch_get_name,
	.get_addr	= patch_get_addr,
	.get_options	= patch_get_options,
	.set_options	= patch_set_options,
	.get_dev_flags	= vport_gen_get_dev_flags,
	.is_running	= vport_gen_is_running,
	.get_operstate	= vport_gen_get_operstate,
	.send		= patch_send,
};
