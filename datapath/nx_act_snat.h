#ifdef SUPPORT_SNAT
#ifndef ACT_SNAT_H
#define ACT_SNAT_H

#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>

#include "openflow/nicira-ext.h"
#include "datapath.h"

/* Cache of IP->MAC mappings on the side hidden by the SNAT */
struct snat_mapping {
	struct list_head node;
	uint32_t ip_addr;        /* Stored in network-order */
	uint8_t hw_addr[ETH_ALEN];
	unsigned long used;      /* Last used time (in jiffies). */

	struct rcu_head rcu;
};

struct snat_conf {
	uint32_t ip_addr_start;      /* Stored in host-order */
	uint32_t ip_addr_end;        /* Stored in host-order */
	uint16_t mac_timeout;
	struct list_head mappings;   /* List of snat_mapping entries */
};

#define MAC_TIMEOUT_DEFAULT 120

void snat_local_in(struct sk_buff *skb);
int snat_pre_route(struct sk_buff *skb);
void snat_skb(struct datapath *dp, const struct sk_buff *skb, int out_port);
void snat_maint(struct net_bridge_port *p);
int snat_mod_config(struct datapath *, const struct nx_act_config *);
int snat_free_conf(struct net_bridge_port *p);

#endif
#endif
