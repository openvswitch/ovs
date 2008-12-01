#ifndef CHAIN_H
#define CHAIN_H 1

#include <linux/types.h>

struct sw_flow;
struct sw_flow_key;
struct ofp_action_header;
struct datapath;


#define TABLE_LINEAR_MAX_FLOWS  100
#define TABLE_HASH_MAX_FLOWS	65536

/* Set of tables chained together in sequence from cheap to expensive. */
#define CHAIN_MAX_TABLES 4
struct sw_chain {
	int n_tables;
	struct sw_table *tables[CHAIN_MAX_TABLES];

	struct datapath *dp;
	struct module *owner;
};

struct sw_chain *chain_create(struct datapath *);
struct sw_flow *chain_lookup(struct sw_chain *, const struct sw_flow_key *);
int chain_insert(struct sw_chain *, struct sw_flow *);
int chain_modify(struct sw_chain *, const struct sw_flow_key *, 
		uint16_t, int, const struct ofp_action_header *, size_t);
int chain_delete(struct sw_chain *, const struct sw_flow_key *, uint16_t, 
		uint16_t, int);
int chain_timeout(struct sw_chain *);
void chain_destroy(struct sw_chain *);

int chain_set_hw_hook(struct sw_table *(*create_hw_table)(void),
		      struct module *owner);
void chain_clear_hw_hook(void);

#endif /* chain.h */
