#ifndef CHAIN_H
#define CHAIN_H 1

#include <linux/types.h>

struct sw_flow;
struct sw_flow_key;
struct datapath;


#define TABLE_LINEAR_MAX_FLOWS  100
#define TABLE_HASH_MAX_FLOWS	65536

/* Set of tables chained together in sequence from cheap to expensive. */
#define CHAIN_MAX_TABLES 4
struct sw_chain {
	int n_tables;
	struct sw_table *tables[CHAIN_MAX_TABLES];

	struct datapath *dp;
};

struct sw_chain *chain_create(struct datapath *);
struct sw_flow *chain_lookup(struct sw_chain *, const struct sw_flow_key *);
int chain_insert(struct sw_chain *, struct sw_flow *);
int chain_delete(struct sw_chain *, const struct sw_flow_key *, uint16_t, int);
int chain_timeout(struct sw_chain *);
void chain_destroy(struct sw_chain *);
void chain_print_stats(struct sw_chain *);

#endif /* chain.h */
