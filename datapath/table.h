/* Individual switching tables.  Generally grouped together in a chain (see
 * chain.h). */

#ifndef TABLE_H
#define TABLE_H 1

struct sw_flow;
struct sw_flow_key;
struct datapath;

/* Iterator through the flows stored in a table. */
struct swt_iterator {
	struct sw_flow *flow;	/* Current flow, for use by client. */
	void *private;
};

/* Table statistics. */
struct sw_table_stats {
	const char *name;	/* Human-readable name. */
	unsigned long int n_flows; /* Number of active flows. */
	unsigned long int max_flows; /* Flow capacity. */
};

/* A single table of flows.
 *
 * All functions, except destroy, must be called holding the
 * rcu_read_lock.  destroy must be fully serialized.
 */
struct sw_table {
	/* Searches 'table' for a flow matching 'key', which must not have any
	 * wildcard fields.  Returns the flow if successful, a null pointer
	 * otherwise. */
	struct sw_flow *(*lookup)(struct sw_table *table,
			const struct sw_flow_key *key);

	/* Inserts 'flow' into 'table', replacing any duplicate flow.  Returns
	 * 0 if successful or a negative error.  Error can be due to an
	 * over-capacity table or because the flow is not one of the kind that
	 * the table accepts.
	 *
	 * If successful, 'flow' becomes owned by 'table', otherwise it is
	 * retained by the caller. */
	int (*insert)(struct sw_table *table, struct sw_flow *flow);

	/* Deletes from 'table' any and all flows that match 'key' from
	 * 'table'.  If 'strict' set, wildcards must match.  Returns the 
	 * number of flows that were deleted. */
	int (*delete)(struct sw_table *table, const struct sw_flow_key *key, 
			int strict);

	/* Performs timeout processing on all the flow entries in 'table'.
	 * Returns the number of flow entries deleted through expiration. */
	int (*timeout)(struct datapath *dp, struct sw_table *table);

	/* Destroys 'table', which must not have any users. */
	void (*destroy)(struct sw_table *table);

	int (*iterator)(struct sw_table *, struct swt_iterator *);
	void (*iterator_next)(struct swt_iterator *);
	void (*iterator_destroy)(struct swt_iterator *);

	/* Dumps statistics for 'table' into 'stats'. */
	void (*stats)(struct sw_table *table, struct sw_table_stats *stats);
};

struct sw_table *table_hash_create(unsigned int polynomial,
		unsigned int n_buckets);
struct sw_table *table_hash2_create(unsigned int poly0, unsigned int buckets0,
		unsigned int poly1, unsigned int buckets1);
struct sw_table *table_linear_create(unsigned int max_flows);

#endif /* table.h */
