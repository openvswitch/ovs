/* Individual switching tables.  Generally grouped together in a chain (see
 * chain.h). */

#ifndef TABLE_H
#define TABLE_H 1

#include <linux/types.h>

struct sw_flow;
struct sw_flow_key;
struct ofp_action_header;
struct datapath;

/* Table statistics. */
struct sw_table_stats {
	const char *name;            /* Human-readable name. */
	uint32_t wildcards;          /* Bitmap of OFPFW_* wildcards that are
	                                supported by the table. */
	unsigned int n_flows;        /* Number of active flows. */
	unsigned int max_flows;      /* Flow capacity. */
	unsigned long int n_lookup;  /* Number of packets looked up. */
	unsigned long int n_matched; /* Number of packets that have hit. */
};

/* Position within an iteration of a sw_table.
 *
 * The contents are private to the table implementation, except that a position
 * initialized to all-zero-bits represents the start of a table. */
struct sw_table_position {
	unsigned long private[4];
};

/* A single table of flows.
 *
 * All functions, except destroy, must be called holding the
 * rcu_read_lock.  destroy must be fully serialized.
 */
struct sw_table {
	/* The number of packets that have been looked up and matched,
	 * respecitvely.  To make these 100% accurate, they should be atomic.  
	 * However, we're primarily concerned about speed. */
	unsigned long long n_lookup;
	unsigned long long n_matched;

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

	/* Modifies the actions in 'table' that match 'key'.  If 'strict'
	 * set, wildcards and priority must match.  Returns the number of flows 
	 * that were modified. */
	int (*modify)(struct sw_table *table, const struct sw_flow_key *key,
			uint16_t priority, int strict,
			const struct ofp_action_header *actions, size_t actions_len);

	/* Deletes from 'table' any and all flows that match 'key' from
	 * 'table'.  If 'out_port' is not OFPP_NONE, then matching entries
	 * must have that port as an argument for an output action.  If 
	 * 'strict' is set, wildcards and priority must match.  Returns the 
	 * number of flows that were deleted. */
	int (*delete)(struct sw_table *table, const struct sw_flow_key *key, 
			uint16_t out_port, uint16_t priority, int strict);

	/* Performs timeout processing on all the flow entries in 'table'.
	 * Returns the number of flow entries deleted through expiration. */
	int (*timeout)(struct datapath *dp, struct sw_table *table);

	/* Destroys 'table', which must not have any users. */
	void (*destroy)(struct sw_table *table);

	/* Iterates through the flow entries in 'table', passing each one
	 * matches 'key' and output port 'out_port' to 'callback'.  The 
	 * callback function should return 0 to continue iteration or a 
	 * nonzero error code to stop.  The iterator function returns either 
	 * 0 if the table iteration completed or the value returned by the 
	 * callback function otherwise.
	 *
	 * The iteration starts at 'position', which may be initialized to
	 * all-zero-bits to iterate from the beginning of the table.  If the
	 * iteration terminates due to an error from the callback function,
	 * 'position' is updated to a value that can be passed back to the
	 * iterator function to continue iteration later from the same position
	 * that caused the error (assuming that that flow entry has not been
	 * deleted in the meantime). */
	int (*iterate)(struct sw_table *table,
		       const struct sw_flow_key *key, uint16_t out_port,
		       struct sw_table_position *position,
		       int (*callback)(struct sw_flow *flow, void *private),
		       void *private);

	/* Dumps statistics for 'table' into 'stats'. */
	void (*stats)(struct sw_table *table, struct sw_table_stats *stats);
};

struct sw_table *table_hash_create(unsigned int polynomial,
		unsigned int n_buckets);
struct sw_table *table_hash2_create(unsigned int poly0, unsigned int buckets0,
		unsigned int poly1, unsigned int buckets1);
struct sw_table *table_linear_create(unsigned int max_flows);

#endif /* table.h */
