/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007 The Board of Trustees of The Leland Stanford Junior Univer
sity
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/rcupdate.h>

#include "flow.h"
#include "table.h"
#include "openflow.h"
#include "unit.h"

static const char *
table_name(struct sw_table *table)
{
	struct sw_table_stats stats;
	table->stats(table, &stats);
	return stats.name;
}

static unsigned long int
table_max_flows(struct sw_table *table)
{
	struct sw_table_stats stats;
	table->stats(table, &stats);
	return stats.max_flows;
}

static struct sw_flow *flow_zalloc(int n_actions, gfp_t flags) 
{
	struct sw_flow *flow = flow_alloc(n_actions, flags);
	if (flow) {
		struct ofp_action *actions = flow->actions;
		memset(flow, 0, sizeof *flow);
		flow->actions = actions;
	}
	return flow;
}

static void
simple_insert_delete(struct sw_table *swt, uint16_t wildcards)
{
	struct sw_flow *a_flow = flow_zalloc(0, GFP_KERNEL);
	struct sw_flow *b_flow = flow_zalloc(0, GFP_KERNEL);
	struct sw_flow *found;

	if (!swt) {
		unit_fail("table creation failed");
		return;
	}

	printk("simple_insert_delete: testing %s table\n", table_name(swt));
	*((uint32_t*)a_flow->key.dl_src) = 0x12345678;
	*((uint32_t*)b_flow->key.dl_src) = 0x87654321;

	a_flow->key.nw_src	= 0xdeadbeef;
	b_flow->key.nw_src	= 0x001dd0d0;

	a_flow->key.wildcards = wildcards;
	b_flow->key.wildcards = wildcards;

	if (!(swt->insert(swt, a_flow)))
		unit_fail("insert failed");
	found = swt->lookup(swt, &a_flow->key);
	if(found != a_flow)
		unit_fail("%p != %p", found, a_flow);
	if (swt->lookup(swt, &b_flow->key))
		unit_fail("lookup should not succeed (1)");

	swt->delete(swt, &a_flow->key, 0);
	if (swt->lookup(swt, &a_flow->key))
		unit_fail("lookup should not succeed (3)");

	flow_free(b_flow);
	swt->destroy(swt);
}

static void
multiple_insert_destroy(struct sw_table *swt, int inserts, uint16_t wildcards,
			int min_collisions, int max_collisions)
{
	int i;
	int col = 0;

	if (!swt) {
		unit_fail("table creation failed");
		return;
	}

	printk("inserting %d flows into %s table with max %lu flows: ",
				inserts, table_name(swt), table_max_flows(swt));
	for(i = 0; i < inserts; ++i){
		struct sw_flow *a_flow = flow_zalloc(0, GFP_KERNEL);
		*((uint32_t*)&(a_flow->key.dl_src[0])) = random32();
		a_flow->key.nw_src    = random32();
		a_flow->key.wildcards = wildcards;

		if(!swt->insert(swt, a_flow)) {
			col++;
			flow_free(a_flow);
		}
	}
	printk("%d failures\n", col);
	if (min_collisions <= col && col <= max_collisions)
		printk("\tmin = %d <= %d <= %d = max, OK.\n",
					min_collisions, col, max_collisions);
	else {
		if (col < min_collisions)
			unit_fail("too few collisions (%d < %d)",
				  col, min_collisions);
		else if (col > max_collisions)
			unit_fail("too many collisions (%d > %d)",
				  col, max_collisions);
		printk("(This is statistically possible "
					"but should not occur often.)\n");
	}
	
	swt->destroy(swt);
}

static void
set_random_key(struct sw_flow_key *key, uint16_t wildcards)
{
	key->nw_src = random32();
	key->nw_dst = random32();
	key->in_port = (uint16_t) random32();
	key->dl_vlan = (uint16_t) random32();
	key->dl_type = (uint16_t) random32();
	key->tp_src = (uint16_t) random32();
	key->tp_dst = (uint16_t) random32();
	key->wildcards = wildcards;
	*((uint32_t*)key->dl_src) = random32();
	*(((uint32_t*)key->dl_src) + 1) = random32();
	*((uint32_t*)key->dl_dst) = random32();
	*(((uint32_t*)key->dl_dst) + 1) = random32();
	key->nw_proto = (uint8_t) random32();
}

struct flow_key_entry {
	struct sw_flow_key key;
	struct list_head node;
};

/*
 * Allocates memory for 'n_keys' flow_key_entrys.  Initializes the allocated
 * keys with random values, setting their wildcard values to 'wildcards', and
 * places them all in a list.  Returns a pointer to a flow_key_entry that
 * serves solely as the list's head (its key has not been set).  If allocation
 * fails, returns NULL.  Returned pointer should be freed with vfree (which
 * frees the memory associated with the keys as well.)
 */

static struct flow_key_entry *
allocate_random_keys(int n_keys, uint16_t wildcards)
{
	struct flow_key_entry *entries, *pos;
	struct list_head *keys;

	if (n_keys < 0)
		return NULL;

	entries = vmalloc((n_keys+1) * sizeof *entries);
	if (entries == NULL) {
		unit_fail("cannot allocate memory for %u keys",
					n_keys);
		return NULL;
	}

	keys = &entries->node;
	INIT_LIST_HEAD(keys);

	for(pos = entries+1; pos < (entries + n_keys + 1); pos++) {
		set_random_key(&pos->key, wildcards);
		list_add(&pos->node, keys);
	}

	return entries;
}

/*
 * Attempts to insert the first 'n_flows' flow keys in list 'keys' into table
 * 'swt', where 'keys' is a list of flow_key_entrys.  key_entrys that are
 * inserted into the table are removed from the 'keys' list and placed in
 * 'added' list.  Returns -1 if flow memory allocation fails, else returns the
 * number of flows that were actually inserted (some attempts might fail due to
 * collisions).
 */

static int
insert_flows(struct sw_table *swt, struct list_head *keys, struct list_head *added, int n_flows)
{
	struct flow_key_entry *pos, *next;
	int cnt;

	cnt = 0;


	list_for_each_entry_safe (pos, next, keys, node) {
		struct sw_flow *flow = flow_zalloc(0, GFP_KERNEL);
		if (flow == NULL) {
			unit_fail("Could only allocate %u flows", cnt);
			return -1;
		}

		flow->key = pos->key;

		if (!swt->insert(swt, flow)) {
			flow_free(flow);
			list_del(&pos->node);
		} else {
			list_del(&pos->node);
			list_add(&pos->node, added);
			cnt++;
			if (n_flows != -1 && cnt == n_flows)
				break;
		}
	}

	return cnt;
}

/*
 * Finds and returns the flow_key_entry in list 'keys' matching the passed in
 * flow's key.  If not found, returns NULL.
 */

static struct flow_key_entry *
find_flow(struct list_head *keys, struct sw_flow *flow)
{
	struct flow_key_entry *pos;

	list_for_each_entry(pos, keys, node) {
		if(!memcmp(&pos->key, &flow->key, sizeof(struct sw_flow_key)))
			return pos;
	}

	return NULL;
}

/*
 * Checks that all flow_key_entrys in list 'keys' return successful lookups on
 * the table 'swt'.
 */

static int
check_lookup(struct sw_table *swt, struct list_head *keys)
{
	struct flow_key_entry *pos;

	list_for_each_entry(pos, keys, node) {
		if(swt->lookup(swt, &pos->key) == NULL)
			return -1;
	}

	return 0;
}

/*
 * Checks that all flow_key_entrys in list 'keys' DO NOT return successful
 * lookups in the 'swt' table.
 */

static int
check_no_lookup(struct sw_table *swt, struct list_head *keys)
{
	struct flow_key_entry *pos;

	list_for_each_entry(pos, keys, node) {
		if(swt->lookup(swt, &pos->key) != NULL)
			return -1;
	}

	return 0;
}


/*
 * Compares an iterator's view of the 'swt' table to the list of
 * flow_key_entrys in 'to_find'.  flow_key_entrys that are matched are removed
 * from the 'to_find' list and placed in the 'found' list.  Returns -1 if the
 * iterator cannot be initialized or it encounters a flow with a key not in
 * 'to_find'.  Else returns the number of flows found by the iterator
 * (i.e. there might still be flow keys in the 'to_find' list that were not
 * encountered by the iterator.  it is up to the caller to determine if that is
 * acceptable behavior)
 */

static int
check_iteration(struct sw_table *swt, struct list_head *to_find, struct list_head *found)
{
	struct swt_iterator iter;
	struct flow_key_entry *entry;
	int n_found = 0;

	rcu_read_lock();
	if (!swt->iterator(swt, &iter)) {
		rcu_read_unlock();
		unit_fail("Could not initialize iterator");
		return -1;
	}

	while (iter.flow != NULL) {
		entry = find_flow(to_find, iter.flow);
		if (entry == NULL) {
			unit_fail("UNKNOWN ITERATOR FLOW %p",
				  iter.flow);
			swt->iterator_destroy(&iter);
			rcu_read_unlock();
			return -1;
		}
		n_found++;
		list_del(&entry->node);
		list_add(&entry->node, found);
		swt->iterator_next(&iter);
	}

	swt->iterator_destroy(&iter);
	rcu_read_unlock();

	return n_found;
}

/*
 * Deletes from table 'swt' keys from the list of flow_key_entrys 'keys'.
 * Removes flow_key_entrys of deleted flows from 'keys' and places them in the
 * 'deleted' list.  If 'del_all' == 1, all flows in 'keys' will be deleted,
 * else only every third key will be deleted.  Returns the number flows deleted
 * from the table.
 */

static int
delete_flows(struct sw_table *swt, struct list_head *keys,
		 struct list_head *deleted, uint8_t del_all)
{
	struct flow_key_entry *pos, *next;
	int i, n_del, total_del;

	total_del = 0;
	i = 0;

	list_for_each_entry_safe (pos, next, keys, node) {
		if (del_all == 1 || i % 3 == 0) {
			n_del = swt->delete(swt, &pos->key, 0);
			if (n_del > 1) {
				unit_fail("%d flows deleted for one entry", n_del);
				unit_fail("\tfuture 'errors' could just be product duplicate flow_key_entries");
				unit_fail("THIS IS VERY UNLIKELY...SHOULDN'T HAPPEN OFTEN");
			}
			total_del += n_del;
			list_del(&pos->node);
			list_add(&pos->node, deleted);
		}
		i++;
	}

	return total_del;
}

/*
 * Checks that both iteration and lookups are consistent with the caller's view
 * of the table.  In particular, checks that all keys in flow_key_entry list
 * 'deleted' do not show up in lookup or iteration, and keys in flow_key_entry
 * list 'added' do show up.  'tmp' should be an empty list that can be used for
 * iteration.  References to list_head pointers are needed for 'added' and 'tmp'
 * because iteration will cause the list_heads to change.  Function thus
 * switches 'added' to point to the list of added keys after the iteration.
 */

static int
check_lookup_and_iter(struct sw_table *swt, struct list_head *deleted,
			  struct list_head **added, struct list_head **tmp)
{
	struct list_head *tmp2;
	int ret;

	if (check_no_lookup(swt, deleted) < 0) {
		unit_fail("Uninserted flows returning lookup");
		return -1;
	}

	if (check_lookup(swt, *added) < 0) {
		unit_fail("Inserted flows not returning lookup");
		return -1;
	}

	ret = check_iteration(swt, *added, *tmp);

	tmp2 = *added;
	*added = *tmp;
	*tmp = tmp2;

	if ((*tmp)->next != *tmp) {
		unit_fail("WARNING: not all flows in 'added' found by iterator");
		unit_fail("\tcould be a product of duplicate flow_key_entrys, though should be VERY rare.");
		/* To avoid reoccurence */
		(*tmp)->next = (*tmp)->prev = *tmp;
	}

	return ret;
}

/*
 * Verifies iteration and lookup after inserting 'n_flows', then after deleting
 * some flows, and once again after deleting all flows in table 'swt'.
 */

static int
iterator_test(struct sw_table *swt, int n_flows, uint16_t wildcards)
{
	struct flow_key_entry *allocated, h1, h2;
	struct list_head *added, *deleted, *tmp;
	int ret, n_del, success;

	INIT_LIST_HEAD(&h1.node);
	INIT_LIST_HEAD(&h2.node);

	success = -1;

	allocated = allocate_random_keys(n_flows, wildcards);
	if(allocated == NULL)
		return success;

	deleted = &allocated->node;
	added = &h1.node;
	tmp = &h2.node;

	ret = insert_flows(swt, deleted, added, -1);
	if (ret < 0)
		goto iterator_test_destr;

	n_flows = ret;

	ret = check_lookup_and_iter(swt, deleted, &added, &tmp);
	if (ret < 0) {
		unit_fail("Bad lookup after insertion");
		goto iterator_test_destr;
	} else if (ret != n_flows) {
		unit_fail("Iterator only found %d of %d flows",
			  ret, n_flows);
		goto iterator_test_destr;
	}

	n_del = delete_flows(swt, added, deleted, 0);

	ret = check_lookup_and_iter(swt, deleted, &added, &tmp);
	if (ret < 0) {
		unit_fail("Bad lookup after some deletion");
		goto iterator_test_destr;
	} else if (ret + n_del != n_flows) {
		unit_fail("iterator after deletion inconsistent");
		unit_fail("\tn_del = %d, n_found = %d, n_flows = %d",
			  n_del, ret, n_flows);
		goto iterator_test_destr;
	}

	n_flows -= n_del;

	n_del = delete_flows(swt, added, deleted, 1);
	if (n_del != n_flows) {
		unit_fail("Not all flows deleted - only %d of %d",
			  n_del, n_flows);
		goto iterator_test_destr;
	}

	ret = check_lookup_and_iter(swt, deleted, &added, &tmp);
	if (ret < 0) {
		unit_fail("Bad lookup after all deletion");
		goto iterator_test_destr;
	} else if (ret != 0) {
		unit_fail("Empty table iterator failed.  %d flows found",
			  ret);
		goto iterator_test_destr;
	}

	success = 0;

iterator_test_destr:
	allocated->key.wildcards = OFPFW_ALL;
	swt->delete(swt, &allocated->key, 0);
	vfree(allocated);
	return success;
}


/*
 * Checks lookup and iteration consistency after adding one flow, adding the
 * flow again, and then deleting the flow from table 'swt'.
 */

static int
add_test(struct sw_table *swt, uint16_t wildcards)
{
	struct flow_key_entry *allocated, h1, h2;
	struct list_head *added, *deleted, *tmp, *tmp2;
	int ret, success = -1;

	INIT_LIST_HEAD(&h1.node);
	INIT_LIST_HEAD(&h2.node);

	allocated = allocate_random_keys(2, wildcards);
	if (allocated == NULL)
		return success;

	deleted = &allocated->node;
	added = &h1.node;
	tmp = &h2.node;

	ret = check_lookup_and_iter(swt, deleted, &added, &tmp);
	if (ret < 0) {
		unit_fail("Bad lookup before table modification");
		goto add_test_destr;
	} else if (ret != 0) {
		unit_fail("Iterator on empty table found %d flows",
			  ret);
		goto add_test_destr;
	}

	if (insert_flows(swt, deleted, added, 1) != 1) {
		unit_fail("Cannot add one flow to table");
		goto add_test_destr;
	}

	ret = check_lookup_and_iter(swt, deleted, &added, &tmp);
	if (ret < 0) {
		unit_fail("Bad lookup after single add");
		goto add_test_destr;
	} else if (ret != 1) {
		unit_fail("Iterator on single add found %d flows",
			  ret);
		goto add_test_destr;
	}

	/* Re-adding flow */
	if (insert_flows(swt, added, tmp, 1) != 1) {
		unit_fail("Cannot insert same flow twice");
		goto add_test_destr;
	}

	tmp2 = added;
	added = tmp;
	tmp = tmp2;

	ret = check_lookup_and_iter(swt, deleted, &added, &tmp);
	if (ret < 0) {
		unit_fail("Bad lookup after double add");
		goto add_test_destr;
	} else if (ret != 1) {
		unit_fail("Iterator on double add found %d flows",
			  ret);
		goto add_test_destr;
	}

	ret = delete_flows(swt, added, deleted, 1);
	if (ret != 1) {
		unit_fail("Unexpected %d flows deleted", ret);
		goto add_test_destr;
	}

	ret = check_lookup_and_iter(swt, deleted, &added, &tmp);
	if (ret < 0) {
		unit_fail("Bad lookup after delete.");
		goto add_test_destr;
	} else if (ret != 0) {
		unit_fail("unexpected %d flows found delete", ret);
		goto add_test_destr;
	}

	success = 0;

add_test_destr:
	allocated->key.wildcards = OFPFW_ALL;
	swt->delete(swt, &allocated->key, 0);
	vfree(allocated);
	return success;
}

/*
 * Checks lookup and iteration consistency after each deleting a non-existent
 * flow, adding and then deleting a flow, adding the flow again, and then
 * deleting the flow twice in table 'swt'.
 */

static int
delete_test(struct sw_table *swt, uint16_t wildcards)
{
	struct flow_key_entry *allocated, h1, h2;
	struct list_head *added, *deleted, *tmp, *tmp2;
	int i, ret, success = -1;

	INIT_LIST_HEAD(&h1.node);
	INIT_LIST_HEAD(&h2.node);

	allocated = allocate_random_keys(2, wildcards);
	if (allocated == NULL)
		return success;

	/* Not really added...*/

	added = &allocated->node;
	deleted = &h1.node;
	tmp = &h2.node;

	ret = delete_flows(swt, added, deleted, 1);
	if (ret != 0) {
		unit_fail("Deleting non-existent keys from table returned unexpected value %d",
			  ret);
			goto delete_test_destr;
	}

	for (i = 0; i < 3; i++) {
		ret = check_lookup_and_iter(swt, deleted, &added, &tmp);
		if (ret < 0) {
			if (i == 0)
				unit_fail("Loop %d. Bad lookup before modification.", i);
			else
				unit_fail("Loop %d. Bad lookup after delete.", i);
			goto delete_test_destr;
		} else if (ret != 0) {
			if(i == 0)
				unit_fail("Loop %d. Unexpected %d flows found before modification",
					  i, ret);
			else
				unit_fail("Loop %d. Unexpected %d flows found after delete",
					  i, ret);
			goto delete_test_destr;
		}

		if(i == 2)
			break;

		if (insert_flows(swt, deleted, added, 1) != 1) {
			unit_fail("loop %d: cannot add flow to table", i);
			goto delete_test_destr;
		}

		ret = check_lookup_and_iter(swt, deleted, &added, &tmp);
		if (ret < 0) {
			unit_fail("loop %d: bad lookup after single add.", i);
			goto delete_test_destr;
		} else if (ret != 1) {
			unit_fail("loop %d: unexpected %d flows found after single add",
				  i, ret);
			goto delete_test_destr;
		}

		ret = delete_flows(swt, added, deleted, 1);
		if (ret != 1) {
			unit_fail("loop %d: deleting inserted key from table returned unexpected value %d",
						i, ret);
			goto delete_test_destr;
		}
	}


	ret = delete_flows(swt, deleted, tmp, 1);

	tmp2 = deleted;
	deleted = tmp2;
	tmp = tmp2;

	ret = check_lookup_and_iter(swt, deleted, &added, &tmp);
	if (ret < 0) {
		unit_fail("Bad lookup after double delete.");
		goto delete_test_destr;
	} else if (ret != 0) {
		unit_fail("Unexpected %d flows found after double delete", ret);
		goto delete_test_destr;
	}

	success = 0;

delete_test_destr:
	allocated->key.wildcards = OFPFW_ALL;
	swt->delete(swt, &allocated->key, 0);
	vfree(allocated);
	return success;
}

/*
 * Randomly adds and deletes from a set of size 'n_flows', looping for 'i'
 * iterations.
 */

static int
complex_add_delete_test(struct sw_table *swt, int n_flows, int i, uint16_t wildcards)
{
	struct flow_key_entry *allocated, h1, h2;
	struct list_head *added, *deleted, *tmp;
	int cnt, ret, n_added, n_deleted, success = -1;
	uint8_t del_all;

	INIT_LIST_HEAD(&h1.node);
	INIT_LIST_HEAD(&h2.node);

	allocated = allocate_random_keys(n_flows, wildcards);
	if (allocated == NULL)
		return success;

	deleted = &allocated->node;
	added = &h1.node;
	tmp = &h2.node;

	n_deleted = n_flows;
	n_added = 0;

	for (;i > 0; i--) {
		if (n_deleted != 0 && random32() % 2 == 0) {
			cnt = random32() % n_deleted;
			cnt = insert_flows(swt, deleted, added, cnt);
			if (cnt < 0)
				goto complex_test_destr;
			n_deleted -= cnt;
			n_added += cnt;
		} else {
			if (random32() % 7 == 0)
				del_all = 1;
			else
				del_all = 0;
			cnt = delete_flows(swt, added, deleted, del_all);
			n_deleted += cnt;
			n_added -= cnt;
		}

		ret = check_lookup_and_iter(swt, deleted, &added, &tmp);
		if (ret < 0) {
			unit_fail("Bad lookup on iteration %d.", i);
			goto complex_test_destr;
		}
	}

	delete_flows(swt, added, deleted, 1);
	ret = check_lookup_and_iter(swt, deleted, &added, &tmp);
	if (ret < 0) {
		unit_fail("Bad lookup on end deletion.");
		goto complex_test_destr;
	} else if (ret != 0) {
		unit_fail("Unexpected %d flows found on end deletion", ret);
		goto complex_test_destr;
	}

	success = 0;

complex_test_destr:
	allocated->key.wildcards = OFPFW_ALL;
	swt->delete(swt, &allocated->key, 0);
	vfree(allocated);
	return success;

}

void run_table_t(void)
{
	int mac_buckets, mac_max, linear_max, hash_buckets, hash2_buckets1;
	int hash2_buckets2, num_flows, num_iterations;
	int i;

	struct sw_table *swt;

	/* Most basic operations. */
	simple_insert_delete(table_mac_create(2048, 65536),
			 OFPFW_ALL & ~OFPFW_DL_SRC);
	simple_insert_delete(table_linear_create(2048), 0);
	simple_insert_delete(table_hash_create(0x04C11DB7, 2048), 0);
	simple_insert_delete(table_hash2_create(0x04C11DB7, 2048,
						0x1EDC6F41, 2048), 0);

	/* MAC table operations. */
	multiple_insert_destroy(table_mac_create(2048, 65536), 1024,
				OFPFW_ALL & ~OFPFW_DL_SRC, 0, 0);
	multiple_insert_destroy(table_mac_create(2048, 65536), 2048,
				OFPFW_ALL & ~OFPFW_DL_SRC, 0, 0);
	multiple_insert_destroy(table_mac_create(2048, 65536), 65535,
				OFPFW_ALL & ~OFPFW_DL_SRC, 0, 0);
	multiple_insert_destroy(table_mac_create(2048, 65536),
				131072, OFPFW_ALL & ~OFPFW_DL_SRC, 65536, 65536);

	/* Linear table operations. */
	multiple_insert_destroy(table_linear_create(2048), 1024, 0, 0, 0);
	multiple_insert_destroy(table_linear_create(2048), 2048, 0, 0, 0);
	multiple_insert_destroy(table_linear_create(2048), 8192, 0,
				8192 - 2048, 8192 - 2048);

	/* Hash table operations. */
	multiple_insert_destroy(table_hash_create(0x04C11DB7, 2048), 1024, 0,
				100, 300);
	multiple_insert_destroy(table_hash_create(0x04C11DB7, 2048), 2048, 0,
				500, 1000);
	multiple_insert_destroy(table_hash_create(0x04C11DB7, 1 << 20), 8192, 0,
				0, 50);
	multiple_insert_destroy(table_hash_create(0x04C11DB7, 1 << 20), 65536, 0,
				1500, 3000);

	/* Hash table 2, two hash functions. */
	multiple_insert_destroy(table_hash2_create(0x04C11DB7, 2048,
						0x1EDC6F41, 2048), 1024, 0, 0, 20);
	multiple_insert_destroy(table_hash2_create(0x04C11DB7, 2048,
						0x1EDC6F41, 2048), 2048, 0, 50, 200);
	multiple_insert_destroy(table_hash2_create(0x04C11DB7, 1<<20,
						0x1EDC6F41, 1<<20), 8192, 0, 0, 20);
	multiple_insert_destroy(table_hash2_create(0x04C11DB7, 1<<20,
						0x1EDC6F41, 1<<20), 65536, 0, 0, 20);

	/* Hash table 2, one hash function. */
	multiple_insert_destroy(table_hash2_create(0x04C11DB7, 2048,
						0x04C11DB7, 2048), 1024, 0, 0, 50);
	multiple_insert_destroy(table_hash2_create(0x04C11DB7, 2048,
						0x04C11DB7, 2048), 2048, 0, 100, 300);
	multiple_insert_destroy(table_hash2_create(0x04C11DB7, 1<<20,
						0x04C11DB7, 1<<20), 8192, 0, 0, 20);
	multiple_insert_destroy(table_hash2_create(0x04C11DB7, 1<<20,
						0x04C11DB7, 1<<20), 65536, 0, 0, 100);
	multiple_insert_destroy(table_hash2_create(0x04C11DB7, 1<<20,
						0x04C11DB7, 1<<20), 1<<16, 0, 0, 100);

	mac_buckets = 1024;
	mac_max = 2048;
	linear_max = 2048;
	hash_buckets = 2048;
	hash2_buckets1 = 1024;
	hash2_buckets2 = 1024;

	num_flows = 2300;
	num_iterations = 100;

	printk("\nTesting on each table type:\n");
	printk("  iteration_test on 0 flows\n");
	printk("  iteration_test on %d flows\n", num_flows);
	printk("  add_test\n");
	printk("  delete_test\n");
	printk("  complex_add_delete_test with %d flows and %d iterations\n\n",
				num_flows, num_iterations);

	for (i = 0; i < 4; i++) {
		unsigned int mask = i == 0 ?  : 0;

		if (unit_failed())
			return;

		mask = 0;
		switch (i) {
		case 0:
			swt = table_mac_create(mac_buckets, mac_max);
			mask = OFPFW_ALL & ~OFPFW_DL_SRC;
			break;
		case 1:
			swt = table_linear_create(linear_max);
			break;
		case 2:
			swt = table_hash_create (0x04C11DB7, hash_buckets);
			break;
		case 3:
			swt = table_hash2_create(0x04C11DB7, hash2_buckets1,
						 0x1EDC6F41, hash2_buckets2);
			break;
		default:
			BUG();
			return;
		}

		if (swt == NULL) {
			unit_fail("failed to allocate table %d", i);
			return;
		}
		printk("Testing %s table with %d buckets and %d max flows...\n",
					table_name(swt), mac_buckets, mac_max);
		iterator_test(swt, 0, mask);
		iterator_test(swt, num_flows, mask);
		add_test(swt, mask);
		delete_test(swt, mask);
		complex_add_delete_test(swt, num_flows, num_iterations, mask);
		swt->destroy(swt);
	}
}

