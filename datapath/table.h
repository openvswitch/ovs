/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef TABLE_H
#define TABLE_H 1

struct tbl_bucket;

struct tbl_node {
	u32 hash;
};

/**
 * struct tbl - hash table
 * @n_buckets: number of buckets (a power of 2 between %TBL_L1_SIZE and
 * %TBL_MAX_BUCKETS)
 * @buckets: pointer to @n_buckets/%TBL_L1_SIZE pointers to %TBL_L1_SIZE pointers
 * to buckets
 * @rcu: RCU callback structure
 * @obj_destructor: Called on each element when the table is destroyed.
 *
 * The @buckets array is logically an array of pointers to buckets.  It is
 * broken into two levels to avoid the need to kmalloc() any object larger than
 * a single page or to use vmalloc().  @buckets is always nonnull, as is each
 * @buckets[i], but each @buckets[i][j] is nonnull only if the specified hash
 * bucket is nonempty (for 0 <= i < @n_buckets/%TBL_L1_SIZE, 0 <= j <
 * %TBL_L1_SIZE).
 */
struct tbl {
	struct rcu_head rcu;
	unsigned int n_buckets;
	struct tbl_bucket __rcu ***buckets;
	unsigned int count;
	void (*obj_destructor)(struct tbl_node *);
};

#define TBL_L2_BITS (PAGE_SHIFT - ilog2(sizeof(struct tbl_bucket *)))
#define TBL_L2_SIZE (1 << TBL_L2_BITS)
#define TBL_L2_SHIFT 0

#define TBL_L1_BITS (PAGE_SHIFT - ilog2(sizeof(struct tbl_bucket **)))
#define TBL_L1_SIZE (1 << TBL_L1_BITS)
#define TBL_L1_SHIFT TBL_L2_BITS

/* For 4 kB pages, this is 1,024 on 32-bit or 512 on 64-bit.  */
#define TBL_MIN_BUCKETS TBL_L2_SIZE

/* For 4 kB pages, this is 1,048,576 on 32-bit or 262,144 on 64-bit. */
#define TBL_MAX_BUCKETS (TBL_L1_SIZE * TBL_L2_SIZE)

struct tbl *tbl_create(unsigned int n_buckets);
void tbl_destroy(struct tbl *, void (*destructor)(struct tbl_node *));
struct tbl_node *tbl_lookup(struct tbl *, void *target, int len, u32 hash,
			    int (*cmp)(const struct tbl_node *, void *target, int len));
int tbl_insert(struct tbl *, struct tbl_node *, u32 hash);
int tbl_remove(struct tbl *, struct tbl_node *);
unsigned int tbl_count(struct tbl *);
int tbl_foreach(struct tbl *,
		int (*callback)(struct tbl_node *, void *aux), void *aux);
struct tbl_node *tbl_next(struct tbl *, u32 *bucketp, u32 *objp);

int tbl_n_buckets(struct tbl *);
struct tbl *tbl_expand(struct tbl *);
void tbl_deferred_destroy(struct tbl *, void (*destructor)(struct tbl_node *));

#endif /* table.h */
