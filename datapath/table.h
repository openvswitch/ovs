/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef TABLE_H
#define TABLE_H 1

struct tbl;
struct tbl_bucket;

struct tbl_node {
	u32 hash;
};

#define TBL_L2_BITS (PAGE_SHIFT - ilog2(sizeof(struct tbl_bucket *)))
#define TBL_L2_SIZE (1 << TBL_L2_BITS)
#define TBL_L2_SHIFT 0

#define TBL_L1_BITS (PAGE_SHIFT - ilog2(sizeof(struct tbl_bucket **)))
#define TBL_L1_SIZE (1 << TBL_L1_BITS)
#define TBL_L1_SHIFT TBL_L2_BITS

/* For 4 kB pages, this is 1,048,576 on 32-bit or 262,144 on 64-bit. */
#define TBL_MAX_BUCKETS (TBL_L1_SIZE * TBL_L2_SIZE)

struct tbl *tbl_create(unsigned int n_buckets);
void tbl_destroy(struct tbl *, void (*destructor)(struct tbl_node *));
struct tbl_node *tbl_lookup(struct tbl *, void *target, u32 hash,
			    int (*cmp)(const struct tbl_node *, void *target));
int tbl_insert(struct tbl *, struct tbl_node *, u32 hash);
int tbl_remove(struct tbl *, struct tbl_node *);
unsigned int tbl_count(struct tbl *);
int tbl_foreach(struct tbl *,
		int (*callback)(struct tbl_node *, void *aux), void *aux);

int tbl_n_buckets(struct tbl *);
struct tbl *tbl_expand(struct tbl *);
void tbl_deferred_destroy(struct tbl *, void (*destructor)(struct tbl_node *));

#endif /* table.h */
