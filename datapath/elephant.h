/*
 * Copyright (c) 2007-2014 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef ELEPHANT_H
#define ELEPHANT_H 1

#include <linux/flex_array.h>
#include <linux/skbuff.h>

#include "flow.h"

#define ELEPHANT_TBL_MIN_BUCKETS     1024

struct datapath;

struct elephant_table {
    /* xxx Need all these? */
    struct flex_array *buckets;
    unsigned int count, n_buckets;
    struct rcu_head rcu;
    int node_ver;
    u32 hash_seed;
    struct delayed_work work;
};

int ovs_elephant_dp_init(struct datapath *);
void ovs_elephant_dp_exit(struct datapath *);

struct elephant_table *ovs_elephant_tbl_alloc(int new_size);
void ovs_elephant_tbl_destroy(struct elephant_table *);

void ovs_elephant_print_flows(struct datapath *dp);
bool is_elephant(const struct sk_buff *, uint32_t mech, uint32_t arg1,
        uint32_t arg2);

int ovs_elephant_init(void);
void ovs_elephant_exit(void);

#endif /* elephant.h */
