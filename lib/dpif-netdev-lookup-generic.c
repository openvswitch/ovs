/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016, 2017 Nicira, Inc.
 * Copyright (c) 2019 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "dpif-netdev.h"
#include "dpif-netdev-private.h"

#include "bitmap.h"
#include "cmap.h"

#include "dp-packet.h"
#include "dpif.h"
#include "dpif-netdev-perf.h"
#include "dpif-provider.h"
#include "flow.h"
#include "packets.h"
#include "pvector.h"

/* Returns a hash value for the bits of 'key' where there are 1-bits in
 * 'mask'. */
static inline uint32_t
netdev_flow_key_hash_in_mask(const struct netdev_flow_key *key,
                             const struct netdev_flow_key *mask)
{
    const uint64_t *p = miniflow_get_values(&mask->mf);
    uint32_t hash = 0;
    uint64_t value;

    NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP (value, key, mask->mf.map) {
        hash = hash_add64(hash, value & *p);
        p++;
    }

    return hash_finish(hash, (p - miniflow_get_values(&mask->mf)) * 8);
}

uint32_t
dpcls_subtable_lookup_generic(struct dpcls_subtable *subtable,
                              uint32_t keys_map,
                              const struct netdev_flow_key *keys[],
                              struct dpcls_rule **rules)
{
    int i;
    uint32_t found_map;

    /* Compute hashes for the remaining keys.  Each search-key is
     * masked with the subtable's mask to avoid hashing the wildcarded
     * bits. */
    uint32_t hashes[NETDEV_MAX_BURST];
    ULLONG_FOR_EACH_1 (i, keys_map) {
        hashes[i] = netdev_flow_key_hash_in_mask(keys[i], &subtable->mask);
    }

    /* Lookup. */
    const struct cmap_node *nodes[NETDEV_MAX_BURST];
    found_map = cmap_find_batch(&subtable->rules, keys_map, hashes, nodes);

    /* Check results.  When the i-th bit of found_map is set, it means
     * that a set of nodes with a matching hash value was found for the
     * i-th search-key.  Due to possible hash collisions we need to check
     * which of the found rules, if any, really matches our masked
     * search-key. */
    ULLONG_FOR_EACH_1 (i, found_map) {
        struct dpcls_rule *rule;

        CMAP_NODE_FOR_EACH (rule, cmap_node, nodes[i]) {
            if (OVS_LIKELY(dpcls_rule_matches_key(rule, keys[i]))) {
                rules[i] = rule;
                /* Even at 20 Mpps the 32-bit hit_cnt cannot wrap
                 * within one second optimization interval. */
                subtable->hit_cnt++;
                goto next;
            }
        }

        /* None of the found rules was a match.  Reset the i-th bit to
         * keep searching this key in the next subtable. */
        ULLONG_SET0(found_map, i);  /* Did not match. */
    next:
        ; /* Keep Sparse happy. */
    }

    return found_map;
}
