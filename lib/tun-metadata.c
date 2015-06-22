/*
 * Copyright (c) 2015 Nicira, Inc.
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
#include <errno.h>
#include <stdbool.h>

#include "bitmap.h"
#include "compiler.h"
#include "hmap.h"
#include "match.h"
#include "nx-match.h"
#include "odp-netlink.h"
#include "ofp-util.h"
#include "ovs-thread.h"
#include "ovs-rcu.h"
#include "packets.h"
#include "tun-metadata.h"

struct tun_meta_entry {
    struct hmap_node node;      /* In struct tun_table's key_hmap. */
    uint32_t key;               /* (class << 16) | type. */
    struct tun_metadata_loc loc;
    bool valid;                 /* True if allocated to a class and type. */
};

/* Maps from Geneve option class+type to positions in a struct tun_metadata's
 * 'opts' array.  */
struct tun_table {
    /* TUN_METADATA<i> is stored in element <i>. */
    struct tun_meta_entry entries[TUN_METADATA_NUM_OPTS];

    /* Each bit represents 4 bytes of space, 0-bits are free space. */
    unsigned long alloc_map[BITMAP_N_LONGS(TUN_METADATA_TOT_OPT_SIZE / 4)];

    /* The valid elements in entries[], indexed by class+type. */
    struct hmap key_hmap;
};
BUILD_ASSERT_DECL(TUN_METADATA_TOT_OPT_SIZE % 4 == 0);

static struct ovs_mutex tab_mutex = OVS_MUTEX_INITIALIZER;
static OVSRCU_TYPE(struct tun_table *) metadata_tab;

static enum ofperr tun_metadata_add_entry(struct tun_table *map, uint8_t idx,
                                          uint16_t opt_class, uint8_t type,
                                          uint8_t len) OVS_REQUIRES(tab_mutex);
static void tun_metadata_del_entry(struct tun_table *map, uint8_t idx)
            OVS_REQUIRES(tab_mutex);
static void memcpy_to_metadata(struct tun_metadata *dst, const void *src,
                               const struct tun_metadata_loc *);
static void memcpy_from_metadata(void *dst, const struct tun_metadata *src,
                                 const struct tun_metadata_loc *);

static uint32_t
tun_meta_key(ovs_be16 class, uint8_t type)
{
    return (OVS_FORCE uint16_t)class << 8 | type;
}

static ovs_be16
tun_key_class(uint32_t key)
{
    return (OVS_FORCE ovs_be16)(key >> 8);
}

static uint8_t
tun_key_type(uint32_t key)
{
    return key & 0xff;
}

/* Returns a newly allocated tun_table.  If 'old_map' is nonnull then the new
 * tun_table is a deep copy of the old one. */
static struct tun_table *
table_alloc(const struct tun_table *old_map) OVS_REQUIRES(tab_mutex)
{
    struct tun_table *new_map;

    new_map = xzalloc(sizeof *new_map);

    if (old_map) {
        struct tun_meta_entry *entry;

        *new_map = *old_map;
        hmap_init(&new_map->key_hmap);

        HMAP_FOR_EACH (entry, node, &old_map->key_hmap) {
            struct tun_meta_entry *new_entry;
            struct tun_metadata_loc_chain *chain;

            new_entry = &new_map->entries[entry - old_map->entries];
            hmap_insert(&new_map->key_hmap, &new_entry->node, entry->node.hash);

            chain = &new_entry->loc.c;
            while (chain->next) {
                chain->next = xmemdup(chain->next, sizeof *chain->next);
                chain = chain->next;
            }
        }
    } else {
        hmap_init(&new_map->key_hmap);
    }

    return new_map;
}

/* Frees 'map' and all the memory it owns. */
static void
table_free(struct tun_table *map) OVS_REQUIRES(tab_mutex)
{
    struct tun_meta_entry *entry;

    if (!map) {
        return;
    }

    HMAP_FOR_EACH (entry, node, &map->key_hmap) {
        tun_metadata_del_entry(map, entry - map->entries);
    }

    free(map);
}

/* Creates a global tunnel metadata mapping table, if none already exists. */
void
tun_metadata_init(void)
{
    ovs_mutex_lock(&tab_mutex);

    if (!ovsrcu_get_protected(struct tun_table *, &metadata_tab)) {
        ovsrcu_set(&metadata_tab, table_alloc(NULL));
    }

    ovs_mutex_unlock(&tab_mutex);
}

enum ofperr
tun_metadata_table_mod(struct ofputil_geneve_table_mod *gtm)
{
    struct tun_table *old_map, *new_map;
    struct ofputil_geneve_map *ofp_map;
    enum ofperr err = 0;

    ovs_mutex_lock(&tab_mutex);

    old_map = ovsrcu_get_protected(struct tun_table *, &metadata_tab);

    switch (gtm->command) {
    case NXGTMC_ADD:
        new_map = table_alloc(old_map);

        LIST_FOR_EACH (ofp_map, list_node, &gtm->mappings) {
            err = tun_metadata_add_entry(new_map, ofp_map->index,
                                         ofp_map->option_class,
                                         ofp_map->option_type,
                                         ofp_map->option_len);
            if (err) {
                table_free(new_map);
                goto out;
            }
        }
        break;

    case NXGTMC_DELETE:
        new_map = table_alloc(old_map);

        LIST_FOR_EACH (ofp_map, list_node, &gtm->mappings) {
            tun_metadata_del_entry(new_map, ofp_map->index);
        }
        break;

    case NXGTMC_CLEAR:
        new_map = table_alloc(NULL);
        break;

    default:
        OVS_NOT_REACHED();
    }

    ovsrcu_set(&metadata_tab, new_map);
    ovsrcu_postpone(table_free, old_map);

out:
    ovs_mutex_unlock(&tab_mutex);
    return err;
}

void
tun_metadata_table_request(struct ofputil_geneve_table_reply *gtr)
{
    struct tun_table *map = ovsrcu_get(struct tun_table *, &metadata_tab);
    int i;

    gtr->max_option_space = TUN_METADATA_TOT_OPT_SIZE;
    gtr->max_fields = TUN_METADATA_NUM_OPTS;
    list_init(&gtr->mappings);

    for (i = 0; i < TUN_METADATA_NUM_OPTS; i++) {
        struct tun_meta_entry *entry = &map->entries[i];
        struct ofputil_geneve_map *map;

        if (!entry->valid) {
            continue;
        }

        map = xmalloc(sizeof *map);
        map->option_class = ntohs(tun_key_class(entry->key));
        map->option_type = tun_key_type(entry->key);
        map->option_len = entry->loc.len;
        map->index = i;

        list_push_back(&gtr->mappings, &map->list_node);
    }
}

/* Copies the value of field 'mf' from 'metadata' into 'value'.
 *
 * 'mf' must be an MFF_TUN_METADATA* field.
 *
 * This uses the global tunnel metadata mapping table created by
 * tun_metadata_init().  If no such table has been created or if 'mf' hasn't
 * been allocated in it yet, this just zeros 'value'. */
void
tun_metadata_read(const struct tun_metadata *metadata,
                  const struct mf_field *mf, union mf_value *value)
{
    struct tun_table *map = ovsrcu_get(struct tun_table *, &metadata_tab);
    unsigned int idx = mf->id - MFF_TUN_METADATA0;
    struct tun_metadata_loc *loc;

    if (!map) {
        memset(value->tun_metadata, 0, mf->n_bytes);
        return;
    }

    loc = &map->entries[idx].loc;

    memset(value->tun_metadata, 0, mf->n_bytes - loc->len);
    memcpy_from_metadata(value->tun_metadata + mf->n_bytes - loc->len,
                         metadata, loc);
}

/* Copies 'value' into field 'mf' in 'metadata'.
 *
 * 'mf' must be an MFF_TUN_METADATA* field.
 *
 * This uses the global tunnel metadata mapping table created by
 * tun_metadata_init().  If no such table has been created or if 'mf' hasn't
 * been allocated in it yet, this function does nothing. */
void
tun_metadata_write(struct tun_metadata *metadata,
                   const struct mf_field *mf, const union mf_value *value)
{
    struct tun_table *map = ovsrcu_get(struct tun_table *, &metadata_tab);
    unsigned int idx = mf->id - MFF_TUN_METADATA0;
    struct tun_metadata_loc *loc;

    if (!map || !map->entries[idx].valid) {
        return;
    }

    loc = &map->entries[idx].loc;

    ULLONG_SET1(metadata->opt_map, idx);
    memcpy_to_metadata(metadata, value->tun_metadata + mf->n_bytes - loc->len,
                       loc);
}

static const struct tun_metadata_loc *
metadata_loc_from_match(struct tun_table *map, struct match *match,
                        unsigned int idx, unsigned int field_len)
{
    ovs_assert(idx < TUN_METADATA_NUM_OPTS);

    if (map) {
        if (map->entries[idx].valid) {
            return &map->entries[idx].loc;
        } else {
            return NULL;
        }
    }

    if (match->tun_md.alloc_offset + field_len >= TUN_METADATA_TOT_OPT_SIZE ||
        match->tun_md.loc[idx].len) {
        return NULL;
    }

    match->tun_md.loc[idx].len = field_len;
    match->tun_md.loc[idx].c.offset = match->tun_md.alloc_offset;
    match->tun_md.loc[idx].c.len = field_len;
    match->tun_md.loc[idx].c.next = NULL;
    match->tun_md.alloc_offset += field_len;
    match->tun_md.valid = true;

    return &match->tun_md.loc[idx];
}

/* Makes 'match' match 'value'/'mask' on field 'mf'.
 *
 * 'mf' must be an MFF_TUN_METADATA* field.
 *
 * If there is global tunnel metadata matching table, this function is
 * effective only if there is already a mapping for 'mf'.  Otherwise, the
 * metadata mapping table integrated into 'match' is used, adding 'mf' to its
 * mapping table if it isn't already mapped (and if there is room).  If 'mf'
 * isn't or can't be mapped, this function returns without modifying 'match'.
 *
 * 'value' may be NULL; if so, then 'mf' is made to match on an all-zeros
 * value.
 *
 * 'mask' may be NULL; if so, then 'mf' is made exact-match.
 */
void
tun_metadata_set_match(const struct mf_field *mf, const union mf_value *value,
                       const union mf_value *mask, struct match *match)
{
    struct tun_table *map = ovsrcu_get(struct tun_table *, &metadata_tab);
    const struct tun_metadata_loc *loc;
    unsigned int idx = mf->id - MFF_TUN_METADATA0;
    unsigned int field_len;
    unsigned int data_offset;
    union mf_value data;

    field_len = mf_field_len(mf, value, mask);
    loc = metadata_loc_from_match(map, match, idx, field_len);
    if (!loc) {
        return;
    }

    data_offset = mf->n_bytes - loc->len;

    if (!value) {
        memset(data.tun_metadata, 0, loc->len);
    } else if (!mask) {
        memcpy(data.tun_metadata, value->tun_metadata + data_offset, loc->len);
    } else {
        int i;
        for (i = 0; i < loc->len; i++) {
            data.tun_metadata[i] = value->tun_metadata[data_offset + i] &
                                   mask->tun_metadata[data_offset + i];
        }
    }
    ULLONG_SET1(match->flow.tunnel.metadata.opt_map, idx);
    memcpy_to_metadata(&match->flow.tunnel.metadata, data.tun_metadata, loc);

    if (!value) {
        memset(data.tun_metadata, 0, loc->len);
    } else if (!mask) {
        memset(data.tun_metadata, 0xff, loc->len);
    } else {
        memcpy(data.tun_metadata, mask->tun_metadata + data_offset, loc->len);
    }
    ULLONG_SET1(match->wc.masks.tunnel.metadata.opt_map, idx);
    memcpy_to_metadata(&match->wc.masks.tunnel.metadata, data.tun_metadata, loc);
}

/* Copies all MFF_TUN_METADATA* fields from 'metadata' to 'flow_metadata'. */
void
tun_metadata_get_fmd(const struct tun_metadata *metadata,
                     struct match *flow_metadata)
{
    struct tun_table *map;
    int i;

    map = metadata->tab;
    if (!map) {
        map = ovsrcu_get(struct tun_table *, &metadata_tab);
    }

    ULLONG_FOR_EACH_1 (i, metadata->opt_map) {
        union mf_value opts;
        const struct tun_metadata_loc *old_loc = &map->entries[i].loc;
        const struct tun_metadata_loc *new_loc;

        new_loc = metadata_loc_from_match(NULL, flow_metadata, i, old_loc->len);

        memcpy_from_metadata(opts.tun_metadata, metadata, old_loc);
        memcpy_to_metadata(&flow_metadata->flow.tunnel.metadata,
                           opts.tun_metadata, new_loc);

        memset(opts.tun_metadata, 0xff, old_loc->len);
        memcpy_to_metadata(&flow_metadata->wc.masks.tunnel.metadata,
                           opts.tun_metadata, new_loc);
    }
}

static uint32_t
tun_meta_hash(uint32_t key)
{
    return hash_int(key, 0);
}

static struct tun_meta_entry *
tun_meta_find_key(const struct hmap *hmap, uint32_t key)
{
    struct tun_meta_entry *entry;

    HMAP_FOR_EACH_IN_BUCKET (entry, node, tun_meta_hash(key), hmap) {
        if (entry->key == key) {
            return entry;
        }
    }
    return NULL;
}

static void
memcpy_to_metadata(struct tun_metadata *dst, const void *src,
                   const struct tun_metadata_loc *loc)
{
    const struct tun_metadata_loc_chain *chain = &loc->c;
    int addr = 0;

    while (chain) {
        memcpy(dst->opts + loc->c.offset + addr, (uint8_t *)src + addr,
               chain->len);
        addr += chain->len;
        chain = chain->next;
    }
}

static void
memcpy_from_metadata(void *dst, const struct tun_metadata *src,
                     const struct tun_metadata_loc *loc)
{
    const struct tun_metadata_loc_chain *chain = &loc->c;
    int addr = 0;

    while (chain) {
        memcpy((uint8_t *)dst + addr, src->opts + loc->c.offset + addr,
               chain->len);
        addr += chain->len;
        chain = chain->next;
    }
}

static int
tun_metadata_alloc_chain(struct tun_table *map, uint8_t len,
                         struct tun_metadata_loc_chain *loc)
                         OVS_REQUIRES(tab_mutex)
{
    int alloc_len = len / 4;
    int scan_start = 0;
    int scan_end = TUN_METADATA_TOT_OPT_SIZE / 4;
    int pos_start, pos_end, pos_len;
    int best_start = 0, best_len = 0;

    while (true) {
        pos_start = bitmap_scan(map->alloc_map, 0, scan_start, scan_end);
        if (pos_start == scan_end) {
            break;
        }

        pos_end = bitmap_scan(map->alloc_map, 1, pos_start,
                              MIN(pos_start + alloc_len, scan_end));
        pos_len = pos_end - pos_start;
        if (pos_len == alloc_len) {
            goto found;
        }

        if (pos_len > best_len) {
            best_start = pos_start;
            best_len = pos_len;
        }
        scan_start = pos_end + 1;
    }

    if (best_len == 0) {
        return ENOSPC;
    }

    pos_start = best_start;
    pos_len = best_len;

found:
    bitmap_set_multiple(map->alloc_map, pos_start, pos_len, 1);
    loc->offset = pos_start * 4;
    loc->len = pos_len * 4;

    return 0;
}

static enum ofperr
tun_metadata_add_entry(struct tun_table *map, uint8_t idx, uint16_t opt_class,
                       uint8_t type, uint8_t len) OVS_REQUIRES(tab_mutex)
{
    struct tun_meta_entry *entry;
    struct tun_metadata_loc_chain *cur_chain, *prev_chain;

    ovs_assert(idx < TUN_METADATA_NUM_OPTS);

    entry = &map->entries[idx];
    if (entry->valid) {
        return OFPERR_NXGTMFC_ALREADY_MAPPED;
    }

    entry->key = tun_meta_key(htons(opt_class), type);
    if (tun_meta_find_key(&map->key_hmap, entry->key)) {
        return OFPERR_NXGTMFC_DUP_ENTRY;
    }

    entry->valid = true;
    hmap_insert(&map->key_hmap, &entry->node,
                tun_meta_hash(entry->key));

    entry->loc.len = len;
    cur_chain = &entry->loc.c;
    memset(cur_chain, 0, sizeof *cur_chain);
    prev_chain = NULL;

    while (len) {
        int err;

        if (!cur_chain) {
            cur_chain = xzalloc(sizeof *cur_chain);
        }

        err = tun_metadata_alloc_chain(map, len, cur_chain);
        if (err) {
            tun_metadata_del_entry(map, idx);
            return OFPERR_NXGTMFC_TABLE_FULL;
        }

        len -= cur_chain->len;

        if (prev_chain) {
            prev_chain->next = cur_chain;
        }
        prev_chain = cur_chain;
        cur_chain = NULL;
    }

    return 0;
}

static void
tun_metadata_del_entry(struct tun_table *map, uint8_t idx)
                       OVS_REQUIRES(tab_mutex)
{
    struct tun_meta_entry *entry;
    struct tun_metadata_loc_chain *chain;

    if (idx >= TUN_METADATA_NUM_OPTS) {
        return;
    }

    entry = &map->entries[idx];
    if (!entry->valid) {
        return;
    }

    chain = &entry->loc.c;
    while (chain) {
        struct tun_metadata_loc_chain *next = chain->next;

        bitmap_set_multiple(map->alloc_map, chain->offset / 4,
                            chain->len / 4, 0);
        if (chain != &entry->loc.c) {
            free(chain);
        }
        chain = next;
    }

    entry->valid = false;
    hmap_remove(&map->key_hmap, &entry->node);
    memset(&entry->loc, 0, sizeof entry->loc);
}

static int
tun_metadata_from_geneve__(struct tun_table *map, const struct geneve_opt *opt,
                           const struct geneve_opt *flow_opt, int opts_len,
                           struct tun_metadata *metadata)
{
    if (!map) {
        return 0;
    }

    while (opts_len > 0) {
        int len;
        struct tun_meta_entry *entry;

        if (opts_len < sizeof(*opt)) {
            return EINVAL;
        }

        len = sizeof(*opt) + flow_opt->length * 4;
        if (len > opts_len) {
            return EINVAL;
        }

        entry = tun_meta_find_key(&map->key_hmap,
                                  tun_meta_key(flow_opt->opt_class,
                                               flow_opt->type));
        if (entry) {
            if (entry->loc.len == flow_opt->length * 4) {
                memcpy_to_metadata(metadata, opt + 1, &entry->loc);
                ULLONG_SET1(metadata->opt_map, entry - map->entries);
            } else {
                return EINVAL;
            }
        } else if (flow_opt->type & GENEVE_CRIT_OPT_TYPE) {
            return EINVAL;
        }

        opt = opt + len / sizeof(*opt);
        flow_opt = flow_opt + len / sizeof(*opt);
        opts_len -= len;
    }

    return 0;
}

int
tun_metadata_from_geneve_nlattr(const struct nlattr *attr,
                                const struct nlattr *flow_attrs,
                                size_t flow_attr_len,
                                const struct tun_metadata *flow_metadata,
                                struct tun_metadata *metadata)
{
    struct tun_table *map;
    bool is_mask = !!flow_attrs;
    const struct nlattr *flow;

    if (is_mask) {
        const struct nlattr *tnl_key;
        int mask_len = nl_attr_get_size(attr);

        tnl_key = nl_attr_find__(flow_attrs, flow_attr_len, OVS_KEY_ATTR_TUNNEL);
        if (!tnl_key) {
            return mask_len ? EINVAL : 0;
        }

        flow = nl_attr_find_nested(tnl_key, OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS);
        if (!flow) {
            return mask_len ? EINVAL : 0;
        }

        if (mask_len != nl_attr_get_size(flow)) {
            return EINVAL;
        }
    } else {
        flow = attr;
    }

    if (!is_mask) {
        map = ovsrcu_get(struct tun_table *, &metadata_tab);
        metadata->tab = map;
    } else {
        map = flow_metadata->tab;
    }

    return tun_metadata_from_geneve__(map, nl_attr_get(attr), nl_attr_get(flow),
                                      nl_attr_get_size(flow), metadata);
}

int
tun_metadata_from_geneve_header(const struct geneve_opt *opts, int opt_len,
                                struct tun_metadata *metadata)
{
    struct tun_table *map;

    map = ovsrcu_get(struct tun_table *, &metadata_tab);
    metadata->tab = map;

    return tun_metadata_from_geneve__(map, opts, opts, opt_len, metadata);
}

static void
tun_metadata_to_geneve__(const struct tun_metadata *flow, struct ofpbuf *b,
                         bool *crit_opt)
{
    struct tun_table *map;
    int i;

    map = flow->tab;
    if (!map) {
        map = ovsrcu_get(struct tun_table *, &metadata_tab);
    }

    *crit_opt = false;

    ULLONG_FOR_EACH_1 (i, flow->opt_map) {
        struct tun_meta_entry *entry = &map->entries[i];
        struct geneve_opt *opt;

        opt = ofpbuf_put_uninit(b, sizeof *opt + entry->loc.len);

        opt->opt_class = tun_key_class(entry->key);
        opt->type = tun_key_type(entry->key);
        opt->length = entry->loc.len / 4;
        opt->r1 = 0;
        opt->r2 = 0;
        opt->r3 = 0;

        memcpy_from_metadata(opt + 1, flow, &entry->loc);
        *crit_opt |= !!(opt->type & GENEVE_CRIT_OPT_TYPE);
    }
}

void
tun_metadata_to_geneve_nlattr_flow(const struct tun_metadata *flow,
                                   struct ofpbuf *b)
{
    size_t nlattr_offset;
    bool crit_opt;

    if (!flow->opt_map) {
        return;
    }

    /* For all intents and purposes, the Geneve options are nested
     * attributes even if this doesn't show up directly to netlink. It's
     * similar enough that we can use the same mechanism. */
    nlattr_offset = nl_msg_start_nested(b, OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS);

    tun_metadata_to_geneve__(flow, b, &crit_opt);

    nl_msg_end_nested(b, nlattr_offset);
}

int
tun_metadata_to_geneve_header(const struct tun_metadata *flow,
                              struct geneve_opt *opts, bool *crit_opt)
{
    struct ofpbuf b;

    ofpbuf_use_stack(&b, opts, GENEVE_TOT_OPT_SIZE);
    tun_metadata_to_geneve__(flow, &b, crit_opt);

    return b.size;
}

void
tun_metadata_to_geneve_nlattr_mask(const struct ofpbuf *key,
                                   const struct tun_metadata *mask,
                                   const struct tun_metadata *flow,
                                   struct ofpbuf *b)
{
    struct tun_table *map = flow->tab;
    const struct nlattr *tnl_key, *geneve_key;
    struct nlattr *geneve_mask;
    struct geneve_opt *opt;
    int opts_len;

    if (!map) {
        return;
    }

    tnl_key = nl_attr_find(key, 0, OVS_KEY_ATTR_TUNNEL);
    if (!tnl_key) {
        return;
    }

    geneve_key = nl_attr_find_nested(tnl_key,
                                     OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS);
    if (!geneve_key) {
        return;
    }

    geneve_mask = ofpbuf_tail(b);
    nl_msg_put(b, geneve_key, geneve_key->nla_len);

    /* All of these options have already been validated, so no need
     * for sanity checking. */
    opt = CONST_CAST(struct geneve_opt *, nl_attr_get(geneve_mask));
    opts_len = nl_attr_get_size(geneve_mask);

    while (opts_len > 0) {
        struct tun_meta_entry *entry;
        int len = sizeof(*opt) + opt->length * 4;

        entry = tun_meta_find_key(&map->key_hmap,
                                  tun_meta_key(opt->opt_class, opt->type));
        if (entry) {
            memcpy_from_metadata(opt + 1, mask, &entry->loc);
        } else {
            memset(opt + 1, 0, opt->length * 4);
        }

        opt->opt_class = htons(0xffff);
        opt->type = 0xff;
        opt->length = 0x1f;
        opt->r1 = 0;
        opt->r2 = 0;
        opt->r3 = 0;

        opt = opt + len / sizeof(*opt);
        opts_len -= len;
    }
}

static const struct tun_metadata_loc *
metadata_loc_from_match_read(struct tun_table *map, const struct match *match,
                             unsigned int idx)
{
    if (match->tun_md.valid) {
        return &match->tun_md.loc[idx];
    }

    return &map->entries[idx].loc;
}

void
tun_metadata_to_nx_match(struct ofpbuf *b, enum ofp_version oxm,
                         const struct match *match)
{
    struct tun_table *map = ovsrcu_get(struct tun_table *, &metadata_tab);
    const struct tun_metadata *metadata = &match->flow.tunnel.metadata;
    const struct tun_metadata *mask = &match->wc.masks.tunnel.metadata;
    int i;

    ULLONG_FOR_EACH_1 (i, mask->opt_map) {
        const struct tun_metadata_loc *loc;
        union mf_value opts;
        union mf_value mask_opts;

        loc = metadata_loc_from_match_read(map, match, i);
        memcpy_from_metadata(opts.tun_metadata, metadata, loc);
        memcpy_from_metadata(mask_opts.tun_metadata, mask, loc);
        nxm_put(b, MFF_TUN_METADATA0 + i, oxm, opts.tun_metadata,
                mask_opts.tun_metadata, loc->len);
    }
}

void
tun_metadata_match_format(struct ds *s, const struct match *match)
{
    struct tun_table *map = ovsrcu_get(struct tun_table *, &metadata_tab);
    const struct tun_metadata *metadata = &match->flow.tunnel.metadata;
    const struct tun_metadata *mask = &match->wc.masks.tunnel.metadata;
    unsigned int i;

    ULLONG_FOR_EACH_1 (i, mask->opt_map) {
        const struct tun_metadata_loc *loc;
        union mf_value opts;

        loc = metadata_loc_from_match_read(map, match, i);

        ds_put_format(s, "tun_metadata%u=", i);
        memcpy_from_metadata(opts.tun_metadata, metadata, loc);
        ds_put_hex(s, opts.tun_metadata, loc->len);

        memcpy_from_metadata(opts.tun_metadata, mask, loc);
        if (!is_all_ones(opts.tun_metadata, loc->len)) {
            ds_put_char(s, '/');
            ds_put_hex(s, opts.tun_metadata, loc->len);
        }
        ds_put_char(s, ',');
    }
}
