/*
 * Copyright (c) 2024 Red Hat, Inc.
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
#include "ofproto-dpif-lsample.h"

#include "cmap.h"
#include "hash.h"
#include "ofproto.h"
#include "openvswitch/thread.h"

/* Dpif local sampling.
 *
 * Thread safety: dpif_lsample allows lockless concurrent reads of local
 * sampling exporters as long as the following restrictions are met:
 *   1) While the last reference is being dropped, i.e: a thread is calling
 *      "dpif_lsample_unref" on the last reference, other threads cannot call
 *      "dpif_lsample_ref".
 *   2) Threads do not quiese while holding references to internal
 *      lsample_exporter objects.
 */

struct dpif_lsample {
    struct cmap exporters;          /* Contains lsample_exporter_node instances
                                     * indexed by collector_set_id. */
    struct ovs_mutex mutex;         /* Protects concurrent insertion/deletion
                                     * of exporters. */
    struct ovs_refcount ref_cnt;    /* Controls references to this instance. */
};

struct lsample_exporter {
    struct ofproto_lsample_options options;
};

struct lsample_exporter_node {
    struct cmap_node node;              /* In dpif_lsample->exporters. */
    struct lsample_exporter exporter;
};

static void
dpif_lsample_delete_exporter(struct dpif_lsample *lsample,
                             struct lsample_exporter_node *node)
{
    ovs_mutex_lock(&lsample->mutex);
    cmap_remove(&lsample->exporters, &node->node,
                hash_int(node->exporter.options.collector_set_id, 0));
    ovs_mutex_unlock(&lsample->mutex);

    ovsrcu_postpone(free, node);
}

/* Adds an exporter with the provided options which are copied. */
static struct lsample_exporter_node *
dpif_lsample_add_exporter(struct dpif_lsample *lsample,
                          const struct ofproto_lsample_options *options)
{
    struct lsample_exporter_node *node;

    node = xzalloc(sizeof *node);
    node->exporter.options = *options;

    ovs_mutex_lock(&lsample->mutex);
    cmap_insert(&lsample->exporters, &node->node,
                hash_int(options->collector_set_id, 0));
    ovs_mutex_unlock(&lsample->mutex);

    return node;
}

static struct lsample_exporter_node *
dpif_lsample_find_exporter_node(const struct dpif_lsample *lsample,
                                const uint32_t collector_set_id)
{
    struct lsample_exporter_node *node;

    CMAP_FOR_EACH_WITH_HASH (node, node, hash_int(collector_set_id, 0),
                             &lsample->exporters) {
        if (node->exporter.options.collector_set_id == collector_set_id) {
            return node;
        }
    }
    return NULL;
}

/* Sets the lsample configuration and returns true if the configuration
 * has changed. */
bool
dpif_lsample_set_options(struct dpif_lsample *lsample,
                         const struct ofproto_lsample_options *options,
                         size_t n_options)
{
    const struct ofproto_lsample_options *opt;
    struct lsample_exporter_node *node;
    bool changed = false;
    int i;

    for (i = 0; i < n_options; i++) {
        opt = &options[i];
        node = dpif_lsample_find_exporter_node(lsample,
                                               opt->collector_set_id);
        if (!node) {
            dpif_lsample_add_exporter(lsample, opt);
            changed = true;
        } else if (memcmp(&node->exporter.options, opt, sizeof *opt)) {
            dpif_lsample_delete_exporter(lsample, node);
            dpif_lsample_add_exporter(lsample, opt);
            changed = true;
        }
    }

    /* Delete exporters that have been removed. */
    CMAP_FOR_EACH (node, node, &lsample->exporters) {
        for (i = 0; i < n_options; i++) {
            if (node->exporter.options.collector_set_id
                == options[i].collector_set_id) {
                break;
            }
        }
        if (i == n_options) {
            dpif_lsample_delete_exporter(lsample, node);
            changed = true;
        }
    }

    return changed;
}

/* Returns the group_id for a given collector_set_id, if it exists. */
bool
dpif_lsample_get_group_id(struct dpif_lsample *ps, uint32_t collector_set_id,
                          uint32_t *group_id)
{
    struct lsample_exporter_node *node;

    node = dpif_lsample_find_exporter_node(ps, collector_set_id);
    if (node) {
        *group_id = node->exporter.options.group_id;
    }
    return !!node;
}

struct dpif_lsample *
dpif_lsample_create(void)
{
    struct dpif_lsample *lsample;

    lsample = xzalloc(sizeof *lsample);
    cmap_init(&lsample->exporters);
    ovs_mutex_init(&lsample->mutex);
    ovs_refcount_init(&lsample->ref_cnt);

    return lsample;
}

static void
dpif_lsample_destroy(struct dpif_lsample *lsample)
{
    if (lsample) {
        struct lsample_exporter_node *node;

        CMAP_FOR_EACH (node, node, &lsample->exporters) {
            dpif_lsample_delete_exporter(lsample, node);
        }
        cmap_destroy(&lsample->exporters);
        free(lsample);
    }
}

struct dpif_lsample *
dpif_lsample_ref(const struct dpif_lsample *lsample_)
{
    struct dpif_lsample *lsample = CONST_CAST(struct dpif_lsample *, lsample_);

    if (lsample) {
        ovs_refcount_ref(&lsample->ref_cnt);
    }
    return lsample;
}

void
dpif_lsample_unref(struct dpif_lsample *lsample)
{
    if (lsample && ovs_refcount_unref_relaxed(&lsample->ref_cnt) == 1) {
        dpif_lsample_destroy(lsample);
    }
}
