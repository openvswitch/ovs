/*
 * Copyright (c) 2018 eBay Inc.
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
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "inc-proc-eng.h"

VLOG_DEFINE_THIS_MODULE(inc_proc_eng);

static bool engine_force_recompute = false;
static const struct engine_context *engine_context;

void
engine_set_force_recompute(bool val)
{
    engine_force_recompute = val;
}

const struct engine_context *
engine_get_context(void)
{
    return engine_context;
}

void
engine_set_context(const struct engine_context *ctx)
{
    engine_context = ctx;
}

void
engine_init(struct engine_node *node)
{
    for (size_t i = 0; i < node->n_inputs; i++) {
        engine_init(node->inputs[i].node);
    }
    if (node->init) {
        node->init(node);
    }
}

void
engine_cleanup(struct engine_node *node)
{
    for (size_t i = 0; i < node->n_inputs; i++) {
        engine_cleanup(node->inputs[i].node);
    }
    if (node->cleanup) {
        node->cleanup(node);
    }
}

struct engine_node *
engine_get_input(const char *input_name, struct engine_node *node)
{
    size_t i;
    for (i = 0; i < node->n_inputs; i++) {
        if (!strcmp(node->inputs[i].node->name, input_name)) {
            return node->inputs[i].node;
        }
    }
    OVS_NOT_REACHED();
    return NULL;
}

void
engine_add_input(struct engine_node *node, struct engine_node *input,
                 bool (*change_handler)(struct engine_node *))
{
    ovs_assert(node->n_inputs < ENGINE_MAX_INPUT);
    node->inputs[node->n_inputs].node = input;
    node->inputs[node->n_inputs].change_handler = change_handler;
    node->n_inputs ++;
}

struct ovsdb_idl_index *
engine_ovsdb_node_get_index(struct engine_node *node, const char *name)
{
    struct ed_type_ovsdb_table *ed = (struct ed_type_ovsdb_table *)node->data;
    for (size_t i = 0; i < ed->n_indexes; i++) {
        if (!strcmp(ed->indexes[i].name, name)) {
            return ed->indexes[i].index;
        }
    }
    OVS_NOT_REACHED();
    return NULL;
}

void
engine_ovsdb_node_add_index(struct engine_node *node, const char *name,
                            struct ovsdb_idl_index *index)
{
    struct ed_type_ovsdb_table *ed = (struct ed_type_ovsdb_table *)node->data;
    ovs_assert(ed->n_indexes < ENGINE_MAX_OVSDB_INDEX);

    ed->indexes[ed->n_indexes].name = name;
    ed->indexes[ed->n_indexes].index = index;
    ed->n_indexes ++;
}

void
engine_run(struct engine_node *node, uint64_t run_id)
{
    if (node->run_id == run_id) {
        return;
    }
    node->run_id = run_id;

    node->changed = false;
    if (!node->n_inputs) {
        node->run(node);
        VLOG_DBG("node: %s, changed: %d", node->name, node->changed);
        return;
    }

    for (size_t i = 0; i < node->n_inputs; i++) {
        engine_run(node->inputs[i].node, run_id);
    }

    bool need_compute = false;
    bool need_recompute = false;

    if (engine_force_recompute) {
        need_recompute = true;
    } else {
        for (size_t i = 0; i < node->n_inputs; i++) {
            if (node->inputs[i].node->changed) {
                need_compute = true;
                if (!node->inputs[i].change_handler) {
                    need_recompute = true;
                    break;
                }
            }
        }
    }

    if (need_recompute) {
        VLOG_DBG("node: %s, recompute (%s)", node->name,
                 engine_force_recompute ? "forced" : "triggered");
        node->run(node);
    } else if (need_compute) {
        for (size_t i = 0; i < node->n_inputs; i++) {
            if (node->inputs[i].node->changed) {
                VLOG_DBG("node: %s, handle change for input %s",
                         node->name, node->inputs[i].node->name);
                if (!node->inputs[i].change_handler(node)) {
                    VLOG_DBG("node: %s, can't handle change for input %s, "
                             "fall back to recompute",
                             node->name, node->inputs[i].node->name);
                    node->run(node);
                    break;
                }
            }
        }
    }

    VLOG_DBG("node: %s, changed: %d", node->name, node->changed);
}

bool
engine_need_run(struct engine_node *node)
{
    size_t i;

    if (!node->n_inputs) {
        node->run(node);
        VLOG_DBG("input node: %s, changed: %d", node->name, node->changed);
        return node->changed;
    }

    for (i = 0; i < node->n_inputs; i++) {
        if (engine_need_run(node->inputs[i].node)) {
            return true;
        }
    }

    return false;
}
