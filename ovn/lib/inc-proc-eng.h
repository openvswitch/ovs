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

#ifndef INC_PROC_ENG_H
#define INC_PROC_ENG_H 1

/* The Incremental Processing Engine is a framework for incrementally
 * processing changes from different inputs. The main user is ovn-controller.
 * To compute desired states (e.g. openflow rules) based on many inputs (e.g.
 * south-bound DB tables, local OVSDB interfaces, etc.), it is straightforward
 * to recompute everything when there is any change in any inputs, but it
 * is inefficient when the size of the input data becomes large. Instead,
 * tracking the changes and update the desired states based on what's changed
 * is more efficient and scalable. However, it is not straightforward to
 * implement the change-based processing when there are a big number of
 * inputs. In addition, what makes it more complicated is that intermediate
 * results needs to be computed, which needs to be reused in different part
 * of the processing and finally generates the final desired states. It is
 * proved to be difficult and error-prone to implement this kind of complex
 * processing by ad-hoc implementation.
 *
 * This framework is to provide a generic way to solve the above problem.
 * It does not understand the processing logic, but provides a unified way
 * to describe the inputs and dependencies clearly, with interfaces for
 * users to implement the processing logic for how to handle each input
 * changes.
 *
 * The engine is composed of engine_nodes. Each engine_node is either
 * an input, an output or both (intermediate result). Each engine node
 * maintains its own data, which is persistent across interactions. Each node
 * has zero to ENGINE_MAX_INPUT inputs, which creates a DAG (directed
 * acyclic graph). For each input of each engine_node, there is a
 * change_handler to process changes of that input, and update the data
 * of the engine_node. Then the user can simply call the run() method
 * of the engine so that the processing will happen in the order according
 * to the dependencies defined and handle the changes incrementally.
 *
 * While the more fine-grained dependencies and change-handlers are
 * implemented, the more efficient the processing will be, it is not
 * realistic to implement all change-processing for all inputs (and
 * intermediate results). The engine doesn't require change-handler to be
 * implemented for every input of every node. Users can choose to implement
 * the most important change-handlers (for the changes happens most
 * frequently) for overall performance. When there is no change_handler
 * defined for a certain input on a certain engine_node, the run() method
 * of the engine_node will be called to fall-back to a full recompute
 * against all its inputs.
 */

#define ENGINE_MAX_INPUT 256
#define ENGINE_MAX_OVSDB_INDEX 256

struct engine_context {
    struct ovsdb_idl_txn *ovs_idl_txn;
    struct ovsdb_idl_txn *ovnsb_idl_txn;
};

struct engine_node;

struct engine_node_input {
    /* The input node. */
    struct engine_node *node;

    /* Change handler for changes of the input node. The changes may need to be
     * evaluated against all the other inputs. Returns:
     *  - true: if change can be handled
     *  - false: if change cannot be handled (indicating full recompute needed)
     */
    bool (*change_handler)(struct engine_node *node);
};

struct engine_node {
    /* A unique id to distinguish each iteration of the engine_run(). */
    uint64_t run_id;

    /* A unique name for each node. */
    char *name;

    /* Number of inputs of this node. */
    size_t n_inputs;

    /* Inputs of this node. */
    struct engine_node_input inputs[ENGINE_MAX_INPUT];

    /* Data of this node. It is vague and interpreted by the related functions.
     * The content of the data should be changed only by the change_handlers
     * and run() function of the current node. Users should ensure that the
     * data is read-only in change-handlers of the nodes that depends on this
     * node. */
    void *data;

    /* Whether the data changed in the last engine run. */
    bool changed;

    /* Method to initialize data. It may be NULL. */
    void (*init)(struct engine_node *);

    /* Method to clean up data. It may be NULL. */
    void (*cleanup)(struct engine_node *);

    /* Fully processes all inputs of this node and regenerates the data
     * of this node */
    void (*run)(struct engine_node *);
};

/* Initialize the data for the engine nodes recursively. It calls each node's
 * init() method if not NULL. It should be called before the main loop. */
void engine_init(struct engine_node *);

/* Execute the processing recursively, which should be called in the main
 * loop. */
void engine_run(struct engine_node *, uint64_t run_id);

/* Clean up the data for the engine nodes recursively. It calls each node's
 * cleanup() method if not NULL. It should be called before the program
 * terminates. */
void engine_cleanup(struct engine_node *);

/* Check if engine needs to run, i.e. any change to be processed. */
bool
engine_need_run(struct engine_node *);

/* Get the input node with <name> for <node> */
struct engine_node * engine_get_input(const char *input_name,
                                      struct engine_node *);

/* Add an input (dependency) for <node>, with corresponding change_handler,
 * which can be NULL. If the change_handler is NULL, the engine will not
 * be able to process the change incrementally, and will fall back to call
 * the run method to recompute. */
void engine_add_input(struct engine_node *node, struct engine_node *input,
                      bool (*change_handler)(struct engine_node *));

/* Force the engine to recompute everything if set to true. It is used
 * in circumstances when we are not sure there is change or not, or
 * when there is change but the engine couldn't be executed in that
 * iteration, and the change can't be tracked across iterations */
void engine_set_force_recompute(bool val);

const struct engine_context * engine_get_context(void);

void engine_set_context(const struct engine_context *);

struct ed_ovsdb_index {
    const char *name;
    struct ovsdb_idl_index *index;
};

struct ed_type_ovsdb_table {
    const void *table;
    size_t n_indexes;
    struct ed_ovsdb_index indexes[ENGINE_MAX_OVSDB_INDEX];
};

#define EN_OVSDB_GET(NODE) \
    (((struct ed_type_ovsdb_table *)NODE->data)->table)

struct ovsdb_idl_index * engine_ovsdb_node_get_index(struct engine_node *,
                                                     const char *name);

void engine_ovsdb_node_add_index(struct engine_node *, const char *name,
                                 struct ovsdb_idl_index *);

/* Macro to define an engine node. */
#define ENGINE_NODE(NAME, NAME_STR) \
    struct engine_node en_##NAME = { \
        .name = NAME_STR, \
        .data = &ed_##NAME, \
        .init = en_##NAME##_init, \
        .run = en_##NAME##_run, \
        .cleanup = en_##NAME##_cleanup, \
    };

/* Macro to define member functions of an engine node which represents
 * a table of OVSDB */
#define ENGINE_FUNC_OVSDB(DB_NAME, TBL_NAME) \
static void \
en_##DB_NAME##_##TBL_NAME##_run(struct engine_node *node) \
{ \
    const struct DB_NAME##rec_##TBL_NAME##_table *table = \
        EN_OVSDB_GET(node); \
    if (DB_NAME##rec_##TBL_NAME##_table_track_get_first(table)) { \
        node->changed = true; \
        return; \
    } \
    node->changed = false; \
} \
static void (*en_##DB_NAME##_##TBL_NAME##_init)(struct engine_node *node) \
            = NULL; \
static void (*en_##DB_NAME##_##TBL_NAME##_cleanup)(struct engine_node *node) \
            = NULL;

/* Macro to define member functions of an engine node which represents
 * a table of OVN SB DB */
#define ENGINE_FUNC_SB(TBL_NAME) \
    ENGINE_FUNC_OVSDB(sb, TBL_NAME)

/* Macro to define member functions of an engine node which represents
 * a table of open_vswitch DB */
#define ENGINE_FUNC_OVS(TBL_NAME) \
    ENGINE_FUNC_OVSDB(ovs, TBL_NAME)

/* Macro to define an engine node which represents a table of OVSDB */
#define ENGINE_NODE_OVSDB(DB_NAME, DB_NAME_STR, TBL_NAME, TBL_NAME_STR, IDL) \
    struct ed_type_ovsdb_table ed_##DB_NAME##_##TBL_NAME; \
    memset(&ed_##DB_NAME##_##TBL_NAME, 0, sizeof ed_##DB_NAME##_##TBL_NAME); \
    ovs_assert(IDL); \
    ed_##DB_NAME##_##TBL_NAME.table = \
        DB_NAME##rec_##TBL_NAME##_table_get(IDL); \
    ENGINE_NODE(DB_NAME##_##TBL_NAME, DB_NAME_STR"_"TBL_NAME_STR)

/* Macro to define an engine node which represents a table of OVN SB DB */
#define ENGINE_NODE_SB(TBL_NAME, TBL_NAME_STR) \
    ENGINE_NODE_OVSDB(sb, "SB", TBL_NAME, TBL_NAME_STR, ovnsb_idl_loop.idl);

/* Macro to define an engine node which represents a table of open_vswitch
 * DB */
#define ENGINE_NODE_OVS(TBL_NAME, TBL_NAME_STR) \
    ENGINE_NODE_OVSDB(ovs, "OVS", TBL_NAME, TBL_NAME_STR, ovs_idl_loop.idl);

#endif /* ovn/lib/inc-proc-eng.h */
