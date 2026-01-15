/*
 * Copyright (c) 2025 Red Hat, Inc.
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

#include "dpif-offload.h"
#include "dpif-offload-provider.h"
#include "dpif-provider.h"
#include "netdev-provider.h"
#include "unixctl.h"
#include "util.h"
#include "vswitch-idl.h"

#include "openvswitch/dynamic-string.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload);

static struct vlog_rate_limit rl_dbg = VLOG_RATE_LIMIT_INIT(100, 100);

static struct ovs_mutex dpif_offload_mutex = OVS_MUTEX_INITIALIZER;
static struct shash dpif_offload_classes \
    OVS_GUARDED_BY(dpif_offload_mutex) = \
    SHASH_INITIALIZER(&dpif_offload_classes);
static struct shash dpif_offload_providers \
    OVS_GUARDED_BY(dpif_offload_mutex) = \
    SHASH_INITIALIZER(&dpif_offload_providers);

static const struct dpif_offload_class *base_dpif_offload_classes[] = {
#if defined(__linux__)
    &dpif_offload_tc_class,
#endif
#ifdef DPDK_NETDEV
    &dpif_offload_dpdk_class,
#endif
    /* While adding a new offload class to this structure make sure to also
     * update the dpif_offload_provider_priority_list below. */
    &dpif_offload_dummy_class,
    &dpif_offload_dummy_x_class,
};

#define DEFAULT_PROVIDER_PRIORITY_LIST "tc,dpdk,dummy,dummy_x"

static char *dpif_offload_provider_priority_list = NULL;
static atomic_bool offload_global_enabled = false;
static atomic_bool offload_rebalance_policy = false;
static struct smap port_order_cfg = SMAP_INITIALIZER(&port_order_cfg);

static int
dpif_offload_register_provider__(const struct dpif_offload_class *class)
    OVS_REQUIRES(dpif_offload_mutex)
{
    int error;

    if (shash_find(&dpif_offload_classes, class->type)) {
        VLOG_WARN("attempted to register duplicate dpif offload class: %s",
                  class->type);
        return EEXIST;
    }

    if (!class->supported_dpif_types) {
        VLOG_WARN("attempted to register a dpif offload class without any "
                  "supported dpif types: %s", class->type);
        return EINVAL;
    }

    error = class->init ? class->init() : 0;
    if (error) {
        VLOG_WARN("failed to initialize %s dpif offload class: %s",
                  class->type, ovs_strerror(error));
        return error;
    }

    shash_add(&dpif_offload_classes, class->type, class);
    return 0;
}

static int
dpif_offload_register_provider(const struct dpif_offload_class *class)
{
    int error;

    ovs_mutex_lock(&dpif_offload_mutex);
    error = dpif_offload_register_provider__(class);
    ovs_mutex_unlock(&dpif_offload_mutex);

    return error;
}

static void
dpif_offload_show_classes(struct unixctl_conn *conn, int argc OVS_UNUSED,
                          const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    const struct shash_node **list;
    struct ds ds;

    ds_init(&ds);
    ovs_mutex_lock(&dpif_offload_mutex);

    list = shash_sort(&dpif_offload_classes);
    for (size_t i = 0; i < shash_count(&dpif_offload_classes); i++) {
        const struct dpif_offload_class *class = list[i]->data;

        if (i == 0) {
            ds_put_cstr(&ds, "Offload Class     Supported dpif class(es)\n");
            ds_put_cstr(&ds, "----------------  ------------------------\n");
        }

        ds_put_format(&ds, "%-16s  ", list[i]->name);

        for (size_t j = 0; class->supported_dpif_types[j] != NULL; j++) {
            ds_put_format(&ds, "%*s%s\n", j == 0 ? 0 : 18, "",
                          class->supported_dpif_types[j]);
        }
    }

    ovs_mutex_unlock(&dpif_offload_mutex);
    free(list);

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

void
dpif_offload_module_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (!ovsthread_once_start(&once)) {
        return;
    }

    if (!dpif_offload_provider_priority_list) {
        dpif_offload_provider_priority_list =
            xstrdup(DEFAULT_PROVIDER_PRIORITY_LIST);
    }

    unixctl_command_register("dpif/offload/classes", NULL, 0, 0,
                             dpif_offload_show_classes, NULL);

    for (int i = 0; i < ARRAY_SIZE(base_dpif_offload_classes); i++) {
        ovs_assert(base_dpif_offload_classes[i]->open
                   && base_dpif_offload_classes[i]->close
                   && base_dpif_offload_classes[i]->can_offload
                   && base_dpif_offload_classes[i]->port_add
                   && base_dpif_offload_classes[i]->port_del
                   && base_dpif_offload_classes[i]->get_netdev);

        ovs_assert((base_dpif_offload_classes[i]->flow_dump_create &&
                    base_dpif_offload_classes[i]->flow_dump_next &&
                    base_dpif_offload_classes[i]->flow_dump_destroy &&
                    base_dpif_offload_classes[i]->flow_dump_thread_create &&
                    base_dpif_offload_classes[i]->flow_dump_thread_destroy) ||
                   (!base_dpif_offload_classes[i]->flow_dump_create &&
                    !base_dpif_offload_classes[i]->flow_dump_next &&
                    !base_dpif_offload_classes[i]->flow_dump_destroy &&
                    !base_dpif_offload_classes[i]->flow_dump_thread_create &&
                    !base_dpif_offload_classes[i]->flow_dump_thread_destroy));

        dpif_offload_register_provider(base_dpif_offload_classes[i]);
    }

    ovsthread_once_done(&once);
}

static struct dpif_offload_provider_collection*
dpif_get_offload_provider_collection(const struct dpif *dpif)
{
    return ovsrcu_get(struct dpif_offload_provider_collection *,
                      &dpif->offload_provider_collection);
}

static void
dpif_attach_offload_provider_collection(
    struct dpif *dpif, struct dpif_offload_provider_collection *collection)
    OVS_REQUIRES(dpif_offload_mutex)
{
    /* When called, 'collection' should still have a refcount > 0, which is
     * guaranteed by holding the lock from the shash lookup up to this point.
     * If, for any reason, the refcount is not > 0, ovs_refcount_ref() will
     * assert. */
    ovs_refcount_ref(&collection->ref_cnt);
    ovsrcu_set(&dpif->offload_provider_collection, collection);
}

static int
provider_collection_add(struct dpif_offload_provider_collection *collection,
                        struct dpif_offload *offload)
{
    struct ovs_list *providers_list = &collection->list;
    struct dpif_offload *offload_entry;

    ovs_assert(collection);

    LIST_FOR_EACH (offload_entry, dpif_list_node, providers_list) {
        if (offload_entry == offload || !strcmp(offload->name,
                                                offload_entry->name)) {
            return EEXIST;
        }
    }

    ovs_list_push_back(providers_list, &offload->dpif_list_node);
    return 0;
}

static void
move_provider_to_collection(
    struct dpif_offload_provider_collection *collection,
    struct dpif_offload *offload)
    OVS_REQUIRES(dpif_offload_mutex)
{
    int error;

    ovs_list_remove(&offload->dpif_list_node);
    error = provider_collection_add(collection, offload);
    if (error) {
        VLOG_WARN("failed to add dpif offload provider %s to %s: %s",
                  dpif_offload_type(offload), collection->dpif_name,
                  ovs_strerror(error));

        offload->class->close(offload);
    }
}

static int
dpif_attach_new_offload_provider_collection(struct dpif *dpif)
    OVS_REQUIRES(dpif_offload_mutex)
{
    struct ovs_list provider_list = OVS_LIST_INITIALIZER(&provider_list);
    const char *dpif_type_str = dpif_normalize_type(dpif_type(dpif));
    struct dpif_offload_provider_collection *collection;
    struct dpif_offload *offload;
    struct shash_node *node;
    char *tokens, *saveptr;

    /* Allocate and attach collection to dpif. */
    collection = xmalloc(sizeof *collection);
    collection->dpif_name = xstrdup(dpif_name(dpif));
    ovs_mutex_init_recursive(&collection->mutex);
    ovs_refcount_init(&collection->ref_cnt);
    ovs_list_init(&collection->list);
    shash_add(&dpif_offload_providers, collection->dpif_name, collection);

    /* Open all the providers supporting this dpif type. */
    SHASH_FOR_EACH (node, &dpif_offload_classes) {
        const struct dpif_offload_class *class = node->data;

        for (size_t i = 0; class->supported_dpif_types[i] != NULL; i++) {
            if (!strcmp(class->supported_dpif_types[i], dpif_type_str)) {
                int error = class->open(class, dpif, &offload);

                if (error) {
                    VLOG_WARN("failed to initialize dpif offload provider "
                              "%s for %s: %s",
                              class->type, dpif_name(dpif),
                              ovs_strerror(error));
                } else {
                    ovs_list_push_back(&provider_list,
                                       &offload->dpif_list_node);
                }
                break;
            }
        }
    }

    /* Attach all the providers based on the priority list. */
    tokens = xstrdup(dpif_offload_provider_priority_list);

    for (char *name = strtok_r(tokens, ",", &saveptr);
         name;
         name = strtok_r(NULL, ",", &saveptr)) {

        LIST_FOR_EACH_SAFE (offload, dpif_list_node, &provider_list) {
            if (strcmp(name, offload->class->type)) {
                continue;
            }

            move_provider_to_collection(collection, offload);
            break;
        }
    }
    free(tokens);

    /* Add remaining entries in order. */
    LIST_FOR_EACH_SAFE (offload, dpif_list_node, &provider_list) {
        move_provider_to_collection(collection, offload);
    }

    /* Attach the new collection to the dpif. */
    ovsrcu_set(&dpif->offload_provider_collection, collection);

    return 0;
}

/* This function returns 0 if a new provider set was attached to the dpif,
 * returns EEXIST if an existing set of providers was attached, and
 * returns a negative error code on error. */
int
dpif_attach_offload_providers(struct dpif *dpif)
{
    struct dpif_offload_provider_collection *collection;
    int rc = EEXIST;

    ovs_mutex_lock(&dpif_offload_mutex);

    collection = shash_find_data(&dpif_offload_providers, dpif_name(dpif));
    if (collection) {
        dpif_attach_offload_provider_collection(dpif, collection);
    } else {
        rc = dpif_attach_new_offload_provider_collection(dpif);
    }

    ovs_mutex_unlock(&dpif_offload_mutex);
    return rc;
}

static void
provider_collection_free_rcu(
    struct dpif_offload_provider_collection *collection)
{
    struct dpif_offload *offload_entry;

    /* We need to use the safe variant here as we removed the entry, and the
     * close API will free() it. */
    LIST_FOR_EACH_SAFE (offload_entry, dpif_list_node, &collection->list) {
        char *name = offload_entry->name;

        ovs_list_remove(&offload_entry->dpif_list_node);
        offload_entry->class->close(offload_entry);
        free(name);
    }

    /* Free remaining resources. */
    ovs_mutex_destroy(&collection->mutex);
    free(collection->dpif_name);
    free(collection);
}

void
dpif_detach_offload_providers(struct dpif *dpif)
{
    struct dpif_offload_provider_collection *collection;

    collection = dpif_get_offload_provider_collection(dpif);
    if (collection) {
        /* Take dpif_offload_mutex so that, if collection->ref_cnt falls to
         * zero, we can't get a new reference to 'collection' through the
         * 'dpif_offload_providers' shash. */
        ovs_mutex_lock(&dpif_offload_mutex);
        if (ovs_refcount_unref_relaxed(&collection->ref_cnt) == 1) {
            shash_find_and_delete(&dpif_offload_providers,
                                  collection->dpif_name);
            ovsrcu_postpone(provider_collection_free_rcu, collection);
        }
        ovs_mutex_unlock(&dpif_offload_mutex);
        ovsrcu_set(&dpif->offload_provider_collection, NULL);
    }
}

void
dpif_offload_set_config(struct dpif *dpif, const struct smap *other_cfg)
{
    struct dpif_offload_provider_collection *collection;
    struct dpif_offload *offload;

    collection = dpif_get_offload_provider_collection(dpif);

    if (!collection) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
        if (offload->class->set_config) {
            offload->class->set_config(offload, other_cfg);
        }
    }
}


void
dpif_offload_init(struct dpif_offload *offload,
                  const struct dpif_offload_class *class,
                  struct dpif *dpif)
{
    ovs_assert(offload && class && dpif);

    offload->class = class;
    offload->name = xasprintf("%s[%s]", class->type, dpif_name(dpif));
}

const char *
dpif_offload_name(const struct dpif_offload *offload)
{
    return offload->name;
}

const char *
dpif_offload_type(const struct dpif_offload *offload)
{
    return offload->class->type;
}

bool
dpif_offload_get_debug(const struct dpif_offload *offload, struct ds *ds,
                       struct json *json)
{
    if (!offload->class->get_debug) {
        return false;
    }

    offload->class->get_debug(offload, ds, json);
    return true;
}

bool
dpif_offload_enabled(void)
{
    bool enabled;

    atomic_read_relaxed(&offload_global_enabled, &enabled);
    return enabled;
}

bool
dpif_offload_rebalance_policy_enabled(void)
{
    bool enabled;

    atomic_read_relaxed(&offload_rebalance_policy, &enabled);
    return enabled;
}

void
dpif_offload_set_netdev_offload(struct netdev *netdev,
                                struct dpif_offload *offload)
{
    ovsrcu_set(&netdev->dpif_offload, offload);
}

static bool
dpif_offload_try_port_add(struct dpif_offload *offload, struct netdev *netdev,
                          odp_port_t port_no)
{
    if (offload->class->can_offload(offload, netdev)) {
        int err = offload->class->port_add(offload, netdev, port_no);

        if (!err) {
            VLOG_DBG("netdev %s added to dpif-offload provider %s",
                     netdev_get_name(netdev), dpif_offload_name(offload));
            return true;
        } else {
            VLOG_ERR("Failed adding netdev %s to dpif-offload provider "
                     "%s, error %s",
                     netdev_get_name(netdev), dpif_offload_name(offload),
                     ovs_strerror(err));
        }
    } else {
        VLOG_DBG("netdev %s failed can_offload for dpif-offload provider %s",
                 netdev_get_name(netdev), dpif_offload_name(offload));
    }
    return false;
}

void
dpif_offload_port_add(struct dpif *dpif, struct netdev *netdev,
                      odp_port_t port_no)
{
    struct dpif_offload_provider_collection *collection;
    const char *port_priority = smap_get(&port_order_cfg,
                                         netdev_get_name(netdev));
    struct dpif_offload *offload;

    collection = dpif_get_offload_provider_collection(dpif);
    if (!collection) {
        return;
    }

    if (port_priority) {
        char *tokens = xstrdup(port_priority);
        char *saveptr;

        VLOG_DBG("for netdev %s using port priority %s",
                 netdev_get_name(netdev), port_priority);

        for (char *name = strtok_r(tokens, ",", &saveptr);
             name;
             name = strtok_r(NULL, ",", &saveptr)) {
            bool provider_added = false;

            if (!strcmp("none", name)) {
                break;
            }

            LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
                if (!strcmp(name, offload->class->type)) {
                    provider_added = dpif_offload_try_port_add(offload, netdev,
                                                               port_no);
                    break;
                }
            }

            if (provider_added) {
                break;
            }
        }
        free(tokens);
    } else {
        LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
            if (dpif_offload_try_port_add(offload, netdev, port_no)) {
                break;
            }
        }
    }
}

void
dpif_offload_port_del(struct dpif *dpif, odp_port_t port_no)
{
    struct dpif_offload_provider_collection *collection;
    struct dpif_offload *offload;

    collection = dpif_get_offload_provider_collection(dpif);
    if (!collection) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
        int err = offload->class->port_del(offload, port_no);

        if (err) {
            VLOG_ERR("Failed deleting port_no %d from dpif-offload provider "
                     "%s, error %s", port_no, dpif_offload_name(offload),
                     ovs_strerror(err));
        }
    }
}

void
dpif_offload_port_set_config(struct dpif *dpif, odp_port_t port_no,
                             const struct smap *cfg)
{
    struct dpif_offload_provider_collection *collection;
    struct dpif_offload *offload;

    collection = dpif_get_offload_provider_collection(dpif);
    if (!collection) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
        if (offload->class->port_set_config) {
            offload->class->port_set_config(offload, port_no, cfg);
        }
    }
}

struct dpif_offload *
dpif_offload_port_offloaded_by(const struct dpif *dpif, odp_port_t port_no)
{
    struct dpif_offload_provider_collection *collection;
    struct dpif_offload *offload, *offload_return = NULL;

    collection = dpif_get_offload_provider_collection(dpif);
    if (!collection || !dpif_offload_enabled()) {
        return NULL;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
        if (offload->class->get_netdev(offload, port_no)) {
            offload_return = offload;
            break;
        }
    }

    return offload_return;
}

void
dpif_offload_dump_start(struct dpif_offload_dump *dump,
                        const struct dpif *dpif)
{
    memset(dump, 0, sizeof *dump);
    dump->dpif = dpif;
}

bool
dpif_offload_dump_next(struct dpif_offload_dump *dump,
                       struct dpif_offload **offload)
{
    struct dpif_offload_provider_collection *collection;

    if (!offload || !dump || dump->error) {
        return false;
    }

    collection = dpif_get_offload_provider_collection(dump->dpif);
    if (!collection) {
        return false;
    }

    if (dump->state) {
        struct dpif_offload *offload_entry;
        bool valid_member = false;

        /* In theory, list entries should not be removed.  However, in case
         * someone calls this during destruction and the node has disappeared,
         * we will return EIDRM (Identifier removed). */
        LIST_FOR_EACH (offload_entry, dpif_list_node, &collection->list) {
            if (offload_entry == dump->state) {
                valid_member = true;
                break;
            }
        }

        if (valid_member) {
            offload_entry = dump->state;

            LIST_FOR_EACH_CONTINUE (offload_entry, dpif_list_node,
                                    &collection->list) {
                *offload = offload_entry;
                dump->state = offload_entry;
                return true;
            }

            dump->error = EOF;
        } else {
            dump->error = EIDRM;
        }
    } else {
        /* Get the first entry in the list. */
        struct dpif_offload *offload_entry;

        LIST_FOR_EACH (offload_entry, dpif_list_node, &collection->list) {
            break;
        }

        if (offload_entry) {
            *offload = offload_entry;
            dump->state = offload_entry;
        } else {
            dump->error = EOF;
        }
    }

    return !dump->error;
}

int
dpif_offload_dump_done(struct dpif_offload_dump *dump)
{
    return dump->error == EOF ? 0 : dump->error;
}

void
dpif_offload_set_global_cfg(const struct ovsrec_open_vswitch *cfg)
{
    static struct ovsthread_once init_once = OVSTHREAD_ONCE_INITIALIZER;
    const struct smap *other_cfg = &cfg->other_config;
    const char *priority;

    /* The 'hw-offload-priority' parameter can only be set at startup,
     * any successive change needs a restart. */
    priority = smap_get(other_cfg, "hw-offload-priority");

    if (ovsthread_once_start(&init_once)) {
        /* Initialize the dpif-offload layer in case it's not yet initialized
         * at the first invocation of setting the configuration. */
        dpif_offload_module_init();

        /* If priority is not set keep the default value. */
        if (priority) {
            char *tokens = xstrdup(priority);
            char *saveptr;

            free(dpif_offload_provider_priority_list);
            dpif_offload_provider_priority_list = xstrdup(priority);

            /* Log a warning for unknown offload providers. */
            for (char *name = strtok_r(tokens, ",", &saveptr);
                 name;
                 name = strtok_r(NULL, ",", &saveptr)) {

                if (!shash_find(&dpif_offload_classes, name)) {
                    VLOG_WARN("hw-offload-priority configuration has an "
                              "unknown type; %s", name);
                }
            }
            free(tokens);
        }
        ovsthread_once_done(&init_once);
    } else {
        if (priority && strcmp(priority,
                               dpif_offload_provider_priority_list)) {
            VLOG_INFO_ONCE("hw-offload-priority configuration changed; "
                           "restart required");
        }
    }

    /* Handle other global configuration settings. */
     if (smap_get_bool(other_cfg, "hw-offload", false)) {
        static struct ovsthread_once once_enable = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once_enable)) {
            atomic_store_relaxed(&offload_global_enabled, true);
            VLOG_INFO("Flow HW offload is enabled");

            if (smap_get_bool(other_cfg, "offload-rebalance", false)) {
                atomic_store_relaxed(&offload_rebalance_policy, true);
            }

            ovsthread_once_done(&once_enable);
        }
    }

    /* Filter out the 'hw-offload-priority' per port setting we need it before
     * ports are added, so we can assign the correct offload-provider.
     * Note that we can safely rebuild the map here, as we only access this
     * from the same (main) thread. */
    smap_clear(&port_order_cfg);
    for (int i = 0; i < cfg->n_bridges; i++) {
        const struct ovsrec_bridge *br_cfg = cfg->bridges[i];

        for (int j = 0; j < br_cfg->n_ports; j++) {
            const struct ovsrec_port *port_cfg = br_cfg->ports[j];

            priority = smap_get(&port_cfg->other_config,
                                "hw-offload-priority");
            if (priority) {
                smap_add(&port_order_cfg, port_cfg->name, priority);
            }
        }
    }
}

void
dpif_offload_flow_flush(struct dpif *dpif)
{
    struct dpif_offload_provider_collection *collection;
    struct dpif_offload *offload;

    collection = dpif_get_offload_provider_collection(dpif);
    if (!collection) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
        if (offload->class->flow_flush) {
            int err = offload->class->flow_flush(offload);

            if (err) {
                VLOG_ERR(
                    "Failed flow flush on dpif-offload provider %s, error %s",
                    dpif_offload_name(offload), ovs_strerror(err));
            }
        }
    }
}

enum dpif_offload_impl_type
dpif_offload_get_impl_type(const struct dpif_offload *offload)
{
    return offload->class->impl_type;
}

enum dpif_offload_impl_type
dpif_offload_get_impl_type_by_class(const char *type)
{
    enum dpif_offload_impl_type impl_type = DPIF_OFFLOAD_IMPL_NONE;
    struct shash_node *node;

    ovs_mutex_lock(&dpif_offload_mutex);
    SHASH_FOR_EACH (node, &dpif_offload_classes) {
        const struct dpif_offload_class *class = node->data;

        if (!strcmp(type, class->type)) {
            impl_type = class->impl_type;
            break;
        }
    }
    ovs_mutex_unlock(&dpif_offload_mutex);

    return impl_type;
}

uint64_t
dpif_offload_flow_count(const struct dpif *dpif)
{
    struct dpif_offload_provider_collection *collection;
    const struct dpif_offload *offload;
    uint64_t flow_count = 0;

    collection = dpif_get_offload_provider_collection(dpif);
    if (!collection || !dpif_offload_enabled()) {
        return 0;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
        if (offload->class->flow_count) {
            flow_count += offload->class->flow_count(offload);
        }
    }

    return flow_count;
}

uint64_t
dpif_offload_flow_count_by_impl(const struct dpif *dpif,
                                enum dpif_offload_impl_type type)
{
     struct dpif_offload_provider_collection *collection;
    const struct dpif_offload *offload;
    uint64_t flow_count = 0;

    collection = dpif_get_offload_provider_collection(dpif);
    if (!collection || !dpif_offload_enabled()) {
        return 0;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
        if (offload->class->flow_count
            && type == dpif_offload_get_impl_type(offload)) {
            flow_count += offload->class->flow_count(offload);
        }
    }

    return flow_count;
}

void
dpif_offload_meter_set(const struct dpif *dpif, ofproto_meter_id meter_id,
                       struct ofputil_meter_config *config)
{
    struct dpif_offload_provider_collection *collection;
    struct dpif_offload *offload;

    collection = dpif_get_offload_provider_collection(dpif);
    if (!collection || !dpif_offload_enabled()) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
        if (offload->class->meter_set) {
            int err = offload->class->meter_set(offload, meter_id, config);

            if (err) {
                /* Offload APIs could fail, for example, because the offload
                 * is not supported.  This is fine, as the offload API should
                 * take care of this. */
                VLOG_DBG_RL(&rl_dbg,
                            "Failed setting meter %u on dpif-offload provider"
                            " %s, error %s", meter_id.uint32,
                            dpif_offload_name(offload), ovs_strerror(err));
            }
        }
    }
}

void
dpif_offload_meter_get(const struct dpif *dpif, ofproto_meter_id meter_id,
                       struct ofputil_meter_stats *stats)
{
    struct dpif_offload_provider_collection *collection;
    struct dpif_offload *offload;

    collection = dpif_get_offload_provider_collection(dpif);
    if (!collection || !dpif_offload_enabled()) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
        if (offload->class->meter_get) {
            int err = offload->class->meter_get(offload, meter_id, stats);
            if (err) {
                VLOG_DBG_RL(&rl_dbg,
                            "Failed getting meter %u on dpif-offload provider"
                            " %s, error %s", meter_id.uint32,
                            dpif_offload_name(offload), ovs_strerror(err));
            }
        }
    }
}

void
dpif_offload_meter_del(const struct dpif *dpif, ofproto_meter_id meter_id,
                       struct ofputil_meter_stats *stats)
{
    struct dpif_offload_provider_collection *collection;
    struct dpif_offload *offload;

    collection = dpif_get_offload_provider_collection(dpif);
    if (!collection || !dpif_offload_enabled()) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
        if (offload->class->meter_del) {
            int err = offload->class->meter_del(offload, meter_id, stats);
            if (err) {
                VLOG_DBG_RL(&rl_dbg,
                            "Failed deleting meter %u on dpif-offload provider"
                            " %s, error %s", meter_id.uint32,
                            dpif_offload_name(offload), ovs_strerror(err));
            }
        }
    }
}

/*
 * Further initializes a 'struct dpif_flow_dump' that was already initialized
 * by dpif_flow_dump_create(), preparing it for use by
 * dpif_offload_flow_dump_next().
 *
 * For more details, see the documentation of dpif_flow_dump_create(). */
void
dpif_offload_flow_dump_create(struct dpif_flow_dump *dump,
                              const struct dpif *dpif, bool terse)
{
    struct dpif_offload_provider_collection *collection;
    const struct dpif_offload *offload;
    size_t n_providers = 0;
    int i = 0;

    collection = dpif_get_offload_provider_collection(dpif);
    if (!dump || !dpif_offload_enabled() || !collection) {
        return;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
        if (offload->class->flow_dump_create) {
            n_providers++;
        }
    }

    if (!n_providers) {
        return;
    }

    dump->offload_dumps = xmalloc(n_providers * sizeof(
        struct dpif_offload_flow_dump *));

    LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
        if (offload->class->flow_dump_create) {
            dump->offload_dumps[i++] =
                offload->class->flow_dump_create(offload, terse);
        }
    }
    dump->n_offload_dumps = i;
    dump->offload_dump_index = 0;
}

/* Destroys the 'dump' data associated with the offload flow dump.
 * This function is called as part of the general dump cleanup
 * by dpif_flow_dump_destroy().
 *
 * Returns 0 if all individual dpif-offload dump operations complete
 * without error.  If one or more providers return an error, the error
 * code from the first failing provider is returned as a positive errno
 * value. */
int
dpif_offload_flow_dump_destroy(struct dpif_flow_dump *dump)
{
    int error = 0;

    for (int i = 0; i < dump->n_offload_dumps; i++) {
        struct dpif_offload_flow_dump *offload_dump = dump->offload_dumps[i];
        const struct dpif_offload *offload = offload_dump->offload;
        int rc = offload->class->flow_dump_destroy(offload_dump);

        if (rc && rc != EOF) {
            VLOG_ERR("Failed flow dumping on dpif-offload provider "
                     "%s, error %s", dpif_offload_name(offload),
                     ovs_strerror(rc));
            if (!error) {
                error = rc;
            }
        }
    }
    ovs_mutex_destroy(&dump->offload_dump_mutex);
    free(dump->offload_dumps);
    return error;
}

static void
dpif_offload_advance_provider_dump(struct dpif_flow_dump_thread *thread)
{
    struct dpif_flow_dump *dump = thread->dump;

    ovs_mutex_lock(&dump->offload_dump_mutex);

    /* If we haven't finished (dumped all providers). */
    if (dump->offload_dump_index < dump->n_offload_dumps) {
        /* If we are the first to find that current dump is finished
         * advance it. */
        if (thread->offload_dump_index == dump->offload_dump_index) {
            thread->offload_dump_index = ++dump->offload_dump_index;
            /* Did we just finish the last dump? If so we are done. */
            if (dump->offload_dump_index == dump->n_offload_dumps) {
                thread->offload_dump_done = true;
            }
        } else {
            /* otherwise, we are behind, catch up */
            thread->offload_dump_index = dump->offload_dump_index;
        }
    } else {
        /* Some other thread finished. */
        thread->offload_dump_done = true;
    }

    ovs_mutex_unlock(&dump->offload_dump_mutex);
}

/* This function behaves exactly the same as dpif_flow_dump_next(),
 * so see its documentation for details. */
int
dpif_offload_flow_dump_next(struct dpif_flow_dump_thread *thread,
                            struct dpif_flow *flows, int max_flows)
{
    int n_flows = 0;

    ovs_assert(max_flows > 0);

    /* The logic here processes all registered offload providers and
     * dumps all related flows.  If done (i.e., it returns 0), continue
     * with the next offload provider. */
    while (!thread->offload_dump_done) {
        struct dpif_offload_flow_dump_thread *offload_thread;

        ovs_assert(thread->offload_dump_index < thread->n_offload_threads);
        offload_thread = thread->offload_threads[thread->offload_dump_index];
        n_flows = offload_thread->dump->offload->class->flow_dump_next(
                        offload_thread, flows, max_flows);

        if (n_flows > 0) {
            /* If we got some flows, we need to return due to the constraint
             * on returned flows, as explained in dpif_flow_dump_next(). */
            break;
        }
        dpif_offload_advance_provider_dump(thread);
    }
    return MAX(n_flows, 0);
}

/* Further initializes a 'struct dpif_flow_dump_thread' that was already
 * initialized by dpif_flow_dump_thread_create(), preparing it for use by
 * dpif_offload_flow_dump_next(). */
void
dpif_offload_flow_dump_thread_create(struct dpif_flow_dump_thread *thread,
                                     struct dpif_flow_dump *dump)
{
    if (!dpif_offload_enabled() || !dump || !dump->n_offload_dumps) {
        return;
    }

    thread->n_offload_threads = dump->n_offload_dumps;
    thread->offload_dump_done = false;
    thread->offload_dump_index = 0;
    thread->offload_threads =
        xmalloc(thread->n_offload_threads * sizeof *thread->offload_threads);

    for (int i = 0; i < dump->n_offload_dumps; i++) {
        struct dpif_offload_flow_dump *offload_dump = dump->offload_dumps[i];
        const struct dpif_offload *offload = offload_dump->offload;

        thread->offload_threads[i] =
            offload->class->flow_dump_thread_create(offload_dump);
    }
}

/* Destroys the 'thread' data associated with the offload flow dump.
 * This function is called as part of the general thread cleanup
 * by dpif_flow_dump_thread_destroy(). */
void
dpif_offload_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread)
{
    for (int i = 0; i < thread->n_offload_threads; i++) {
        struct dpif_offload_flow_dump_thread *offload_thread;
        const struct dpif_offload *offload;

        offload_thread = thread->offload_threads[i];
        offload = offload_thread->dump->offload;
        offload->class->flow_dump_thread_destroy(offload_thread);
    }
    free(thread->offload_threads);
}

struct netdev *
dpif_offload_get_netdev_by_port_id(struct dpif *dpif,
                                   struct dpif_offload **offload,
                                   odp_port_t port_no)
{
    struct dpif_offload_provider_collection *collection;
    struct dpif_offload *tmp_offload;
    struct netdev *netdev = NULL;

    collection = dpif_get_offload_provider_collection(dpif);
    if (!collection || !dpif_offload_enabled()) {
        return NULL;
    }

    LIST_FOR_EACH (tmp_offload, dpif_list_node, &collection->list) {
        netdev = tmp_offload->class->get_netdev(tmp_offload, port_no);
        if (netdev) {
            if (offload) {
                *offload = tmp_offload;
            }
            break;
        }
    }

    return netdev;
}

/* This function tries to offload the operations to the dpif-offload
 * providers.  It will return the number of operations not handled, whose
 * pointers are re-arranged and available in **ops. */
size_t
dpif_offload_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops,
                     enum dpif_offload_type offload_type)
{
    struct dpif_offload_provider_collection *collection;
    const struct dpif_offload *offload;
    size_t n_ops_left = 0;

    collection = dpif_get_offload_provider_collection(dpif);
    if (!collection || !dpif_offload_enabled()) {
        return n_ops;
    }

    for (size_t i = 0; i < n_ops; i++) {
        ops[i]->error = -1;
    }

    LIST_FOR_EACH (offload, dpif_list_node, &collection->list) {
        if (offload->class->impl_type == DPIF_OFFLOAD_IMPL_FLOWS_PROVIDER_ONLY
            && offload->class->operate) {

            offload->class->operate(dpif, offload, ops, n_ops);

            for (size_t i = 0; i < n_ops; i++) {
                struct dpif_op *op = ops[i];

                if (op->error == EOPNOTSUPP) {
                    /* Not supported by this offload provider, try next one. */
                    op->error = -1;
                } else {
                    VLOG_DBG("Tried offloading %d to dpif-offload provider "
                             "%s, error %d",
                             op->type,
                             dpif_offload_name(offload), op->error);

                    switch (op->type) {
                    case DPIF_OP_FLOW_PUT:
                        log_flow_put_message(dpif, &this_module,
                                             &op->flow_put, 0);
                        break;
                    case DPIF_OP_FLOW_DEL:
                        log_flow_del_message(dpif, &this_module,
                                             &op->flow_del, 0);
                        break;
                    case DPIF_OP_FLOW_GET:
                        log_flow_get_message(dpif, &this_module,
                                             &op->flow_get, 0);
                        break;
                    case DPIF_OP_EXECUTE:
                        break;
                    }
                }
            }
        }
    }

    for (size_t i = 0; i < n_ops; i++) {
        struct dpif_op *op = ops[i];

        if (offload_type == DPIF_OFFLOAD_ALWAYS) {
            /* For DPIF_OFFLOAD_ALWAYS, we should keep the error values,
             * and mark the unprocessed ones as EOPNOTSUPP.  This way, they
             * will not be processed by the dpif layer. */
            if (op->error < 0) {
                op->error = EOPNOTSUPP;
            }
            continue;
        }

        /* For the other offload types, operations that were not handled or
         * failed to offload should be processed by the dpif layer. */
        if (op->error != 0 && op->error != EEXIST) {
            op->error = 0;
            ops[n_ops_left++] = op;
        }
    }

    return n_ops_left;
}


int
dpif_offload_netdev_flush_flows(struct netdev *netdev)
{
    const struct dpif_offload *offload;

    offload = ovsrcu_get(const struct dpif_offload *, &netdev->dpif_offload);

    if (offload && offload->class->netdev_flow_flush) {
        return offload->class->netdev_flow_flush(offload, netdev);
    }
    return EOPNOTSUPP;
}

int
dpif_offload_netdev_hw_post_process(struct netdev *netdev,
                                    struct dp_packet *packet)
{
    const struct dpif_offload *offload;
    bool post_process_api_supported;
    int rc;

    atomic_read_relaxed(&netdev->hw_info.post_process_api_supported,
                        &post_process_api_supported);
    if (!post_process_api_supported) {
        return EOPNOTSUPP;
    }

    offload = ovsrcu_get(const struct dpif_offload *, &netdev->dpif_offload);

    if (!offload || !offload->class->netdev_hw_post_process) {
        if (offload) {
            /* Offload is configured and API unsupported by the port;
             * avoid subsequent calls. */
            atomic_store_relaxed(&netdev->hw_info.post_process_api_supported,
                                 false);
        }
        return EOPNOTSUPP;
    }

    rc = offload->class->netdev_hw_post_process(offload, netdev, packet);
    if (rc == EOPNOTSUPP) {
        /* API unsupported by the port; avoid subsequent calls. */
        atomic_store_relaxed(&netdev->hw_info.post_process_api_supported,
                             false);
    }
    return rc;
}


struct dpif_offload_port_mgr *
dpif_offload_port_mgr_init(void)
{
    struct dpif_offload_port_mgr *mgr = xmalloc(sizeof *mgr);

    ovs_mutex_init(&mgr->cmap_mod_lock);

    cmap_init(&mgr->odp_port_to_port);
    cmap_init(&mgr->netdev_to_port);
    cmap_init(&mgr->ifindex_to_port);

    return mgr;
}

void
dpif_offload_port_mgr_uninit(struct dpif_offload_port_mgr *mgr)
{
    if (!mgr) {
        return;
    }

    ovs_assert(cmap_count(&mgr->odp_port_to_port) == 0);
    ovs_assert(cmap_count(&mgr->netdev_to_port) == 0);
    ovs_assert(cmap_count(&mgr->ifindex_to_port) == 0);

    cmap_destroy(&mgr->odp_port_to_port);
    cmap_destroy(&mgr->netdev_to_port);
    cmap_destroy(&mgr->ifindex_to_port);
    free(mgr);
}

struct dpif_offload_port_mgr_port *
dpif_offload_port_mgr_find_by_ifindex(struct dpif_offload_port_mgr *mgr,
                                      int ifindex)
{
    struct dpif_offload_port_mgr_port *port;

    if (ifindex < 0) {
        return NULL;
    }

    CMAP_FOR_EACH_WITH_HASH (port, ifindex_node, hash_int(ifindex, 0),
                             &mgr->ifindex_to_port) {
        if (port->ifindex == ifindex) {
            return port;
        }
    }
    return NULL;
}

struct dpif_offload_port_mgr_port *
dpif_offload_port_mgr_find_by_netdev(struct dpif_offload_port_mgr *mgr,
                                     struct netdev *netdev)
{
    struct dpif_offload_port_mgr_port *port;

    if (!netdev) {
        return NULL;
    }

    CMAP_FOR_EACH_WITH_HASH (port, netdev_node, hash_pointer(netdev, 0),
                             &mgr->netdev_to_port) {
        if (port->netdev == netdev) {
            return port;
        }
    }
    return NULL;
}

struct dpif_offload_port_mgr_port *
dpif_offload_port_mgr_find_by_odp_port(struct dpif_offload_port_mgr *mgr,
                                       odp_port_t port_no)
{
    struct dpif_offload_port_mgr_port *port;

    CMAP_FOR_EACH_WITH_HASH (port, odp_port_node,
                             hash_int(odp_to_u32(port_no), 0),
                             &mgr->odp_port_to_port) {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

struct dpif_offload_port_mgr_port *
dpif_offload_port_mgr_remove(struct dpif_offload_port_mgr *mgr,
                             odp_port_t port_no)
{
    /* Note that it is the caller's responsibility to release the netdev
     * after port removal.  This should probably be done through the
     * ovsrcu_postpone() API. */
    struct dpif_offload_port_mgr_port *port;

    ovs_mutex_lock(&mgr->cmap_mod_lock);

    port = dpif_offload_port_mgr_find_by_odp_port(mgr, port_no);

    if (port) {
        cmap_remove(&mgr->odp_port_to_port, &port->odp_port_node,
                    hash_int(odp_to_u32(port_no), 0));
        cmap_remove(&mgr->netdev_to_port, &port->netdev_node,
                    hash_pointer(port->netdev, 0));

        if (port->ifindex >= 0) {
            cmap_remove(&mgr->ifindex_to_port, &port->ifindex_node,
                        hash_int(port->ifindex, 0));
        }
    }

    ovs_mutex_unlock(&mgr->cmap_mod_lock);
    return port;
}

bool
dpif_offload_port_mgr_add(struct dpif_offload_port_mgr *mgr,
                          struct dpif_offload_port_mgr_port *port,
                          struct netdev *netdev, odp_port_t port_no,
                          bool need_ifindex)
{
    /* Note that this function takes a reference to the passed-in netdev.
     * However, on port removal it is the caller's responsibility to
     * release this reference. */
    ovs_assert(netdev);

    memset(port, 0, sizeof *port);
    port->port_no = port_no;
    port->ifindex = need_ifindex ? netdev_get_ifindex(netdev) : -1;

    ovs_mutex_lock(&mgr->cmap_mod_lock);

    if (dpif_offload_port_mgr_find_by_odp_port(mgr, port_no)
        || dpif_offload_port_mgr_find_by_ifindex(mgr, port->ifindex)
        || dpif_offload_port_mgr_find_by_netdev(mgr, netdev)) {

        ovs_mutex_unlock(&mgr->cmap_mod_lock);
        return false;
    }

    port->netdev = netdev_ref(netdev);

    cmap_insert(&mgr->odp_port_to_port, &port->odp_port_node,
                hash_int(odp_to_u32(port_no), 0));

    cmap_insert(&mgr->netdev_to_port, &port->netdev_node,
                hash_pointer(netdev, 0));

    if (port->ifindex >= 0) {
        cmap_insert(&mgr->ifindex_to_port, &port->ifindex_node,
                    hash_int(port->ifindex, 0));
    }

    ovs_mutex_unlock(&mgr->cmap_mod_lock);
    return true;
}

size_t
dpif_offload_port_mgr_port_count(struct dpif_offload_port_mgr *mgr)
{
    return cmap_count(&mgr->odp_port_to_port);
}
