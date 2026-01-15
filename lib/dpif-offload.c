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
#include "unixctl.h"
#include "util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload);

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
    &dpif_offload_dummy_class,
    &dpif_offload_dummy_x_class,
};

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

    unixctl_command_register("dpif/offload/classes", NULL, 0, 0,
                             dpif_offload_show_classes, NULL);

    for (int i = 0; i < ARRAY_SIZE(base_dpif_offload_classes); i++) {
        ovs_assert(base_dpif_offload_classes[i]->open
                   && base_dpif_offload_classes[i]->close);

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
dpif_attach_new_offload_provider_collection(struct dpif *dpif)
    OVS_REQUIRES(dpif_offload_mutex)
{
    const char *dpif_type_str = dpif_normalize_type(dpif_type(dpif));
    struct dpif_offload_provider_collection *collection;
    struct shash_node *node;

    /* Allocate and attach collection to dpif. */
    collection = xmalloc(sizeof *collection);
    collection->dpif_name = xstrdup(dpif_name(dpif));
    ovs_mutex_init_recursive(&collection->mutex);
    ovs_refcount_init(&collection->ref_cnt);
    ovs_list_init(&collection->list);
    shash_add(&dpif_offload_providers, collection->dpif_name, collection);

    /* Attach all the providers supporting this dpif type. */
    SHASH_FOR_EACH (node, &dpif_offload_classes) {
        const struct dpif_offload_class *class = node->data;

        for (size_t i = 0; class->supported_dpif_types[i] != NULL; i++) {
            if (!strcmp(class->supported_dpif_types[i], dpif_type_str)) {
                struct dpif_offload *offload;
                int error;

                error = class->open(class, dpif, &offload);
                if (!error) {
                    error = provider_collection_add(collection, offload);
                    if (error) {
                        VLOG_WARN("failed to add dpif offload provider "
                                  "%s to %s: %s",
                                  class->type, dpif_name(dpif),
                                  ovs_strerror(error));
                        class->close(offload);
                    }
                } else {
                    VLOG_WARN("failed to initialize dpif offload provider "
                              "%s for %s: %s",
                              class->type, dpif_name(dpif),
                              ovs_strerror(error));
                }
                break;
            }
        }
    }

    /* Attach offload collection to dpif. */
    ovsrcu_set(&dpif->offload_provider_collection, collection);

    return 0;
}

int
dpif_attach_offload_providers(struct dpif *dpif)
{
    struct dpif_offload_provider_collection *collection;
    int rc = 0;

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
