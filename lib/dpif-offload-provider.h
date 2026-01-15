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

#ifndef DPIF_OFFLOAD_PROVIDER_H
#define DPIF_OFFLOAD_PROVIDER_H

#include "cmap.h"
#include "dpif-provider.h"
#include "ovs-thread.h"
#include "smap.h"
#include "util.h"

#include "openvswitch/list.h"

/* The DPIF Offload Provider introduces an abstraction layer for hardware
 * offload functionality implemented at the netdevice level.  It sits above
 * the netdevice layer within the DPIF (Datapath Interface) framework,
 * providing a standardized API for offloading packet processing tasks to
 * hardware-accelerated datapaths.
 *
 * By decoupling hardware-specific implementations from the core DPIF layer,
 * this abstraction enables greater flexibility, maintainability, and support
 * for multiple hardware offload mechanisms without directly modifying DPIF
 * internals. */

/* DPIF Offload specific structure pointed to in struct dpif. */
struct dpif_offload_provider_collection {
    char *dpif_name;        /* Name of the associated dpif. */

    struct ovs_list list;   /* Note that offload providers will only be added
                             * at dpif creation time and removed during
                             * destruction.  No intermediate additions or
                             * deletions are allowed; hence no locking of the
                             * list is required. */

    struct ovs_mutex mutex; /* Mutex to protect all below. */
    struct ovs_refcount ref_cnt;
};

/* This structure should be treated as opaque by dpif offload implementations.
 */
struct dpif_offload {
    const struct dpif_offload_class *class;
    struct ovs_list dpif_list_node;
    char *name;
};


struct dpif_offload_class {
    /* Type of DPIF offload provider in this class, e.g., "tc", "dpdk",
     * "dummy", etc. */
    const char *type;

    /* List of DPIF implementation types supported by the offload provider.
     * This is implemented as a pointer to a null-terminated list of const
     * type strings.  For more details on these type strings, see the
     * 'struct dpif_class' definition. */
    const char *const *supported_dpif_types;

    /* Called when the dpif offload provider class is registered.  Note that
     * this is the global initialization, not the per dpif one. */
    int (*init)(void);

    /* Attempts to open the offload provider for the specified dpif.
     * If successful, stores a pointer to the new dpif offload in
     * 'dpif_offload **', which must be of class 'dpif_offload_class'.
     * On failure (indicated by a negative return value), there are no
     * requirements for what is stored in 'dpif_offload **'. */
    int (*open)(const struct dpif_offload_class *,
                struct dpif *, struct dpif_offload **);

    /* Closes 'dpif_offload' and frees associated memory and resources.
     * This includes freeing the 'dpif_offload' structure allocated by
     * open() above.  If implementation accesses this provider using
     * RCU pointers, it's responsible for handling deferred deallocation. */
    void (*close)(struct dpif_offload *);
    /* Pass custom configuration options to the offload provider. */
    void (*set_config)(struct dpif_offload *,
                       const struct smap *other_config);

    /* Verifies whether the offload provider supports offloading flows for the
     * given 'netdev'.  Returns 'false' if the provider lacks the capabilities
     * to offload on this port, otherwise returns 'true'. */
    bool (*can_offload)(struct dpif_offload *,
                        struct netdev *);

    /* This callback is invoked when a 'netdev' port has been successfully
     * added to the dpif and should be handled by this offload provider.
     * It is assumed that the 'can_offload' callback was previously called
     * and returned 'true' before this function is executed. */
    int (*port_add)(struct dpif_offload *, struct netdev *,
                    odp_port_t port_no);

    /* This callback is invoked when the 'port_no' port has been successfully
     * removed from the dpif.  Note that it is called for every deleted port,
     * even if 'port_added' was never called, as the framework does not track
     * added ports. */
    int (*port_del)(struct dpif_offload *, odp_port_t port_no);

    /* Refreshes the configuration of 'port_no' port.  The same note as above
     * in 'port_deleted' applies here. */
    void (*port_set_config)(struct dpif_offload *, odp_port_t port_no,
                            const struct smap *cfg);
};


extern struct dpif_offload_class dpif_offload_dummy_class;
extern struct dpif_offload_class dpif_offload_dummy_x_class;
extern struct dpif_offload_class dpif_offload_dpdk_class;
extern struct dpif_offload_class dpif_offload_tc_class;


/* Structure used by the common dpif port management library functions. */
struct dpif_offload_port_mgr {
    struct ovs_mutex cmap_mod_lock;

    struct cmap odp_port_to_port;
    struct cmap netdev_to_port;
    struct cmap ifindex_to_port;
};

struct dpif_offload_port_mgr_port {
    struct cmap_node odp_port_node;
    struct cmap_node netdev_node;
    struct cmap_node ifindex_node;
    struct netdev *netdev;
    odp_port_t port_no;
    int ifindex;
};


/* Global dpif port management library functions. */
struct dpif_offload_port_mgr *dpif_offload_port_mgr_init(void);
bool dpif_offload_port_mgr_add(struct dpif_offload_port_mgr *,
                               struct dpif_offload_port_mgr_port *,
                               struct netdev *netdev, odp_port_t,
                               bool need_ifindex);
struct dpif_offload_port_mgr_port *dpif_offload_port_mgr_remove(
    struct dpif_offload_port_mgr *, odp_port_t);
void dpif_offload_port_mgr_uninit(struct dpif_offload_port_mgr *);
struct dpif_offload_port_mgr_port *dpif_offload_port_mgr_find_by_ifindex(
    struct dpif_offload_port_mgr *, int ifindex);
struct dpif_offload_port_mgr_port *dpif_offload_port_mgr_find_by_netdev(
    struct dpif_offload_port_mgr *, struct netdev *);
struct dpif_offload_port_mgr_port *dpif_offload_port_mgr_find_by_odp_port(
    struct dpif_offload_port_mgr *, odp_port_t);

#define DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH(PORT, PORT_MGR) \
    CMAP_FOR_EACH (PORT, odp_port_node, &(PORT_MGR)->odp_port_to_port)

/* Global functions, called by the dpif layer or offload providers. */
void dpif_offload_module_init(void);
void dpif_offload_set_config(struct dpif *, const struct smap *other_cfg);
void dpif_offload_port_add(struct dpif *, struct netdev *, odp_port_t);
void dpif_offload_port_del(struct dpif *, odp_port_t);
void dpif_offload_port_set_config(struct dpif *, odp_port_t,
                                  const struct smap *cfg);
void dpif_offload_set_netdev_offload(struct netdev *, struct dpif_offload *);

static inline void
dpif_offload_assert_class(const struct dpif_offload *dpif_offload,
                          const struct dpif_offload_class *dpif_offload_class)
{
    ovs_assert(dpif_offload->class == dpif_offload_class);
}

#endif /* DPIF_OFFLOAD_PROVIDER_H */
