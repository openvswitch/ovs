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


struct dpif_offload_flow_dump {
    struct dpif_offload *offload;
    bool terse;
};

static inline void
dpif_offload_flow_dump_init(struct dpif_offload_flow_dump *dump,
                            const struct dpif_offload *offload, bool terse)
{
    dump->offload = CONST_CAST(struct dpif_offload *, offload);
    dump->terse = terse;
}

struct dpif_offload_flow_dump_thread {
    struct dpif_offload_flow_dump *dump;
};

static inline void
dpif_offload_flow_dump_thread_init(
    struct dpif_offload_flow_dump_thread *thread,
    struct dpif_offload_flow_dump *dump)
{
    thread->dump = dump;
}


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

    /* Retrieve debug information from the offload provider in either string
     * (ds) or JSON format.  If both formats are requested, the provider may
     * choose which one to return.  Note that the actual format is unspecified,
     * it's up to the provider to decide what to return.  If 'ds' is supplied,
     * it should be initialized, and might already contain data.  The caller is
     * responsible for freeing any returned 'ds' or 'json' pointers. */
    void (*get_debug)(const struct dpif_offload *offload, struct ds *ds,
                      struct json *json);

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

    /* Deletes all offloaded flows for this offload_provider.  Return 0 if
     * successful, otherwise returns a positive errno value. */
    int (*flow_flush)(const struct dpif_offload *);

    /* Flow Dumping Interface for dpif-offload.
     *
     * This interface mirrors the flow dumping interface found in the dpif
     * layer.  For a thorough understanding of the design and expectations,
     * please refer to the documentation in:
     *   - include/openvswitch/dpif.h
     *   - include/openvswitch/dpif-provider.h
     *
     * The dpif-offload flow dumping interface is intended for use only when
     * there is a clear separation between traditional dpif flows and offloaded
     * flows handled by an offload mechanism.
     *
     * For example:
     *   - The 'tc' offload provider installs flow rules via kernel tc without
     *     creating corresponding kernel datapath (dpif) flows.  In such cases,
     *     dumping dpif flows would not reflect the actual set of active
     *     offloaded flows.  This interface provides a way to explicitly
     *     enumerate such offloaded flows.
     *
     * 'flow_dump_create' and 'flow_dump_thread_create' must always return
     * initialized and usable data structures.  Specifically, they must
     * initialize the returned structures using dpif_offload_flow_dump_init()
     * and dpif_offload_flow_dump_thread_init(), respectively, and defer any
     * error reporting until flow_dump_destroy() is called. */
    struct dpif_offload_flow_dump *(*flow_dump_create)(
        const struct dpif_offload *, bool terse);

    int (*flow_dump_next)(struct dpif_offload_flow_dump_thread *,
                          struct dpif_flow *, int max_flows);

    int (*flow_dump_destroy)(struct dpif_offload_flow_dump *);

    struct dpif_offload_flow_dump_thread *(*flow_dump_thread_create)(
        struct dpif_offload_flow_dump *);

    void (*flow_dump_thread_destroy)(struct dpif_offload_flow_dump_thread *);

    /* Returns the number of flows offloaded by the offload provider. */
    uint64_t (*flow_count)(const struct dpif_offload *);

    /* Adds or modifies the meter in 'dpif_offload' with the given 'meter_id'
     * and the configuration in 'config'.
     *
     * The meter id specified through 'config->meter_id' is ignored. */
    int (*meter_set)(const struct dpif_offload *, ofproto_meter_id meter_id,
                     struct ofputil_meter_config *);

    /* Queries HW for meter stats with the given 'meter_id'.  Store the stats
     * of dropped packets to band 0.  On failure, a non-zero error code is
     * returned.
     *
     * Note that the 'stats' structure is already initialized, and only the
     * available statistics should be incremented, not replaced.  Those fields
     * are packet_in_count, byte_in_count and band[]->byte_count and
     * band[]->packet_count. */
    int (*meter_get)(const struct dpif_offload *, ofproto_meter_id meter_id,
                     struct ofputil_meter_stats *);

    /* Removes meter 'meter_id' from HW.  Store the stats of dropped packets to
     * band 0.  On failure, a non-zero error code is returned.
     *
     * 'stats' may be passed in as NULL if no stats are needed.  See the above
     * function for additional details on the 'stats' usage. */
    int (*meter_del)(const struct dpif_offload *, ofproto_meter_id meter_id,
                     struct ofputil_meter_stats *);


    /* These APIs operate directly on the provided netdev for performance
     * reasons.  They are intended for use in fast path processing and should
     * be designed with speed and efficiency in mind. */

    /* Deletes all offloaded flows on this netdev.  Return 0 if successful,
     * otherwise returns a positive errno value. */
    int (*netdev_flow_flush)(const struct dpif_offload *, struct netdev *);

    /* Recover and/or set the packet state (contents and metadata) for
     * continued processing in software, and/or perform any additional
     * post-processing required by the offload provider.
     *
     * Return 0 if successful and the packet requires further processing;
     * otherwise, return a positive errno value and take ownership of the
     * packet if errno != EOPNOTSUPP.  Return ECANCELED if the packet was
     * fully consumed by the provider for non-error conditions. */
    int (*netdev_hw_post_process)(const struct dpif_offload *, struct netdev *,
                                  struct dp_packet *);
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
void dpif_offload_flow_dump_create(struct dpif_flow_dump *,
                                   const struct dpif *, bool terse);
int dpif_offload_flow_dump_destroy(struct dpif_flow_dump *);
int dpif_offload_flow_dump_next(struct dpif_flow_dump_thread *,
                                struct dpif_flow *, int max_flows);
void dpif_offload_flow_dump_thread_create(struct dpif_flow_dump_thread *,
                                          struct dpif_flow_dump *);
void dpif_offload_flow_dump_thread_destroy(struct dpif_flow_dump_thread *);

static inline void
dpif_offload_assert_class(const struct dpif_offload *dpif_offload,
                          const struct dpif_offload_class *dpif_offload_class)
{
    ovs_assert(dpif_offload->class == dpif_offload_class);
}

#endif /* DPIF_OFFLOAD_PROVIDER_H */
