/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

#ifndef OFPROTO_H
#define OFPROTO_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cfm.h"
#include "classifier.h"
#include "flow.h"
#include "meta-flow.h"
#include "netflow.h"
#include "sset.h"
#include "stp.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct bfd_cfg;
struct cfm_settings;
struct cls_rule;
struct netdev;
struct netdev_stats;
struct ofport;
struct ofproto;
struct shash;
struct simap;
struct smap;

struct ofproto_controller_info {
    bool is_connected;
    enum ofp12_controller_role role;
    struct {
        const char *keys[4];
        const char *values[4];
        size_t n;
    } pairs;
};

struct ofproto_sflow_options {
    struct sset targets;
    uint32_t sampling_rate;
    uint32_t polling_interval;
    uint32_t header_len;
    uint32_t sub_id;
    char *agent_device;
    char *control_ip;
};

struct ofproto_ipfix_bridge_exporter_options {
    struct sset targets;
    uint32_t sampling_rate;
    uint32_t obs_domain_id;  /* Bridge-wide Observation Domain ID. */
    uint32_t obs_point_id;  /* Bridge-wide Observation Point ID. */
    uint32_t cache_active_timeout;
    uint32_t cache_max_flows;
};

struct ofproto_ipfix_flow_exporter_options {
    uint32_t collector_set_id;
    struct sset targets;
    uint32_t cache_active_timeout;
    uint32_t cache_max_flows;
};

struct ofproto_stp_settings {
    stp_identifier system_id;
    uint16_t priority;
    uint16_t hello_time;
    uint16_t max_age;
    uint16_t fwd_delay;
};

struct ofproto_stp_status {
    bool enabled;               /* If false, ignore other members. */
    stp_identifier bridge_id;
    stp_identifier designated_root;
    int root_path_cost;
};

struct ofproto_port_stp_settings {
    bool enable;
    uint8_t port_num;           /* In the range 1-255, inclusive. */
    uint8_t priority;
    uint16_t path_cost;
};

struct ofproto_port_stp_status {
    bool enabled;               /* If false, ignore other members. */
    int port_id;
    enum stp_state state;
    unsigned int sec_in_state;
    enum stp_role role;
};

struct ofproto_port_stp_stats {
    bool enabled;               /* If false, ignore other members. */
    int tx_count;               /* Number of BPDUs transmitted. */
    int rx_count;               /* Number of valid BPDUs received. */
    int error_count;            /* Number of bad BPDUs received. */
};

struct ofproto_port_queue {
    uint32_t queue;             /* Queue ID. */
    uint8_t dscp;               /* DSCP bits (e.g. [0, 63]). */
};

/* How the switch should act if the controller cannot be contacted. */
enum ofproto_fail_mode {
    OFPROTO_FAIL_SECURE,        /* Preserve flow table. */
    OFPROTO_FAIL_STANDALONE     /* Act as a standalone switch. */
};

enum ofproto_band {
    OFPROTO_IN_BAND,            /* In-band connection to controller. */
    OFPROTO_OUT_OF_BAND         /* Out-of-band connection to controller. */
};

struct ofproto_controller {
    char *target;               /* e.g. "tcp:127.0.0.1" */
    int max_backoff;            /* Maximum reconnection backoff, in seconds. */
    int probe_interval;         /* Max idle time before probing, in seconds. */
    enum ofproto_band band;     /* In-band or out-of-band? */
    bool enable_async_msgs;     /* Initially enable asynchronous messages? */

    /* OpenFlow packet-in rate-limiting. */
    int rate_limit;             /* Max packet-in rate in packets per second. */
    int burst_limit;            /* Limit on accumulating packet credits. */

    uint8_t dscp;               /* DSCP value for controller connection. */
};

void ofproto_enumerate_types(struct sset *types);
const char *ofproto_normalize_type(const char *);

int ofproto_enumerate_names(const char *type, struct sset *names);
void ofproto_parse_name(const char *name, char **dp_name, char **dp_type);

/* An interface hint element, which is used by ofproto_init() to
 * describe the caller's understanding of the startup state. */
struct iface_hint {
    char *br_name;              /* Name of owning bridge. */
    char *br_type;              /* Type of owning bridge. */
    ofp_port_t ofp_port;        /* OpenFlow port number. */
};

void ofproto_init(const struct shash *iface_hints);

int ofproto_type_run(const char *datapath_type);
void ofproto_type_wait(const char *datapath_type);

int ofproto_create(const char *datapath, const char *datapath_type,
                   struct ofproto **ofprotop);
void ofproto_destroy(struct ofproto *);
int ofproto_delete(const char *name, const char *type);

int ofproto_run(struct ofproto *);
void ofproto_wait(struct ofproto *);
bool ofproto_is_alive(const struct ofproto *);

void ofproto_get_memory_usage(const struct ofproto *, struct simap *);
void ofproto_type_get_memory_usage(const char *datapath_type, struct simap *);

/* A port within an OpenFlow switch.
 *
 * 'name' and 'type' are suitable for passing to netdev_open(). */
struct ofproto_port {
    char *name;                 /* Network device name, e.g. "eth0". */
    char *type;                 /* Network device type, e.g. "system". */
    ofp_port_t ofp_port;        /* OpenFlow port number. */
};
void ofproto_port_clone(struct ofproto_port *, const struct ofproto_port *);
void ofproto_port_destroy(struct ofproto_port *);

struct ofproto_port_dump {
    const struct ofproto *ofproto;
    int error;
    void *state;
};
void ofproto_port_dump_start(struct ofproto_port_dump *,
                             const struct ofproto *);
bool ofproto_port_dump_next(struct ofproto_port_dump *, struct ofproto_port *);
int ofproto_port_dump_done(struct ofproto_port_dump *);

/* Iterates through each OFPROTO_PORT in OFPROTO, using DUMP as state.
 *
 * Arguments all have pointer type.
 *
 * If you break out of the loop, then you need to free the dump structure by
 * hand using ofproto_port_dump_done(). */
#define OFPROTO_PORT_FOR_EACH(OFPROTO_PORT, DUMP, OFPROTO)  \
    for (ofproto_port_dump_start(DUMP, OFPROTO);            \
         (ofproto_port_dump_next(DUMP, OFPROTO_PORT)        \
          ? true                                            \
          : (ofproto_port_dump_done(DUMP), false));         \
        )

#define OFPROTO_FLOW_LIMIT_DEFAULT 200000
#define OFPROTO_MAX_IDLE_DEFAULT 1500

const char *ofproto_port_open_type(const char *datapath_type,
                                   const char *port_type);
int ofproto_port_add(struct ofproto *, struct netdev *, ofp_port_t *ofp_portp);
int ofproto_port_del(struct ofproto *, ofp_port_t ofp_port);
int ofproto_port_get_stats(const struct ofport *, struct netdev_stats *stats);

int ofproto_port_query_by_name(const struct ofproto *, const char *devname,
                               struct ofproto_port *);

/* Top-level configuration. */
uint64_t ofproto_get_datapath_id(const struct ofproto *);
void ofproto_set_datapath_id(struct ofproto *, uint64_t datapath_id);
void ofproto_set_controllers(struct ofproto *,
                             const struct ofproto_controller *, size_t n,
                             uint32_t allowed_versions);
void ofproto_set_fail_mode(struct ofproto *, enum ofproto_fail_mode fail_mode);
void ofproto_reconnect_controllers(struct ofproto *);
void ofproto_set_extra_in_band_remotes(struct ofproto *,
                                       const struct sockaddr_in *, size_t n);
void ofproto_set_in_band_queue(struct ofproto *, int queue_id);
void ofproto_set_flow_limit(unsigned limit);
void ofproto_set_max_idle(unsigned max_idle);
void ofproto_set_forward_bpdu(struct ofproto *, bool forward_bpdu);
void ofproto_set_mac_table_config(struct ofproto *, unsigned idle_time,
                                  size_t max_entries);
void ofproto_set_threads(int n_handlers, int n_revalidators);
void ofproto_set_dp_desc(struct ofproto *, const char *dp_desc);
int ofproto_set_snoops(struct ofproto *, const struct sset *snoops);
int ofproto_set_netflow(struct ofproto *,
                        const struct netflow_options *nf_options);
int ofproto_set_sflow(struct ofproto *, const struct ofproto_sflow_options *);
int ofproto_set_ipfix(struct ofproto *,
                      const struct ofproto_ipfix_bridge_exporter_options *,
                      const struct ofproto_ipfix_flow_exporter_options *,
                      size_t);
void ofproto_set_flow_restore_wait(bool flow_restore_wait_db);
bool ofproto_get_flow_restore_wait(void);
int ofproto_set_stp(struct ofproto *, const struct ofproto_stp_settings *);
int ofproto_get_stp_status(struct ofproto *, struct ofproto_stp_status *);

/* Configuration of ports. */
void ofproto_port_unregister(struct ofproto *, ofp_port_t ofp_port);

void ofproto_port_clear_cfm(struct ofproto *, ofp_port_t ofp_port);
void ofproto_port_set_cfm(struct ofproto *, ofp_port_t ofp_port,
                          const struct cfm_settings *);
void ofproto_port_set_bfd(struct ofproto *, ofp_port_t ofp_port,
                          const struct smap *cfg);
int ofproto_port_get_bfd_status(struct ofproto *, ofp_port_t ofp_port,
                                bool force, struct smap *);
int ofproto_port_is_lacp_current(struct ofproto *, ofp_port_t ofp_port);
int ofproto_port_set_stp(struct ofproto *, ofp_port_t ofp_port,
                         const struct ofproto_port_stp_settings *);
int ofproto_port_get_stp_status(struct ofproto *, ofp_port_t ofp_port,
                                struct ofproto_port_stp_status *);
int ofproto_port_get_stp_stats(struct ofproto *, ofp_port_t ofp_port,
                               struct ofproto_port_stp_stats *);
int ofproto_port_set_queues(struct ofproto *, ofp_port_t ofp_port,
                            const struct ofproto_port_queue *,
                            size_t n_queues);

/* The behaviour of the port regarding VLAN handling */
enum port_vlan_mode {
    /* This port is an access port.  'vlan' is the VLAN ID.  'trunks' is
     * ignored. */
    PORT_VLAN_ACCESS,

    /* This port is a trunk.  'trunks' is the set of trunks. 'vlan' is
     * ignored. */
    PORT_VLAN_TRUNK,

    /* Untagged incoming packets are part of 'vlan', as are incoming packets
     * tagged with 'vlan'.  Outgoing packets tagged with 'vlan' stay tagged.
     * Other VLANs in 'trunks' are trunked. */
    PORT_VLAN_NATIVE_TAGGED,

    /* Untagged incoming packets are part of 'vlan', as are incoming packets
     * tagged with 'vlan'.  Outgoing packets tagged with 'vlan' are untagged.
     * Other VLANs in 'trunks' are trunked. */
    PORT_VLAN_NATIVE_UNTAGGED
};

/* Configuration of bundles. */
struct ofproto_bundle_settings {
    char *name;                 /* For use in log messages. */

    ofp_port_t *slaves;         /* OpenFlow port numbers for slaves. */
    size_t n_slaves;

    enum port_vlan_mode vlan_mode; /* Selects mode for vlan and trunks */
    int vlan;                   /* VLAN VID, except for PORT_VLAN_TRUNK. */
    unsigned long *trunks;      /* vlan_bitmap, except for PORT_VLAN_ACCESS. */
    bool use_priority_tags;     /* Use 802.1p tag for frames in VLAN 0? */

    struct bond_settings *bond; /* Must be nonnull iff if n_slaves > 1. */

    struct lacp_settings *lacp;              /* Nonnull to enable LACP. */
    struct lacp_slave_settings *lacp_slaves; /* Array of n_slaves elements. */

    /* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
     *
     * This is deprecated.  It is only for compatibility with broken device
     * drivers in old versions of Linux that do not properly support VLANs when
     * VLAN devices are not used.  When broken device drivers are no longer in
     * widespread use, we will delete these interfaces. */
    ofp_port_t realdev_ofp_port;/* OpenFlow port number of real device. */
};

int ofproto_bundle_register(struct ofproto *, void *aux,
                            const struct ofproto_bundle_settings *);
int ofproto_bundle_unregister(struct ofproto *, void *aux);

/* Configuration of mirrors. */
struct ofproto_mirror_settings {
    /* Name for log messages. */
    char *name;

    /* Bundles that select packets for mirroring upon ingress.  */
    void **srcs;                /* A set of registered ofbundle handles. */
    size_t n_srcs;

    /* Bundles that select packets for mirroring upon egress.  */
    void **dsts;                /* A set of registered ofbundle handles. */
    size_t n_dsts;

    /* VLANs of packets to select for mirroring. */
    unsigned long *src_vlans;   /* vlan_bitmap, NULL selects all VLANs. */

    /* Output (mutually exclusive). */
    void *out_bundle;           /* A registered ofbundle handle or NULL. */
    uint16_t out_vlan;          /* Output VLAN, only if out_bundle is NULL. */
};

int ofproto_mirror_register(struct ofproto *, void *aux,
                            const struct ofproto_mirror_settings *);
int ofproto_mirror_unregister(struct ofproto *, void *aux);
int ofproto_mirror_get_stats(struct ofproto *, void *aux,
                             uint64_t *packets, uint64_t *bytes);

int ofproto_set_flood_vlans(struct ofproto *, unsigned long *flood_vlans);
bool ofproto_is_mirror_output_bundle(const struct ofproto *, void *aux);

/* Configuration of OpenFlow tables. */
struct ofproto_table_settings {
    char *name;                 /* Name exported via OpenFlow or NULL. */
    unsigned int max_flows;     /* Maximum number of flows or UINT_MAX. */

    /* These members determine the handling of an attempt to add a flow that
     * would cause the table to have more than 'max_flows' flows.
     *
     * If 'groups' is NULL, overflows will be rejected with an error.
     *
     * If 'groups' is nonnull, an overflow will cause a flow to be removed.
     * The flow to be removed is chosen to give fairness among groups
     * distinguished by different values for the subfields within 'groups'. */
    struct mf_subfield *groups;
    size_t n_groups;

    /*
     * Fields for which prefix trie lookup is maintained.
     */
    unsigned int n_prefix_fields;
    enum mf_field_id prefix_fields[CLS_MAX_TRIES];
};

int ofproto_get_n_tables(const struct ofproto *);
uint8_t ofproto_get_n_visible_tables(const struct ofproto *);
void ofproto_configure_table(struct ofproto *, int table_id,
                             const struct ofproto_table_settings *);

/* Configuration querying. */
bool ofproto_has_snoops(const struct ofproto *);
void ofproto_get_snoops(const struct ofproto *, struct sset *);
void ofproto_get_all_flows(struct ofproto *p, struct ds *);
void ofproto_get_netflow_ids(const struct ofproto *,
                             uint8_t *engine_type, uint8_t *engine_id);

void ofproto_get_ofproto_controller_info(const struct ofproto *, struct shash *);
void ofproto_free_ofproto_controller_info(struct shash *);

/* CFM status query. */
struct ofproto_cfm_status {
    /* 0 if not faulted, otherwise a combination of one or more reasons. */
    enum cfm_fault_reason faults;

    /* 0 if the remote CFM endpoint is operationally down,
     * 1 if the remote CFM endpoint is operationally up,
     * -1 if we don't know because the remote CFM endpoint is not in extended
     * mode. */
    int remote_opstate;

    uint64_t flap_count;

    /* Ordinarily a "health status" in the range 0...100 inclusive, with 0
     * being worst and 100 being best, or -1 if the health status is not
     * well-defined. */
    int health;

    /* MPIDs of remote maintenance points whose CCMs have been received. */
    uint64_t *rmps;
    size_t n_rmps;
};

int ofproto_port_get_cfm_status(const struct ofproto *,
                                ofp_port_t ofp_port, bool force,
                                struct ofproto_cfm_status *);

/* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
 *
 * This is deprecated.  It is only for compatibility with broken device drivers
 * in old versions of Linux that do not properly support VLANs when VLAN
 * devices are not used.  When broken device drivers are no longer in
 * widespread use, we will delete these interfaces. */

void ofproto_get_vlan_usage(struct ofproto *, unsigned long int *vlan_bitmap);
bool ofproto_has_vlan_usage_changed(const struct ofproto *);
int ofproto_port_set_realdev(struct ofproto *, ofp_port_t vlandev_ofp_port,
                             ofp_port_t realdev_ofp_port, int vid);

/* Table configuration */

enum ofproto_table_config {
    /* Send to controller. */
    OFPROTO_TABLE_MISS_CONTROLLER = OFPTC11_TABLE_MISS_CONTROLLER,

    /* Continue to the next table in the pipeline (OpenFlow 1.0 behavior). */
    OFPROTO_TABLE_MISS_CONTINUE   = OFPTC11_TABLE_MISS_CONTINUE,

    /* Drop the packet. */
    OFPROTO_TABLE_MISS_DROP       = OFPTC11_TABLE_MISS_DROP,

    /* The default miss behaviour for the OpenFlow version of the controller a
     * packet_in message would be sent to..  For pre-OF1.3 controllers, send
     * packet_in to controller.  For OF1.3+ controllers, drop. */
    OFPROTO_TABLE_MISS_DEFAULT    = 3,
};

enum ofproto_table_config ofproto_table_get_config(const struct ofproto *,
                                                   uint8_t table_id);

#ifdef  __cplusplus
}
#endif

#endif /* ofproto.h */
