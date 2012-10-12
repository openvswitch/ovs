/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include "flow.h"
#include "netflow.h"
#include "sset.h"
#include "stp.h"
#include "tag.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct cfm_settings;
struct cls_rule;
struct netdev;
struct ofproto;
struct ofport;
struct shash;
struct simap;
struct netdev_stats;

struct ofproto_controller_info {
    bool is_connected;
    enum nx_role role;
    struct {
        const char *keys[4];
        const char *values[4];
        size_t n;
    } pairs;
};

struct ofexpired {
    struct flow flow;
    uint64_t packet_count;      /* Packets from subrules. */
    uint64_t byte_count;        /* Bytes from subrules. */
    long long int used;         /* Last-used time (0 if never used). */
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

#define DEFAULT_MFR_DESC "Nicira, Inc."
#define DEFAULT_HW_DESC "Open vSwitch"
#define DEFAULT_SW_DESC VERSION
#define DEFAULT_SERIAL_DESC "None"
#define DEFAULT_DP_DESC "None"

void ofproto_enumerate_types(struct sset *types);
const char *ofproto_normalize_type(const char *);

int ofproto_enumerate_names(const char *type, struct sset *names);
void ofproto_parse_name(const char *name, char **dp_name, char **dp_type);

int ofproto_create(const char *datapath, const char *datapath_type,
                   struct ofproto **ofprotop);
void ofproto_destroy(struct ofproto *);
int ofproto_delete(const char *name, const char *type);

int ofproto_run(struct ofproto *);
int ofproto_run_fast(struct ofproto *);
void ofproto_wait(struct ofproto *);
bool ofproto_is_alive(const struct ofproto *);

void ofproto_get_memory_usage(const struct ofproto *, struct simap *);

/* A port within an OpenFlow switch.
 *
 * 'name' and 'type' are suitable for passing to netdev_open(). */
struct ofproto_port {
    char *name;                 /* Network device name, e.g. "eth0". */
    char *type;                 /* Network device type, e.g. "system". */
    uint16_t ofp_port;          /* OpenFlow port number. */
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

#define OFPROTO_FLOW_EVICTION_THRESHOLD_DEFAULT  1000
#define OFPROTO_FLOW_EVICTION_THRESHOLD_MIN 100

int ofproto_port_add(struct ofproto *, struct netdev *, uint16_t *ofp_portp);
int ofproto_port_del(struct ofproto *, uint16_t ofp_port);
int ofproto_port_get_stats(const struct ofport *, struct netdev_stats *stats);

int ofproto_port_query_by_name(const struct ofproto *, const char *devname,
                               struct ofproto_port *);

/* Top-level configuration. */
uint64_t ofproto_get_datapath_id(const struct ofproto *);
void ofproto_set_datapath_id(struct ofproto *, uint64_t datapath_id);
void ofproto_set_controllers(struct ofproto *,
                             const struct ofproto_controller *, size_t n);
void ofproto_set_fail_mode(struct ofproto *, enum ofproto_fail_mode fail_mode);
void ofproto_reconnect_controllers(struct ofproto *);
void ofproto_set_extra_in_band_remotes(struct ofproto *,
                                       const struct sockaddr_in *, size_t n);
void ofproto_set_in_band_queue(struct ofproto *, int queue_id);
void ofproto_set_flow_eviction_threshold(struct ofproto *, unsigned threshold);
void ofproto_set_forward_bpdu(struct ofproto *, bool forward_bpdu);
void ofproto_set_mac_idle_time(struct ofproto *, unsigned idle_time);
void ofproto_set_desc(struct ofproto *,
                      const char *mfr_desc, const char *hw_desc,
                      const char *sw_desc, const char *serial_desc,
                      const char *dp_desc);
int ofproto_set_snoops(struct ofproto *, const struct sset *snoops);
int ofproto_set_netflow(struct ofproto *,
                        const struct netflow_options *nf_options);
int ofproto_set_sflow(struct ofproto *, const struct ofproto_sflow_options *);
int ofproto_set_stp(struct ofproto *, const struct ofproto_stp_settings *);
int ofproto_get_stp_status(struct ofproto *, struct ofproto_stp_status *);

/* Configuration of ports. */
void ofproto_port_unregister(struct ofproto *, uint16_t ofp_port);

void ofproto_port_clear_cfm(struct ofproto *, uint16_t ofp_port);
void ofproto_port_set_cfm(struct ofproto *, uint16_t ofp_port,
                          const struct cfm_settings *);
int ofproto_port_is_lacp_current(struct ofproto *, uint16_t ofp_port);
int ofproto_port_set_stp(struct ofproto *, uint16_t ofp_port,
                         const struct ofproto_port_stp_settings *);
int ofproto_port_get_stp_status(struct ofproto *, uint16_t ofp_port,
                                struct ofproto_port_stp_status *);
int ofproto_port_set_queues(struct ofproto *, uint16_t ofp_port,
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

    uint16_t *slaves;           /* OpenFlow port numbers for slaves. */
    size_t n_slaves;

    enum port_vlan_mode vlan_mode; /* Selects mode for vlan and trunks */
    int vlan;                   /* VLAN VID, except for PORT_VLAN_TRUNK. */
    unsigned long *trunks;      /* vlan_bitmap, except for PORT_VLAN_ACCESS. */
    bool use_priority_tags;     /* Use 802.1p tag for frames in VLAN 0? */

    struct bond_settings *bond; /* Must be nonnull iff if n_slaves > 1. */
    uint32_t *bond_stable_ids;  /* Array of n_slaves elements. */

    struct lacp_settings *lacp;              /* Nonnull to enable LACP. */
    struct lacp_slave_settings *lacp_slaves; /* Array of n_slaves elements. */

    /* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
     *
     * This is deprecated.  It is only for compatibility with broken device
     * drivers in old versions of Linux that do not properly support VLANs when
     * VLAN devices are not used.  When broken device drivers are no longer in
     * widespread use, we will delete these interfaces. */
    uint16_t realdev_ofp_port;  /* OpenFlow port number of real device. */
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
};

int ofproto_get_n_tables(const struct ofproto *);
void ofproto_configure_table(struct ofproto *, int table_id,
                             const struct ofproto_table_settings *);

/* Configuration querying. */
bool ofproto_has_snoops(const struct ofproto *);
void ofproto_get_snoops(const struct ofproto *, struct sset *);
void ofproto_get_all_flows(struct ofproto *p, struct ds *);
void ofproto_get_netflow_ids(const struct ofproto *,
                             uint8_t *engine_type, uint8_t *engine_id);
int ofproto_port_get_cfm_fault(const struct ofproto *, uint16_t ofp_port);
int ofproto_port_get_cfm_opup(const struct ofproto *, uint16_t ofp_port);
int ofproto_port_get_cfm_remote_mpids(const struct ofproto *,
                                      uint16_t ofp_port, const uint64_t **rmps,
                                      size_t *n_rmps);
int ofproto_port_get_cfm_health(const struct ofproto *ofproto,
                                uint16_t ofp_port);
void ofproto_get_ofproto_controller_info(const struct ofproto *, struct shash *);
void ofproto_free_ofproto_controller_info(struct shash *);

/* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
 *
 * This is deprecated.  It is only for compatibility with broken device drivers
 * in old versions of Linux that do not properly support VLANs when VLAN
 * devices are not used.  When broken device drivers are no longer in
 * widespread use, we will delete these interfaces. */

void ofproto_get_vlan_usage(struct ofproto *, unsigned long int *vlan_bitmap);
bool ofproto_has_vlan_usage_changed(const struct ofproto *);
int ofproto_port_set_realdev(struct ofproto *, uint16_t vlandev_ofp_port,
                             uint16_t realdev_ofp_port, int vid);

#ifdef  __cplusplus
}
#endif

#endif /* ofproto.h */
