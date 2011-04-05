/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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
#include "flow.h"
#include "netflow.h"
#include "sset.h"
#include "tag.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct cfm;
struct cls_rule;
struct dpif_port;
struct netdev;
struct nlattr;
struct ofhooks;
struct ofproto;
struct shash;

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
    enum ofproto_band band;      /* In-band or out-of-band? */

    /* OpenFlow packet-in rate-limiting. */
    int rate_limit;             /* Max packet-in rate in packets per second. */
    int burst_limit;            /* Limit on accumulating packet credits. */
};

#define DEFAULT_MFR_DESC "Nicira Networks, Inc."
#define DEFAULT_HW_DESC "Open vSwitch"
#define DEFAULT_SW_DESC VERSION BUILDNR
#define DEFAULT_SERIAL_DESC "None"
#define DEFAULT_DP_DESC "None"

int ofproto_create(const char *datapath, const char *datapath_type,
                   const struct ofhooks *, void *aux,
                   struct ofproto **ofprotop);
void ofproto_destroy(struct ofproto *);
void ofproto_destroy_and_delete(struct ofproto *);
int ofproto_run(struct ofproto *);
int ofproto_run1(struct ofproto *);
int ofproto_run2(struct ofproto *, bool revalidate_all);
void ofproto_wait(struct ofproto *);
bool ofproto_is_alive(const struct ofproto *);

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

/* Iterates through each DPIF_PORT in OFPROTO, using DUMP as state.
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

int ofproto_port_add(struct ofproto *, struct netdev *, uint16_t *ofp_portp);
int ofproto_port_del(struct ofproto *, uint16_t ofp_port);
bool ofproto_port_is_floodable(struct ofproto *, uint16_t odp_port);

int ofproto_port_query_by_name(const struct ofproto *, const char *devname,
                               struct ofproto_port *);

/* Top-level configuration. */
void ofproto_set_datapath_id(struct ofproto *, uint64_t datapath_id);
void ofproto_set_controllers(struct ofproto *,
                             const struct ofproto_controller *, size_t n);
void ofproto_set_fail_mode(struct ofproto *, enum ofproto_fail_mode fail_mode);
void ofproto_reconnect_controllers(struct ofproto *);
void ofproto_set_extra_in_band_remotes(struct ofproto *,
                                       const struct sockaddr_in *, size_t n);
void ofproto_set_in_band_queue(struct ofproto *, int queue_id);
void ofproto_set_desc(struct ofproto *,
                      const char *mfr_desc, const char *hw_desc,
                      const char *sw_desc, const char *serial_desc,
                      const char *dp_desc);
int ofproto_set_snoops(struct ofproto *, const struct sset *snoops);
int ofproto_set_netflow(struct ofproto *,
                        const struct netflow_options *nf_options);
void ofproto_set_sflow(struct ofproto *, const struct ofproto_sflow_options *);

/* Configuration of individual interfaces. */
void ofproto_port_clear_cfm(struct ofproto *, uint32_t port_no);
void ofproto_port_set_cfm(struct ofproto *, uint32_t port_no,
                          const struct cfm *,
                          const uint16_t *remote_mps, size_t n_remote_mps);
const struct cfm *ofproto_port_get_cfm(struct ofproto *, uint32_t port_no);

/* Configuration querying. */
uint64_t ofproto_get_datapath_id(const struct ofproto *);
enum ofproto_fail_mode ofproto_get_fail_mode(const struct ofproto *);
void ofproto_get_listeners(const struct ofproto *, struct sset *);
bool ofproto_has_snoops(const struct ofproto *);
void ofproto_get_snoops(const struct ofproto *, struct sset *);
void ofproto_get_all_flows(struct ofproto *p, struct ds *);
void ofproto_get_netflow_ids(const struct ofproto *,
                             uint8_t *engine_type, uint8_t *engine_id);

/* Hooks for ovs-vswitchd. */
struct ofhooks {
    bool (*normal_cb)(const struct flow *, const struct ofpbuf *packet,
                      struct ofpbuf *odp_actions, tag_type *,
                      uint16_t *nf_output_iface, void *aux);
    bool (*special_cb)(const struct flow *flow, const struct ofpbuf *packet,
                       void *aux);
    void (*account_flow_cb)(const struct flow *, tag_type tags,
                            const struct nlattr *odp_actions,
                            size_t actions_len,
                            uint64_t n_bytes, void *aux);
    void (*account_checkpoint_cb)(void *aux);

    uint16_t (*autopath_cb)(const struct flow *, uint32_t id,
                            tag_type *, void *aux);
};
void ofproto_revalidate(struct ofproto *, tag_type);
struct tag_set *ofproto_get_revalidate_set(struct ofproto *);

void ofproto_get_ofproto_controller_info(const struct ofproto *, struct shash *);
void ofproto_free_ofproto_controller_info(struct shash *);

#ifdef  __cplusplus
}
#endif

#endif /* ofproto.h */
