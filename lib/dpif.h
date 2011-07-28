/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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


#ifndef DPIF_H
#define DPIF_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "openflow/openflow.h"
#include "openvswitch/datapath-protocol.h"
#include "netdev.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct dpif;
struct ds;
struct nlattr;
struct ofpbuf;
struct sset;
struct dpif_class;

int dp_register_provider(const struct dpif_class *);
int dp_unregister_provider(const char *type);
void dp_enumerate_types(struct sset *types);
const char *dpif_normalize_type(const char *);

int dp_enumerate_names(const char *type, struct sset *names);
void dp_parse_name(const char *datapath_name, char **name, char **type);

int dpif_open(const char *name, const char *type, struct dpif **);
int dpif_create(const char *name, const char *type, struct dpif **);
int dpif_create_and_open(const char *name, const char *type, struct dpif **);
void dpif_close(struct dpif *);

void dpif_run(struct dpif *);
void dpif_wait(struct dpif *);

const char *dpif_name(const struct dpif *);
const char *dpif_base_name(const struct dpif *);

int dpif_delete(struct dpif *);

int dpif_get_dp_stats(const struct dpif *, struct odp_stats *);
int dpif_get_drop_frags(const struct dpif *, bool *drop_frags);
int dpif_set_drop_frags(struct dpif *, bool drop_frags);

int dpif_port_add(struct dpif *, struct netdev *, uint16_t *port_nop);
int dpif_port_del(struct dpif *, uint16_t port_no);

/* A port within a datapath.
 *
 * 'name' and 'type' are suitable for passing to netdev_open(). */
struct dpif_port {
    char *name;                 /* Network device name, e.g. "eth0". */
    char *type;                 /* Network device type, e.g. "system". */
    uint32_t port_no;           /* Port number within datapath. */
    struct netdev_stats stats;  /* Port statistics. */
};
void dpif_port_clone(struct dpif_port *, const struct dpif_port *);
void dpif_port_destroy(struct dpif_port *);
int dpif_port_query_by_number(const struct dpif *, uint16_t port_no,
                              struct dpif_port *);
int dpif_port_query_by_name(const struct dpif *, const char *devname,
                            struct dpif_port *);
int dpif_port_get_name(struct dpif *, uint16_t port_no,
                       char *name, size_t name_size);
int dpif_get_max_ports(const struct dpif *);

struct dpif_port_dump {
    const struct dpif *dpif;
    int error;
    void *state;
};
void dpif_port_dump_start(struct dpif_port_dump *, const struct dpif *);
bool dpif_port_dump_next(struct dpif_port_dump *, struct dpif_port *);
int dpif_port_dump_done(struct dpif_port_dump *);

/* Iterates through each DPIF_PORT in DPIF, using DUMP as state.
 *
 * Arguments all have pointer type.
 *
 * If you break out of the loop, then you need to free the dump structure by
 * hand using dpif_port_dump_done(). */
#define DPIF_PORT_FOR_EACH(DPIF_PORT, DUMP, DPIF)   \
    for (dpif_port_dump_start(DUMP, DPIF);          \
         (dpif_port_dump_next(DUMP, DPIF_PORT)      \
          ? true                                    \
          : (dpif_port_dump_done(DUMP), false));    \
        )

int dpif_port_poll(const struct dpif *, char **devnamep);
void dpif_port_poll_wait(const struct dpif *);

struct dpif_flow_stats {
    uint64_t n_packets;
    uint64_t n_bytes;
    long long int used;
    uint8_t tcp_flags;
};

void dpif_flow_stats_format(const struct dpif_flow_stats *, struct ds *);

enum dpif_flow_put_flags {
    DPIF_FP_CREATE = 1 << 0,    /* Allow creating a new flow. */
    DPIF_FP_MODIFY = 1 << 1,    /* Allow modifying an existing flow. */
    DPIF_FP_ZERO_STATS = 1 << 2 /* Zero the stats of an existing flow. */
};

int dpif_flow_flush(struct dpif *);
int dpif_flow_put(struct dpif *, enum dpif_flow_put_flags,
                  const struct nlattr *key, size_t key_len,
                  const struct nlattr *actions, size_t actions_len,
                  struct dpif_flow_stats *);
int dpif_flow_del(struct dpif *,
                  const struct nlattr *key, size_t key_len,
                  struct dpif_flow_stats *);
int dpif_flow_get(const struct dpif *,
                  const struct nlattr *key, size_t key_len,
                  struct ofpbuf **actionsp, struct dpif_flow_stats *);

struct dpif_flow_dump {
    const struct dpif *dpif;
    int error;
    void *state;
};
void dpif_flow_dump_start(struct dpif_flow_dump *, const struct dpif *);
bool dpif_flow_dump_next(struct dpif_flow_dump *,
                         const struct nlattr **key, size_t *key_len,
                         const struct nlattr **actions, size_t *actions_len,
                         const struct dpif_flow_stats **);
int dpif_flow_dump_done(struct dpif_flow_dump *);

int dpif_execute(struct dpif *,
                 const struct nlattr *key, size_t key_len,
                 const struct nlattr *actions, size_t actions_len,
                 const struct ofpbuf *);

enum dpif_upcall_type {
    DPIF_UC_MISS,               /* Miss in flow table. */
    DPIF_UC_ACTION,             /* ODP_ACTION_ATTR_USERSPACE action. */
    DPIF_UC_SAMPLE,             /* Packet sampling. */
    DPIF_N_UC_TYPES
};

const char *dpif_upcall_type_to_string(enum dpif_upcall_type);

/* A packet passed up from the datapath to userspace.
 *
 * If 'key' or 'actions' is nonnull, then it points into data owned by
 * 'packet', so their memory cannot be freed separately.  (This is hardly a
 * great way to do things but it works out OK for the dpif providers and
 * clients that exist so far.)
 */
struct dpif_upcall {
    /* All types. */
    enum dpif_upcall_type type;
    struct ofpbuf *packet;      /* Packet data. */
    struct nlattr *key;         /* Flow key. */
    size_t key_len;             /* Length of 'key' in bytes. */

    /* DPIF_UC_ACTION only. */
    uint64_t userdata;          /* Argument to ODP_ACTION_ATTR_USERSPACE. */

    /* DPIF_UC_SAMPLE only. */
    uint32_t sample_pool;       /* # of sampling candidate packets so far. */
    struct nlattr *actions;     /* Associated flow actions. */
    size_t actions_len;
};

int dpif_recv_get_mask(const struct dpif *, int *listen_mask);
int dpif_recv_set_mask(struct dpif *, int listen_mask);
int dpif_get_sflow_probability(const struct dpif *, uint32_t *probability);
int dpif_set_sflow_probability(struct dpif *, uint32_t probability);
int dpif_recv(struct dpif *, struct dpif_upcall *);
void dpif_recv_purge(struct dpif *);
void dpif_recv_wait(struct dpif *);

void dpif_get_netflow_ids(const struct dpif *,
                          uint8_t *engine_type, uint8_t *engine_id);

int dpif_queue_to_priority(const struct dpif *, uint32_t queue_id,
                           uint32_t *priority);

#ifdef  __cplusplus
}
#endif

#endif /* dpif.h */
