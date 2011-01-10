/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct dpif;
struct netdev;
struct nlattr;
struct ofpbuf;
struct svec;
struct dpif_class;

void dp_run(void);
void dp_wait(void);

int dp_register_provider(const struct dpif_class *);
int dp_unregister_provider(const char *type);
void dp_enumerate_types(struct svec *types);

int dp_enumerate_names(const char *type, struct svec *names);
void dp_parse_name(const char *datapath_name, char **name, char **type);

int dpif_open(const char *name, const char *type, struct dpif **);
int dpif_create(const char *name, const char *type, struct dpif **);
int dpif_create_and_open(const char *name, const char *type, struct dpif **);
void dpif_close(struct dpif *);

const char *dpif_name(const struct dpif *);
const char *dpif_base_name(const struct dpif *);
int dpif_get_all_names(const struct dpif *, struct svec *);

int dpif_delete(struct dpif *);

int dpif_get_dp_stats(const struct dpif *, struct odp_stats *);
int dpif_get_drop_frags(const struct dpif *, bool *drop_frags);
int dpif_set_drop_frags(struct dpif *, bool drop_frags);

int dpif_port_add(struct dpif *, struct netdev *, uint16_t *port_nop);
int dpif_port_del(struct dpif *, uint16_t port_no);
int dpif_port_query_by_number(const struct dpif *, uint16_t port_no,
                              struct odp_port *);
int dpif_port_query_by_name(const struct dpif *, const char *devname,
                            struct odp_port *);
int dpif_port_get_name(struct dpif *, uint16_t port_no,
                       char *name, size_t name_size);

struct dpif_port_dump {
    const struct dpif *dpif;
    int error;
    void *state;
};
void dpif_port_dump_start(struct dpif_port_dump *, const struct dpif *);
bool dpif_port_dump_next(struct dpif_port_dump *, struct odp_port *);
int dpif_port_dump_done(struct dpif_port_dump *);

/* Iterates through each ODP_PORT in DPIF, using DUMP as state.
 *
 * Arguments all have pointer type.
 *
 * If you break out of the loop, then you need to free the dump structure by
 * hand using dpif_port_dump_done(). */
#define DPIF_PORT_FOR_EACH(ODP_PORT, DUMP, DPIF)    \
    for (dpif_port_dump_start(DUMP, DPIF);          \
         (dpif_port_dump_next(DUMP, ODP_PORT)       \
          ? true                                    \
          : (dpif_port_dump_done(DUMP), false));    \
        )

int dpif_port_poll(const struct dpif *, char **devnamep);
void dpif_port_poll_wait(const struct dpif *);

int dpif_flow_flush(struct dpif *);
int dpif_flow_put(struct dpif *, struct odp_flow_put *);
int dpif_flow_del(struct dpif *, struct odp_flow *);
int dpif_flow_get(const struct dpif *, struct odp_flow *);
int dpif_flow_get_multiple(const struct dpif *, struct odp_flow[], size_t n);

struct dpif_flow_dump {
    const struct dpif *dpif;
    int error;
    void *state;
};
void dpif_flow_dump_start(struct dpif_flow_dump *, const struct dpif *);
bool dpif_flow_dump_next(struct dpif_flow_dump *, struct odp_flow *);
int dpif_flow_dump_done(struct dpif_flow_dump *);

int dpif_execute(struct dpif *, const struct nlattr *actions,
                 size_t actions_len, const struct ofpbuf *);

/* A packet passed up from the datapath to userspace.
 *
 * If 'key' or 'actions' is nonnull, then it points into data owned by
 * 'packet', so their memory cannot be freed separately.  (This is hardly a
 * great way to do things but it works out OK for the dpif providers and
 * clients that exist so far.)
 */
struct dpif_upcall {
    uint32_t type;              /* One of _ODPL_*_NR. */

    /* All types. */
    struct ofpbuf *packet;      /* Packet data. */
    struct nlattr *key;         /* Flow key. */
    size_t key_len;             /* Length of 'key' in bytes. */

    /* _ODPL_ACTION_NR only. */
    uint64_t userdata;          /* Argument to ODPAT_CONTROLLER. */

    /* _ODPL_SFLOW_NR only. */
    uint32_t sample_pool;       /* # of sampling candidate packets so far. */
    struct nlattr *actions;     /* Associated flow actions. */
    size_t actions_len;
};

int dpif_recv_get_mask(const struct dpif *, int *listen_mask);
int dpif_recv_set_mask(struct dpif *, int listen_mask);
int dpif_get_sflow_probability(const struct dpif *, uint32_t *probability);
int dpif_set_sflow_probability(struct dpif *, uint32_t probability);
int dpif_recv(struct dpif *, struct dpif_upcall *);
int dpif_recv_purge(struct dpif *);
void dpif_recv_wait(struct dpif *);

void dpif_get_netflow_ids(const struct dpif *,
                          uint8_t *engine_type, uint8_t *engine_id);

int dpif_queue_to_priority(const struct dpif *, uint32_t queue_id,
                           uint32_t *priority);

#ifdef  __cplusplus
}
#endif

#endif /* dpif.h */
