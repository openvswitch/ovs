/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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

/* Operations for the datapath running in the local kernel.  The interface can
 * generalize to multiple types of local datapaths, but the implementation only
 * supports the openflow kernel module. */

#include "openvswitch/datapath-protocol.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ofpbuf;

/* A datapath interface.  Opaque. */
struct dpif {
    char *name;
    unsigned int minor;
    int fd;
};

int dpif_open(const char *name, struct dpif *);
int dpif_create(const char *name, struct dpif *);
void dpif_close(struct dpif *);

const char *dpif_name(const struct dpif *);

int dpif_delete(struct dpif *);

int dpif_get_dp_stats(const struct dpif *, struct odp_stats *);
int dpif_get_drop_frags(const struct dpif *, bool *drop_frags);
int dpif_set_drop_frags(struct dpif *, bool drop_frags);

int dpif_get_listen_mask(const struct dpif *, int *listen_mask);
int dpif_set_listen_mask(struct dpif *, int listen_mask);
int dpif_purge(struct dpif *);

int dpif_port_add(struct dpif *, const char *devname, uint16_t port_no,
                  uint16_t flags);
int dpif_port_del(struct dpif *, uint16_t port_no);
int dpif_port_query_by_number(const struct dpif *, uint16_t port_no,
                              struct odp_port *);
int dpif_port_query_by_name(const struct dpif *, const char *devname,
                            struct odp_port *);
int dpif_port_get_name(struct dpif *, uint16_t port_no,
                       char *name, size_t name_size);
int dpif_port_list(const struct dpif *, struct odp_port **, size_t *n_ports);

int dpif_port_group_set(struct dpif *, uint16_t group,
                        const uint16_t ports[], size_t n_ports);
int dpif_port_group_get(const struct dpif *, uint16_t group,
                        uint16_t ports[], size_t n_ports, size_t *n_out);

int dpif_flow_flush(struct dpif *);
int dpif_flow_put(struct dpif *, struct odp_flow_put *);
int dpif_flow_del(struct dpif *, struct odp_flow *);
int dpif_flow_get(const struct dpif *, struct odp_flow *);
int dpif_flow_get_multiple(const struct dpif *, struct odp_flow[], size_t n);
int dpif_flow_list(const struct dpif *, struct odp_flow[], size_t n,
                   size_t *n_out);
int dpif_flow_list_all(const struct dpif *,
                       struct odp_flow **flowsp, size_t *np);

int dpif_execute(struct dpif *, uint16_t in_port,
                 const union odp_action[], size_t n_actions,
                 const struct ofpbuf *);

int dpif_recv(struct dpif *, struct ofpbuf **);
void dpif_recv_wait(struct dpif *);

void dpif_get_netflow_ids(const struct dpif *,
                          uint8_t *engine_type, uint8_t *engine_id);

struct dpifmon;

int dpifmon_create(const char *datapath_name, struct dpifmon **);
void dpifmon_destroy(struct dpifmon *);

int dpifmon_poll(struct dpifmon *, char **devnamep);

void dpifmon_run(struct dpifmon *);
void dpifmon_wait(struct dpifmon *);

#endif /* dpif.h */
