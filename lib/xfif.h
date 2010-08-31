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


#ifndef XFIF_H
#define XFIF_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "openflow/openflow.h"
#include "openvswitch/xflow.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct xfif;
struct ofpbuf;
struct svec;
struct xfif_class;

void xf_run(void);
void xf_wait(void);

int xf_register_provider(const struct xfif_class *);
int xf_unregister_provider(const char *type);
void xf_enumerate_types(struct svec *types);

int xf_enumerate_names(const char *type, struct svec *names);
void xf_parse_name(const char *datapath_name, char **name, char **type);

int xfif_open(const char *name, const char *type, struct xfif **);
int xfif_create(const char *name, const char *type, struct xfif **);
int xfif_create_and_open(const char *name, const char *type, struct xfif **);
void xfif_close(struct xfif *);

const char *xfif_name(const struct xfif *);
const char *xfif_base_name(const struct xfif *);
int xfif_get_all_names(const struct xfif *, struct svec *);

int xfif_delete(struct xfif *);

int xfif_get_xf_stats(const struct xfif *, struct xflow_stats *);
int xfif_get_drop_frags(const struct xfif *, bool *drop_frags);
int xfif_set_drop_frags(struct xfif *, bool drop_frags);

int xfif_port_add(struct xfif *, const char *devname, uint16_t flags,
                  uint16_t *port_no);
int xfif_port_del(struct xfif *, uint16_t port_no);
int xfif_port_query_by_number(const struct xfif *, uint16_t port_no,
                              struct xflow_port *);
int xfif_port_query_by_name(const struct xfif *, const char *devname,
                            struct xflow_port *);
int xfif_port_get_name(struct xfif *, uint16_t port_no,
                       char *name, size_t name_size);
int xfif_port_list(const struct xfif *, struct xflow_port **, size_t *n_ports);

int xfif_port_poll(const struct xfif *, char **devnamep);
void xfif_port_poll_wait(const struct xfif *);

int xfif_port_group_get(const struct xfif *, uint16_t group,
                        uint16_t **ports, size_t *n_ports);
int xfif_port_group_set(struct xfif *, uint16_t group,
                        const uint16_t ports[], size_t n_ports);

int xfif_flow_flush(struct xfif *);
int xfif_flow_put(struct xfif *, struct xflow_flow_put *);
int xfif_flow_del(struct xfif *, struct xflow_flow *);
int xfif_flow_get(const struct xfif *, struct xflow_flow *);
int xfif_flow_get_multiple(const struct xfif *, struct xflow_flow[], size_t n);
int xfif_flow_list(const struct xfif *, struct xflow_flow[], size_t n,
                   size_t *n_out);
int xfif_flow_list_all(const struct xfif *,
                       struct xflow_flow **flowsp, size_t *np);

int xfif_execute(struct xfif *, uint16_t in_port,
                 const union xflow_action[], size_t n_actions,
                 const struct ofpbuf *);

/* Minimum number of bytes of headroom for a packet returned by xfif_recv()
 * member function.  This headroom allows "struct xflow_msg" to be replaced by
 * "struct ofp_packet_in" without copying the buffer. */
#define XFIF_RECV_MSG_PADDING (sizeof(struct ofp_packet_in) \
                               - sizeof(struct xflow_msg))
BUILD_ASSERT_DECL(sizeof(struct ofp_packet_in) > sizeof(struct xflow_msg));
BUILD_ASSERT_DECL(XFIF_RECV_MSG_PADDING % 4 == 0);

int xfif_recv_get_mask(const struct xfif *, int *listen_mask);
int xfif_recv_set_mask(struct xfif *, int listen_mask);
int xfif_get_sflow_probability(const struct xfif *, uint32_t *probability);
int xfif_set_sflow_probability(struct xfif *, uint32_t probability);
int xfif_recv(struct xfif *, struct ofpbuf **);
int xfif_recv_purge(struct xfif *);
void xfif_recv_wait(struct xfif *);

void xfif_get_netflow_ids(const struct xfif *,
                          uint8_t *engine_type, uint8_t *engine_id);

int xfif_queue_to_priority(const struct xfif *, uint32_t queue_id,
                           uint32_t *priority);

#ifdef  __cplusplus
}
#endif

#endif /* xfif.h */
