/*
 * Copyright (c) 2009, 2010 Nicira Networks.
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "flow.h"
#include "netflow.h"
#include "tag.h"

struct odp_actions;
struct ofhooks;
struct ofproto;
struct svec;

struct ofexpired {
    flow_t flow;
    uint64_t packet_count;      /* Packets from subrules. */
    uint64_t byte_count;        /* Bytes from subrules. */
    long long int used;         /* Last-used time (0 if never used). */
};

int ofproto_create(const char *datapath, const struct ofhooks *, void *aux,
                   struct ofproto **ofprotop);
void ofproto_destroy(struct ofproto *);
int ofproto_run(struct ofproto *);
int ofproto_run1(struct ofproto *);
int ofproto_run2(struct ofproto *, bool revalidate_all);
void ofproto_wait(struct ofproto *);
bool ofproto_is_alive(const struct ofproto *);

/* Configuration. */
void ofproto_set_datapath_id(struct ofproto *, uint64_t datapath_id);
void ofproto_set_mgmt_id(struct ofproto *, uint64_t mgmt_id);
void ofproto_set_probe_interval(struct ofproto *, int probe_interval);
void ofproto_set_max_backoff(struct ofproto *, int max_backoff);
void ofproto_set_desc(struct ofproto *,
                      const char *manufacturer, const char *hardware,
                      const char *software, const char *serial,
                      const char *dp_desc);
int ofproto_set_in_band(struct ofproto *, bool in_band);
int ofproto_set_discovery(struct ofproto *, bool discovery,
                          const char *accept_controller_re,
                          bool update_resolv_conf);
int ofproto_set_controller(struct ofproto *, const char *controller);
int ofproto_set_listeners(struct ofproto *, const struct svec *listeners);
int ofproto_set_snoops(struct ofproto *, const struct svec *snoops);
int ofproto_set_netflow(struct ofproto *,
                        const struct netflow_options *nf_options);
void ofproto_set_failure(struct ofproto *, bool fail_open);
void ofproto_set_rate_limit(struct ofproto *, int rate_limit, int burst_limit);
int ofproto_set_stp(struct ofproto *, bool enable_stp);
int ofproto_set_remote_execution(struct ofproto *, const char *command_acl,
                                 const char *command_dir);

/* Configuration querying. */
uint64_t ofproto_get_datapath_id(const struct ofproto *);
uint64_t ofproto_get_mgmt_id(const struct ofproto *);
int ofproto_get_probe_interval(const struct ofproto *);
int ofproto_get_max_backoff(const struct ofproto *);
bool ofproto_get_in_band(const struct ofproto *);
bool ofproto_get_discovery(const struct ofproto *);
const char *ofproto_get_controller(const struct ofproto *);
void ofproto_get_listeners(const struct ofproto *, struct svec *);
void ofproto_get_snoops(const struct ofproto *, struct svec *);
void ofproto_get_all_flows(struct ofproto *p, struct ds *);

/* Functions for use by ofproto implementation modules, not by clients. */
int ofproto_send_packet(struct ofproto *, const flow_t *,
                        const union ofp_action *, size_t n_actions,
                        const struct ofpbuf *);
void ofproto_add_flow(struct ofproto *, const flow_t *, uint32_t wildcards,
                      unsigned int priority,
                      const union ofp_action *, size_t n_actions,
                      int idle_timeout);
void ofproto_delete_flow(struct ofproto *, const flow_t *, uint32_t wildcards,
                         unsigned int priority);
void ofproto_flush_flows(struct ofproto *);

/* Hooks for ovs-vswitchd. */
struct ofhooks {
    void (*port_changed_cb)(enum ofp_port_reason, const struct ofp_phy_port *,
                            void *aux);
    bool (*normal_cb)(const flow_t *, const struct ofpbuf *packet,
                      struct odp_actions *, tag_type *,
                      uint16_t *nf_output_iface, void *aux);
    void (*account_flow_cb)(const flow_t *, const union odp_action *,
                            size_t n_actions, unsigned long long int n_bytes,
                            void *aux);
    void (*account_checkpoint_cb)(void *aux);
};
void ofproto_revalidate(struct ofproto *, tag_type);
struct tag_set *ofproto_get_revalidate_set(struct ofproto *);

#endif /* ofproto.h */
