/*
 * Copyright (c) 2009 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef OFPROTO_H
#define OFPROTO_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "flow.h"
#include "tag.h"

struct odp_actions;
struct ofhooks;
struct ofproto;
struct svec;

struct ofexpired {
    flow_t flow;
    uint64_t packet_count;      /* Packets from *expired* subrules. */
    uint64_t byte_count;        /* Bytes from *expired* subrules. */
    long long int used;         /* Last-used time (0 if never used). */
    long long int created;      /* Creation time. */
    uint8_t tcp_flags;          /* Bitwise-OR of all TCP flags seen. */
    uint8_t ip_tos;             /* Last-seen IP type-of-service. */
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
                      const char *software, const char *serial);
int ofproto_set_in_band(struct ofproto *, bool in_band);
int ofproto_set_discovery(struct ofproto *, bool discovery,
                          const char *accept_controller_re,
                          bool update_resolv_conf);
int ofproto_set_controller(struct ofproto *, const char *controller);
int ofproto_set_listeners(struct ofproto *, const struct svec *listeners);
int ofproto_set_snoops(struct ofproto *, const struct svec *snoops);
int ofproto_set_netflow(struct ofproto *, const struct svec *collectors,
        uint8_t engine_type, uint8_t engine_id, bool add_id_to_iface);
void ofproto_set_failure(struct ofproto *, bool fail_open);
void ofproto_set_rate_limit(struct ofproto *, int rate_limit, int burst_limit);
int ofproto_set_stp(struct ofproto *, bool enable_stp);
int ofproto_set_remote_execution(struct ofproto *, const char *command_acl,
                                 const char *command_dir);

/* Configuration querying. */
uint64_t ofproto_get_datapath_id(const struct ofproto *);
int ofproto_get_probe_interval(const struct ofproto *);
int ofproto_get_max_backoff(const struct ofproto *);
bool ofproto_get_in_band(const struct ofproto *);
bool ofproto_get_discovery(const struct ofproto *);
const char *ofproto_get_controller(const struct ofproto *);
void ofproto_get_listeners(const struct ofproto *, struct svec *);
void ofproto_get_snoops(const struct ofproto *, struct svec *);

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
                      struct odp_actions *, tag_type *, void *aux);
    void (*account_flow_cb)(const flow_t *, const union odp_action *,
                            size_t n_actions, unsigned long long int n_bytes,
                            void *aux);
    void (*account_checkpoint_cb)(void *aux);
};
void ofproto_revalidate(struct ofproto *, tag_type);
struct tag_set *ofproto_get_revalidate_set(struct ofproto *);

#endif /* ofproto.h */
