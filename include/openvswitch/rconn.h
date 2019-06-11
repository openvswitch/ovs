/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015, 2019 Nicira, Inc.
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

#ifndef RCONN_H
#define RCONN_H 1

#include <stdbool.h>
#include <stdint.h>
#include "openvswitch/types.h"

/* A wrapper around vconn that provides queuing and optionally reliability.
 *
 * An rconn maintains a message transmission queue of bounded length specified
 * by the caller.  The rconn does not guarantee reliable delivery of
 * queued messages: all queued messages are dropped when reconnection becomes
 * necessary.
 *
 * An rconn optionally provides reliable communication, in this sense: the
 * rconn will re-connect, with exponential backoff, when the underlying vconn
 * disconnects.
 *
 *
 * Thread-safety
 * =============
 *
 * Fully thread-safe.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct vconn;
struct rconn_packet_counter;

struct rconn *rconn_create(int inactivity_probe_interval,
                           int max_backoff, uint8_t dscp,
                           uint32_t allowed_versions);
void rconn_set_dscp(struct rconn *rc, uint8_t dscp);
uint32_t rconn_get_allowed_versions(const struct rconn *);
uint8_t rconn_get_dscp(const struct rconn *rc);
void rconn_set_max_backoff(struct rconn *, int max_backoff);
int rconn_get_max_backoff(const struct rconn *);
void rconn_set_probe_interval(struct rconn *, int inactivity_probe_interval);
int rconn_get_probe_interval(const struct rconn *);

void rconn_connect(struct rconn *, const char *target, const char *name);
void rconn_connect_unreliably(struct rconn *,
                              struct vconn *, const char *name);
void rconn_reconnect(struct rconn *);
void rconn_disconnect(struct rconn *);
void rconn_destroy(struct rconn *);

void rconn_run(struct rconn *);
void rconn_run_wait(struct rconn *);
struct ofpbuf *rconn_recv(struct rconn *);
void rconn_recv_wait(struct rconn *);
int rconn_send(struct rconn *, struct ofpbuf *, struct rconn_packet_counter *);
int rconn_send_with_limit(struct rconn *, struct ofpbuf *,
                          struct rconn_packet_counter *, int queue_limit);

void rconn_add_monitor(struct rconn *, struct vconn *);

const char *rconn_get_name(const struct rconn *);
void rconn_set_name(struct rconn *, const char *new_name);
const char *rconn_get_target(const struct rconn *);

bool rconn_is_reliable(const struct rconn *);
bool rconn_is_alive(const struct rconn *);
bool rconn_is_connected(const struct rconn *);
bool rconn_is_admitted(const struct rconn *);
int rconn_failure_duration(const struct rconn *);

int rconn_get_version(const struct rconn *);

const char *rconn_get_state(const struct rconn *);
long long int rconn_get_last_connection(const struct rconn *);
long long int rconn_get_last_disconnect(const struct rconn *);
unsigned int rconn_get_connection_seqno(const struct rconn *);
int rconn_get_last_error(const struct rconn *);
unsigned int rconn_count_txqlen(const struct rconn *);

struct rconn_packet_counter *rconn_packet_counter_create(void);
void rconn_packet_counter_destroy(struct rconn_packet_counter *);
void rconn_packet_counter_inc(struct rconn_packet_counter *, unsigned n_bytes);
void rconn_packet_counter_dec(struct rconn_packet_counter *, unsigned n_bytes);

unsigned int rconn_packet_counter_n_packets(
    const struct rconn_packet_counter *);
unsigned int rconn_packet_counter_n_bytes(const struct rconn_packet_counter *);

#ifdef __cplusplus
}
#endif

#endif /* rconn.h */
