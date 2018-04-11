/*
 * Copyright (c) 2009, 2010, 2011, 2013, 2015 Nicira, Inc.
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

#ifndef STREAM_H
#define STREAM_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "openvswitch/types.h"
#include "socket-util.h"
#include "util.h"

struct pstream;
struct stream;
struct vlog_module;

void stream_usage(const char *name, bool active, bool passive, bool bootstrap);

/* Bidirectional byte streams. */
int stream_verify_name(const char *name);
int stream_open(const char *name, struct stream **, uint8_t dscp);
int stream_open_block(int error, struct stream **);
void stream_close(struct stream *);
const char *stream_get_name(const struct stream *);
int stream_connect(struct stream *);
int stream_recv(struct stream *, void *buffer, size_t n);
int stream_send(struct stream *, const void *buffer, size_t n);

void stream_run(struct stream *);
void stream_run_wait(struct stream *);

enum stream_wait_type {
    STREAM_CONNECT,
    STREAM_RECV,
    STREAM_SEND
};
void stream_wait(struct stream *, enum stream_wait_type);
void stream_connect_wait(struct stream *);
void stream_recv_wait(struct stream *);
void stream_send_wait(struct stream *);
void stream_set_peer_id(struct stream *, const char *);
const char *stream_get_peer_id(const struct stream *);

/* Passive streams: listeners for incoming stream connections. */
int pstream_verify_name(const char *name);
int pstream_open(const char *name, struct pstream **, uint8_t dscp);
const char *pstream_get_name(const struct pstream *);
void pstream_close(struct pstream *);
int pstream_accept(struct pstream *, struct stream **);
int pstream_accept_block(struct pstream *, struct stream **);
void pstream_wait(struct pstream *);

ovs_be16 pstream_get_bound_port(const struct pstream *);

/* Convenience functions. */

int stream_open_with_default_port(const char *name,
                                  uint16_t default_port,
                                  struct stream **,
                                  uint8_t dscp);
int pstream_open_with_default_port(const char *name,
                                   uint16_t default_port,
                                   struct pstream **,
                                   uint8_t dscp);
bool stream_parse_target_with_default_port(const char *target,
                                           int default_port,
                                           struct sockaddr_storage *ss);
int stream_or_pstream_needs_probes(const char *name);

/* Error reporting. */

enum stream_content_type {
    STREAM_UNKNOWN,
    STREAM_OPENFLOW,
    STREAM_SSL,
    STREAM_JSONRPC
};

void stream_report_content(const void *, ssize_t, enum stream_content_type,
                           struct vlog_module *, const char *stream_name);

#endif /* stream.h */
