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

#ifndef OFP_UTIL_H
#define OFP_UTIL_H 1

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "flow.h"

struct ofpbuf;
struct ofp_action_header;

/* OpenFlow protocol utility functions. */
void *make_openflow(size_t openflow_len, uint8_t type, struct ofpbuf **);
void *make_openflow_xid(size_t openflow_len, uint8_t type,
                        uint32_t xid, struct ofpbuf **);
void *put_openflow(size_t openflow_len, uint8_t type, struct ofpbuf *);
void *put_openflow_xid(size_t openflow_len, uint8_t type, uint32_t xid,
                       struct ofpbuf *);
void update_openflow_length(struct ofpbuf *);
struct ofpbuf *make_flow_mod(uint16_t command, const flow_t *,
                             size_t actions_len);
struct ofpbuf *make_add_flow(const flow_t *, uint32_t buffer_id,
                             uint16_t max_idle, size_t actions_len);
struct ofpbuf *make_del_flow(const flow_t *);
struct ofpbuf *make_add_simple_flow(const flow_t *,
                                    uint32_t buffer_id, uint16_t out_port,
                                    uint16_t max_idle);
struct ofpbuf *make_packet_in(uint32_t buffer_id, uint16_t in_port,
                              uint8_t reason,
                              const struct ofpbuf *payload, int max_send_len);
struct ofpbuf *make_packet_out(const struct ofpbuf *packet, uint32_t buffer_id,
                               uint16_t in_port,
                               const struct ofp_action_header *,
                               size_t n_actions);
struct ofpbuf *make_buffered_packet_out(uint32_t buffer_id,
                                        uint16_t in_port, uint16_t out_port);
struct ofpbuf *make_unbuffered_packet_out(const struct ofpbuf *packet,
                                          uint16_t in_port, uint16_t out_port);
struct ofpbuf *make_echo_request(void);
struct ofpbuf *make_echo_reply(const struct ofp_header *rq);
int check_ofp_message(const struct ofp_header *, uint8_t type, size_t size);
int check_ofp_message_array(const struct ofp_header *, uint8_t type,
                            size_t size, size_t array_elt_size,
                            size_t *n_array_elts);
int check_ofp_packet_out(const struct ofp_header *, struct ofpbuf *data,
                         int *n_actions, int max_ports);

struct flow_stats_iterator {
    const uint8_t *pos, *end;
};
const struct ofp_flow_stats *flow_stats_first(struct flow_stats_iterator *,
                                              const struct ofp_stats_reply *);
const struct ofp_flow_stats *flow_stats_next(struct flow_stats_iterator *);

struct actions_iterator {
    const union ofp_action *pos, *end;
};
const union ofp_action *actions_first(struct actions_iterator *,
                                      const union ofp_action *,
                                      size_t n_actions);
const union ofp_action *actions_next(struct actions_iterator *);
int validate_actions(const union ofp_action *, size_t n_actions,
                     int max_ports);
bool action_outputs_to_port(const union ofp_action *, uint16_t port);

void normalize_match(struct ofp_match *);
char *ofp_match_to_literal_string(const struct ofp_match *match);

static inline int
ofp_mkerr(uint16_t type, uint16_t code)
{
    assert(type > 0 && type <= 0x7fff);
    return (type << 16) | code;
}

#endif /* ofp-util.h */
