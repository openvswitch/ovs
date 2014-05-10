/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

#ifndef NX_MATCH_H
#define NX_MATCH_H 1

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "compiler.h"
#include "flow.h"
#include "ofp-errors.h"
#include "openvswitch/types.h"

struct ds;
struct match;
struct mf_field;
struct mf_subfield;
struct ofpact_reg_move;
struct ofpact_reg_load;
struct ofpact_stack;
struct ofpbuf;
struct nx_action_reg_load;
struct nx_action_reg_move;


/* Nicira Extended Match (NXM) flexible flow match helper functions.
 *
 * See include/openflow/nicira-ext.h for NXM specification.
 */

enum ofperr nx_pull_match(struct ofpbuf *, unsigned int match_len,
                          struct match *,
                          ovs_be64 *cookie, ovs_be64 *cookie_mask);
enum ofperr nx_pull_match_loose(struct ofpbuf *, unsigned int match_len,
                                struct match *, ovs_be64 *cookie,
                                ovs_be64 *cookie_mask);
enum ofperr oxm_pull_match(struct ofpbuf *, struct match *);
enum ofperr oxm_pull_match_loose(struct ofpbuf *, struct match *);
int nx_put_match(struct ofpbuf *, const struct match *,
                 ovs_be64 cookie, ovs_be64 cookie_mask);
int oxm_put_match(struct ofpbuf *, const struct match *, enum ofp_version);

char *nx_match_to_string(const uint8_t *, unsigned int match_len);
char *oxm_match_to_string(const struct ofpbuf *, unsigned int match_len);
int nx_match_from_string(const char *, struct ofpbuf *);
int oxm_match_from_string(const char *, struct ofpbuf *);

char *nxm_parse_reg_move(struct ofpact_reg_move *, const char *)
    WARN_UNUSED_RESULT;
char *nxm_parse_reg_load(struct ofpact_reg_load *, const char *)
    WARN_UNUSED_RESULT;

void nxm_format_reg_move(const struct ofpact_reg_move *, struct ds *);
void nxm_format_reg_load(const struct ofpact_reg_load *, struct ds *);

enum ofperr nxm_reg_move_from_openflow(const struct nx_action_reg_move *,
                                       struct ofpbuf *ofpacts);
enum ofperr nxm_reg_load_from_openflow(const struct nx_action_reg_load *,
                                       struct ofpbuf *ofpacts);

enum ofperr nxm_reg_move_check(const struct ofpact_reg_move *,
                               const struct flow *);
enum ofperr nxm_reg_load_check(const struct ofpact_reg_load *,
                               const struct flow *);

void nxm_reg_move_to_nxast(const struct ofpact_reg_move *,
                           struct ofpbuf *openflow);
void nxm_reg_load_to_nxast(const struct ofpact_reg_load *,
                           struct ofpbuf *openflow);

void nxm_execute_reg_move(const struct ofpact_reg_move *, struct flow *,
                          struct flow_wildcards *);
void nxm_execute_reg_load(const struct ofpact_reg_load *, struct flow *,
                          struct flow_wildcards *);
void nxm_reg_load(const struct mf_subfield *, uint64_t src_data,
                  struct flow *, struct flow_wildcards *);

char *nxm_parse_stack_action(struct ofpact_stack *, const char *)
    WARN_UNUSED_RESULT;

void nxm_format_stack_push(const struct ofpact_stack *, struct ds *);
void nxm_format_stack_pop(const struct ofpact_stack *, struct ds *);

enum ofperr nxm_stack_push_from_openflow(const struct nx_action_stack *,
                                       struct ofpbuf *ofpacts);
enum ofperr nxm_stack_pop_from_openflow(const struct nx_action_stack *,
                                       struct ofpbuf *ofpacts);
enum ofperr nxm_stack_push_check(const struct ofpact_stack *,
                                 const  struct flow *);
enum ofperr nxm_stack_pop_check(const struct ofpact_stack *,
                               const struct flow *);

void nxm_stack_push_to_nxast(const struct ofpact_stack *,
                           struct ofpbuf *openflow);
void nxm_stack_pop_to_nxast(const struct ofpact_stack *,
                           struct ofpbuf *openflow);

void nxm_execute_stack_push(const struct ofpact_stack *,
                            const struct flow *, struct flow_wildcards *,
                            struct ofpbuf *);
void nxm_execute_stack_pop(const struct ofpact_stack *,
                            struct flow *, struct flow_wildcards *,
                            struct ofpbuf *);

int nxm_field_bytes(uint32_t header);
int nxm_field_bits(uint32_t header);

/* Dealing with the 'ofs_nbits' members in several Nicira extensions. */

static inline ovs_be16
nxm_encode_ofs_nbits(int ofs, int n_bits)
{
    return htons((ofs << 6) | (n_bits - 1));
}

static inline int
nxm_decode_ofs(ovs_be16 ofs_nbits)
{
    return ntohs(ofs_nbits) >> 6;
}

static inline int
nxm_decode_n_bits(ovs_be16 ofs_nbits)
{
    return (ntohs(ofs_nbits) & 0x3f) + 1;
}

/* This is my guess at the length of a "typical" nx_match, for use in
 * predicting space requirements. */
#define NXM_TYPICAL_LEN 64

#endif /* nx-match.h */
