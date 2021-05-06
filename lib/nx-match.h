/*
 * Copyright (c) 2010-2017, 2020 Nicira, Inc.
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
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/types.h"

struct ds;
struct match;
struct ofpact_reg_move;
struct ofpact_reg_load;
struct ofpact_stack;
struct ofpbuf;
struct nx_action_reg_load;
struct nx_action_reg_move;
struct vl_mff_map;


/* Nicira Extended Match (NXM) flexible flow match helper functions.
 *
 * See include/openflow/nicira-ext.h for NXM specification.
 */

char * mf_parse_field(const struct mf_field **field, const char *s)
    OVS_WARN_UNUSED_RESULT;
void mf_format_subfield(const struct mf_subfield *, struct ds *);
char *mf_parse_subfield__(struct mf_subfield *sf, const char **s)
    OVS_WARN_UNUSED_RESULT;
char *mf_parse_subfield(struct mf_subfield *, const char *s)
    OVS_WARN_UNUSED_RESULT;

/* Decoding matches. */
enum ofperr nx_pull_match(struct ofpbuf *, unsigned int match_len,
                          struct match *, ovs_be64 *cookie,
                          ovs_be64 *cookie_mask, bool pipeline_fields_only,
                          const struct tun_table *, const struct vl_mff_map *);
enum ofperr nx_pull_match_loose(struct ofpbuf *, unsigned int match_len,
                                struct match *, ovs_be64 *cookie,
                                ovs_be64 *cookie_mask,
                                bool pipeline_fields_only,
                                const struct tun_table *);
enum ofperr oxm_pull_match(struct ofpbuf *, bool pipeline_fields_only,
                           const struct tun_table *, const struct vl_mff_map *,
                           struct match *);
enum ofperr oxm_pull_match_loose(struct ofpbuf *, bool pipeline_fields_only,
                                 const struct tun_table *, struct match *);
enum ofperr oxm_decode_match(const void *, size_t, bool,
                             const struct tun_table *,
                             const struct vl_mff_map *, struct match *);
enum ofperr oxm_pull_field_array(const void *, size_t fields_len,
                                 struct field_array *);

/* Encoding matches. */
int nx_put_match(struct ofpbuf *, const struct match *,
                 ovs_be64 cookie, ovs_be64 cookie_mask);
int oxm_put_match(struct ofpbuf *, const struct match *, enum ofp_version);
void oxm_put_raw(struct ofpbuf *, const struct match *, enum ofp_version);
void oxm_format_field_array(struct ds *, const struct field_array *);
int oxm_put_field_array(struct ofpbuf *, const struct field_array *,
                        enum ofp_version version);

/* Decoding and encoding OXM/NXM headers (just a field ID) or entries (a field
 * ID followed by a value and possibly a mask). */
enum ofperr nx_pull_entry(struct ofpbuf *, const struct vl_mff_map *,
                          const struct mf_field **, union mf_value *value,
                          union mf_value *mask, bool is_action);
enum ofperr nx_pull_header(struct ofpbuf *, const struct vl_mff_map *,
                           const struct mf_field **, bool *masked);
void nxm_put_entry_raw(struct ofpbuf *, enum mf_field_id field,
                       enum ofp_version version, const void *value,
                       const void *mask, size_t n_bytes);
void nx_put_entry(struct ofpbuf *, const struct mf_field *, enum ofp_version,
                  const union mf_value *value, const union mf_value *mask);
void nx_put_header(struct ofpbuf *, enum mf_field_id, enum ofp_version,
                   bool masked);
void nx_put_mff_header(struct ofpbuf *, const struct mf_field *,
                       enum ofp_version, bool);

/* NXM and OXM protocol headers values.
 *
 * These are often alternatives to nx_pull_entry/header() and
 * nx_put_entry/header() for decoding and encoding OXM/NXM.  In those cases,
 * the nx_*() functions should be preferred because they can support the 64-bit
 * "experimenter" OXM format (even though it is not yet implemented). */
uint32_t mf_nxm_header(enum mf_field_id);
uint32_t nxm_header_from_mff(const struct mf_field *);
const struct mf_field *mf_from_nxm_header(uint32_t nxm_header,
                                          const struct vl_mff_map *);

char *nx_match_to_string(const uint8_t *, unsigned int match_len);
char *oxm_match_to_string(const struct ofpbuf *, unsigned int match_len);
int nx_match_from_string(const char *, struct ofpbuf *);
int oxm_match_from_string(const char *, struct ofpbuf *);

void nx_format_field_name(enum mf_field_id, enum ofp_version, struct ds *);

char *nxm_parse_reg_move(struct ofpact_reg_move *, const char *)
    OVS_WARN_UNUSED_RESULT;

void nxm_format_reg_move(const struct ofpact_reg_move *, struct ds *);

enum ofperr nxm_reg_move_check(const struct ofpact_reg_move *,
                               const struct match *);

void nxm_reg_load(const struct mf_subfield *, uint64_t src_data,
                  struct flow *, struct flow_wildcards *);

char *nxm_parse_stack_action(struct ofpact_stack *, const char *)
    OVS_WARN_UNUSED_RESULT;

void nxm_format_stack_push(const struct ofpact_stack *, struct ds *);
void nxm_format_stack_pop(const struct ofpact_stack *, struct ds *);

enum ofperr nxm_stack_push_check(const struct ofpact_stack *,
                                 const  struct match *);
enum ofperr nxm_stack_pop_check(const struct ofpact_stack *,
                                const struct match *);
void nx_stack_push(struct ofpbuf *stack, const void *v, uint8_t bytes);
void nx_stack_push_bottom(struct ofpbuf *stack, const void *v, uint8_t bytes);
void *nx_stack_pop(struct ofpbuf *stack, uint8_t *bytes);

void nxm_execute_stack_push(const struct ofpact_stack *,
                            const struct flow *, struct flow_wildcards *,
                            struct ofpbuf *);
bool nxm_execute_stack_pop(const struct ofpact_stack *,
                           struct flow *, struct flow_wildcards *,
                           struct ofpbuf *);

ovs_be64 oxm_bitmap_from_mf_bitmap(const struct mf_bitmap *, enum ofp_version);
struct mf_bitmap oxm_bitmap_to_mf_bitmap(ovs_be64 oxm_bitmap,
                                         enum ofp_version);
struct mf_bitmap oxm_writable_fields(void);
struct mf_bitmap oxm_matchable_fields(void);
struct mf_bitmap oxm_maskable_fields(void);

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
