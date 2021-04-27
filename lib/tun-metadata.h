/*
 * Copyright (c) 2015 Nicira, Inc.
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

#ifndef TUN_METADATA_H
#define TUN_METADATA_H 1

#include <stdint.h>

#include "openvswitch/dynamic-string.h"
#include "netlink.h"
#include "openvswitch/ofpbuf.h"
#include "openflow/openflow.h"
#include "openvswitch/tun-metadata.h"

struct flow_tnl;
struct match;
struct mf_field;
union mf_value;
struct ofputil_tlv_table_mod;
struct ofputil_tlv_table_reply;
struct tun_table;

struct tun_table *tun_metadata_alloc(const struct tun_table *old_map);
void tun_metadata_free(struct tun_table *);
void tun_metadata_postpone_free(struct tun_table *);

enum ofperr tun_metadata_table_mod(struct ofputil_tlv_table_mod *,
                                   const struct tun_table *old_tab,
                                   struct tun_table **new_tab);
void tun_metadata_table_request(const struct tun_table *,
                                struct ofputil_tlv_table_reply *);

void tun_metadata_read(const struct flow_tnl *,
                       const struct mf_field *, union mf_value *);
void tun_metadata_write(struct flow_tnl *,
                        const struct mf_field *, const union mf_value *);
void tun_metadata_delete(struct flow_tnl *, const struct mf_field *);
void tun_metadata_set_match(const struct mf_field *,
                            const union mf_value *value,
                            const union mf_value *mask, struct match *,
                            char **err_str);
void tun_metadata_get_fmd(const struct flow_tnl *, struct match *flow_metadata);

void tun_metadata_from_geneve_nlattr(const struct nlattr *attr, bool is_mask,
                                     struct flow_tnl *tun);
void tun_metadata_to_geneve_nlattr(const struct flow_tnl *tun,
                                   const struct flow_tnl *flow,
                                   const struct ofpbuf *key,
                                   struct ofpbuf *);

int tun_metadata_from_geneve_udpif(const struct tun_table *,
                                   const struct flow_tnl *flow,
                                   const struct flow_tnl *src,
                                   struct flow_tnl *dst);
void tun_metadata_to_geneve_udpif_mask(const struct flow_tnl *flow_src,
                                       const struct flow_tnl *mask_src,
                                       const struct geneve_opt *flow_src_opt,
                                       int opts_len, struct geneve_opt *dst);

int tun_metadata_to_geneve_header(const struct flow_tnl *flow,
                                  struct geneve_opt *, bool *crit_opt);

void tun_metadata_to_nx_match(struct ofpbuf *b, enum ofp_version oxm,
                              const struct match *);
void tun_metadata_match_format(struct ds *, const struct match *);

#endif /* tun-metadata.h */
