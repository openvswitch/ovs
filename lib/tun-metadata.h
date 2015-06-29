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

#include "dynamic-string.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"

struct match;
struct mf_field;
union mf_value;
struct ofputil_geneve_table_mod;
struct ofputil_geneve_table_reply;
struct tun_table;
struct geneve_opt;

#define TUN_METADATA_NUM_OPTS 64
#define TUN_METADATA_TOT_OPT_SIZE 256

/* Tunnel option data, plus metadata to aid in their interpretation.
 *
 * 'opt_map' is indexed by type, that is, by the <i> in TUN_METADATA<i>, so
 * that e.g. TUN_METADATA5 is present if 'opt_map & (1ULL << 5)' is nonzero.
 * The actual data for TUN_METADATA5, if present, might be anywhere in 'opts'
 * (not necessarily even contiguous), and finding it requires referring to
 * 'tab'. */
struct tun_metadata {
    uint8_t opts[TUN_METADATA_TOT_OPT_SIZE]; /* Values from tunnel TLVs. */
    uint64_t opt_map;                        /* 1-bit for each present TLV. */
    struct tun_table *tab;      /* Types & lengths for 'opts' and 'opt_map'. */
    uint8_t pad[sizeof(uint64_t) - sizeof(struct tun_table *)]; /* Make 8 bytes */
};
BUILD_ASSERT_DECL(sizeof(((struct tun_metadata *)0)->opt_map) * 8 >=
                  TUN_METADATA_NUM_OPTS);

/* The location of an option can be stored either as a single offset/len
 * pair (hopefully) or if the address space is fragmented then it is a
 * linked list of these blocks. */
struct tun_metadata_loc_chain {
    struct tun_metadata_loc_chain *next;
    uint8_t offset;       /* In bytes, from start of 'opts', multiple of 4.  */
    uint8_t len;          /* In bytes, multiple of 4. */
};

struct tun_metadata_loc {
    int len;                    /* Sum of 'len' over elements in chain. */
    struct tun_metadata_loc_chain c;
};

/* Allocation of options inside struct match.  This is important if we don't
 * have access to a global allocation table - either because there isn't one
 * (ovs-ofctl) or if we need to keep the allocation outside of packet
 * processing context (Packet-In). These structures never have dynamically
 * allocated memory because the address space is never fragmented. */
struct tun_metadata_allocation {
    struct tun_metadata_loc loc[TUN_METADATA_NUM_OPTS];
    uint8_t alloc_offset;       /* Byte offset into 'opts', multiple of 4.  */
    bool valid;                 /* Set to true after any allocation occurs. */
};

void tun_metadata_init(void);

enum ofperr tun_metadata_table_mod(struct ofputil_geneve_table_mod *);
void tun_metadata_table_request(struct ofputil_geneve_table_reply *);

void tun_metadata_read(const struct tun_metadata *,
                       const struct mf_field *, union mf_value *);
void tun_metadata_write(struct tun_metadata *,
                        const struct mf_field *, const union mf_value *);
void tun_metadata_set_match(const struct mf_field *,
                            const union mf_value *value,
                            const union mf_value *mask, struct match *);
void tun_metadata_get_fmd(const struct tun_metadata *,
                          struct match *flow_metadata);

int tun_metadata_from_geneve_nlattr(const struct nlattr *attr,
                                    const struct nlattr *flow_attrs,
                                    size_t flow_attr_len,
                                    const struct tun_metadata *flow_metadata,
                                    struct tun_metadata *metadata);
int tun_metadata_from_geneve_header(const struct geneve_opt *, int opt_len,
                                    struct tun_metadata *metadata);

void tun_metadata_to_geneve_nlattr_flow(const struct tun_metadata *flow,
                                        struct ofpbuf *);
void tun_metadata_to_geneve_nlattr_mask(const struct ofpbuf *key,
                                        const struct tun_metadata *mask,
                                        const struct tun_metadata *flow,
                                        struct ofpbuf *);
int tun_metadata_to_geneve_header(const struct tun_metadata *flow,
                                  struct geneve_opt *, bool *crit_opt);

void tun_metadata_to_nx_match(struct ofpbuf *b, enum ofp_version oxm,
                              const struct match *);
void tun_metadata_match_format(struct ds *, const struct match *);

#endif /* tun-metadata.h */
