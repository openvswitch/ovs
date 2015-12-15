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
#include "geneve.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"

struct flow_tnl;
struct match;
struct mf_field;
union mf_value;
struct ofputil_tlv_table_mod;
struct ofputil_tlv_table_reply;
struct tun_table;

#define TUN_METADATA_NUM_OPTS 64
#define TUN_METADATA_TOT_OPT_SIZE 256

/* Tunnel option data, plus metadata to aid in their interpretation.
 *
 * The option data exists in two forms and is interpreted differently depending
 * on whether FLOW_TNL_F_UDPIF is set in struct flow_tnl flags:
 *
 * When FLOW_TNL_F_UDPIF is set, the tunnel metadata is in "userspace datapath
 * format". This is typically used for fast-path packet processing to avoid
 * the cost of translating options and in situations where we need to maintain
 * tunnel metadata exactly as it came in. In this case 'opts.gnv' is raw
 * packet data from the tunnel header and 'present.len' indicates the length
 * of the data stored there. In these situations, 'tab' is NULL.
 *
 * In all other cases, we are doing flow-based processing (such as during
 * upcalls). FLOW_TNL_F_UDPIF is not set and options are reordered into
 * pre-allocated locations. 'present.map' is indexed by type, that is, by the
 * <i> in TUN_METADATA<i>, so that e.g. TUN_METADATA5 is present if
 * 'present.map & (1ULL << 5)' is nonzero. The actual data for TUN_METADATA5,
 * if present, might be anywhere in 'opts.u8' (not necessarily even contiguous),
 * and finding it requires referring to 'tab', if set, or the global metadata
 * table. */
struct tun_metadata {
    union { /* Valid members of 'opts'. When 'opts' is sorted into known types,
             * 'map' is used. When 'opts' is raw packet data, 'len' is used. */
        uint64_t map;                      /* 1-bit for each present TLV. */
        uint8_t len;                       /* Length of data in 'opts'. */
    } present;
    struct tun_table *tab;      /* Types & lengths for 'opts' and 'opt_map'. */

#if UINTPTR_MAX == UINT32_MAX
    uint8_t pad[4];             /* Pad to 64-bit boundary. */
#endif

    union {
        uint8_t u8[TUN_METADATA_TOT_OPT_SIZE]; /* Values from tunnel TLVs. */
        struct geneve_opt gnv[TLV_TOT_OPT_SIZE / sizeof(struct geneve_opt)];
    } opts;
};
BUILD_ASSERT_DECL(offsetof(struct tun_metadata, opts) % 8 == 0);
BUILD_ASSERT_DECL(sizeof(((struct tun_metadata *)0)->present.map) * 8 >=
                  TUN_METADATA_NUM_OPTS);

/* The location of an option can be stored either as a single offset/len
 * pair (hopefully) or if the address space is fragmented then it is a
 * linked list of these blocks. */
struct tun_metadata_loc_chain {
    struct tun_metadata_loc_chain *next;
    int offset;       /* In bytes, from start of 'opts', multiple of 4.  */
    int len;          /* In bytes, multiple of 4. */
};

struct tun_metadata_loc {
    int len;                    /* Sum of 'len' over elements in chain. */
    struct tun_metadata_loc_chain c;
};

/* Bookkeeping information to keep track of an option that was allocated
 * inside struct match. */
struct tun_metadata_match_entry {
    struct tun_metadata_loc loc; /* Allocated position. */
    bool masked; /* Source value had a mask. Otherwise we can't tell if the
                  * entire field was exact matched or only the portion that
                  * is the same size as the value. */
};

/* Allocation of options inside struct match.  This is important if we don't
 * have access to a global allocation table - either because there isn't one
 * (ovs-ofctl) or if we need to keep the allocation outside of packet
 * processing context (Packet-In). These structures never have dynamically
 * allocated memory because the address space is never fragmented. */
struct tun_metadata_allocation {
    struct tun_metadata_match_entry entry[TUN_METADATA_NUM_OPTS];
    int alloc_offset;           /* Byte offset into 'opts', multiple of 4.  */
    bool valid;                 /* Set to true after any allocation occurs. */
};

void tun_metadata_init(void);

enum ofperr tun_metadata_table_mod(struct ofputil_tlv_table_mod *);
void tun_metadata_table_request(struct ofputil_tlv_table_reply *);

void tun_metadata_read(const struct flow_tnl *,
                       const struct mf_field *, union mf_value *);
void tun_metadata_write(struct flow_tnl *,
                        const struct mf_field *, const union mf_value *);
void tun_metadata_set_match(const struct mf_field *,
                            const union mf_value *value,
                            const union mf_value *mask, struct match *,
                            char **err_str);
void tun_metadata_get_fmd(const struct flow_tnl *, struct match *flow_metadata);

int tun_metadata_from_geneve_nlattr(const struct nlattr *attr,
                                    const struct nlattr *flow_attrs,
                                    size_t flow_attr_len,
                                    const struct flow_tnl *flow_tun,
                                    bool udpif, struct flow_tnl *tun);
void tun_metadata_to_geneve_nlattr(const struct flow_tnl *tun,
                                   const struct flow_tnl *flow,
                                   const struct ofpbuf *key,
                                   struct ofpbuf *);

int tun_metadata_from_geneve_udpif(const struct flow_tnl *flow,
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
