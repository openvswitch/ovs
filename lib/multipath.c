/*
 * Copyright (c) 2010 Nicira Networks.
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

#include <config.h>

#include "multipath.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "dynamic-string.h"
#include "nx-match.h"
#include "ofp-util.h"
#include "openflow/nicira-ext.h"
#include "packets.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(multipath);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* multipath_check(). */
int
multipath_check(const struct nx_action_multipath *mp)
{
    uint32_t dst = ntohl(mp->dst);
    int ofs = nxm_decode_ofs(mp->ofs_nbits);
    int n_bits = nxm_decode_n_bits(mp->ofs_nbits);

    if (mp->fields != htons(NX_MP_FIELDS_ETH_SRC)
        && mp->fields != htons(NX_MP_FIELDS_SYMMETRIC_L4)) {
        VLOG_WARN_RL(&rl, "unsupported fields %"PRIu16, ntohs(mp->fields));
    } else if (mp->algorithm != htons(NX_MP_ALG_MODULO_N)
               && mp->algorithm != htons(NX_MP_ALG_HASH_THRESHOLD)
               && mp->algorithm != htons(NX_MP_ALG_HRW)
               && mp->algorithm != htons(NX_MP_ALG_ITER_HASH)) {
        VLOG_WARN_RL(&rl, "unsupported algorithm %"PRIu16,
                     ntohs(mp->algorithm));
    } else if (!NXM_IS_NX_REG(dst) || NXM_NX_REG_IDX(dst) >= FLOW_N_REGS) {
        VLOG_WARN_RL(&rl, "unsupported destination field %#"PRIx32, dst);
    } else if (ofs + n_bits > nxm_field_bits(dst)) {
        VLOG_WARN_RL(&rl, "destination overflows output field");
    } else if (n_bits < 16 && ntohs(mp->max_link) > (1u << n_bits)) {
        VLOG_WARN_RL(&rl, "max_link overflows output field");
    } else {
        return 0;
    }

    return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
}

/* multipath_execute(). */

static uint32_t multipath_hash(const struct flow *, enum nx_mp_fields,
                               uint16_t basis);
static uint16_t multipath_algorithm(uint32_t hash, enum nx_mp_algorithm,
                                    unsigned int n_links, unsigned int arg);

void
multipath_execute(const struct nx_action_multipath *mp, struct flow *flow)
{
    /* Calculate value to store. */
    uint32_t hash = multipath_hash(flow, ntohs(mp->fields), ntohs(mp->basis));
    uint16_t link = multipath_algorithm(hash, ntohs(mp->algorithm),
                                        ntohs(mp->max_link) + 1,
                                        ntohl(mp->arg));

    /* Store it. */
    uint32_t *reg = &flow->regs[NXM_NX_REG_IDX(ntohl(mp->dst))];
    int ofs = nxm_decode_ofs(mp->ofs_nbits);
    int n_bits = nxm_decode_n_bits(mp->ofs_nbits);
    uint32_t mask = n_bits == 32 ? UINT32_MAX : (UINT32_C(1) << n_bits) - 1;
    *reg = (*reg & ~(mask << ofs)) | (link << ofs);
}

static uint32_t
hash_symmetric_l4(const struct flow *flow, uint16_t basis)
{
    struct {
        ovs_be32 ip_addr;
        ovs_be16 eth_type;
        ovs_be16 vlan_tci;
        ovs_be16 tp_addr;
        uint8_t eth_addr[ETH_ADDR_LEN];
        uint8_t ip_proto;
    } fields;

    int i;

    memset(&fields, 0, sizeof fields);
    for (i = 0; i < ETH_ADDR_LEN; i++) {
        fields.eth_addr[i] = flow->dl_src[i] ^ flow->dl_dst[i];
    }
    fields.vlan_tci = flow->vlan_tci & htons(VLAN_VID_MASK);
    fields.eth_type = flow->dl_type;
    if (fields.eth_type == htons(ETH_TYPE_IP)) {
        fields.ip_addr = flow->nw_src ^ flow->nw_dst;
        fields.ip_proto = flow->nw_proto;
        if (fields.ip_proto == IP_TYPE_TCP || fields.ip_proto == IP_TYPE_UDP) {
            fields.tp_addr = flow->tp_src ^ flow->tp_dst;
        } else {
            fields.tp_addr = htons(0);
        }
    } else {
        fields.ip_addr = htonl(0);
        fields.ip_proto = 0;
        fields.tp_addr = htons(0);
    }
    return hash_bytes(&fields, sizeof fields, basis);
}

static uint32_t
multipath_hash(const struct flow *flow, enum nx_mp_fields fields,
               uint16_t basis)
{
    switch (fields) {
    case NX_MP_FIELDS_ETH_SRC:
        return hash_bytes(flow->dl_src, sizeof flow->dl_src, basis);

    case NX_MP_FIELDS_SYMMETRIC_L4:
        return hash_symmetric_l4(flow, basis);
    }

    NOT_REACHED();
}

static uint16_t
algorithm_hrw(uint32_t hash, unsigned int n_links)
{
    uint32_t best_weight;
    uint16_t best_link;
    unsigned int link;

    best_link = 0;
    best_weight = hash_2words(hash, 0);
    for (link = 1; link < n_links; link++) {
        uint32_t weight = hash_2words(hash, link);
        if (weight > best_weight) {
            best_link = link;
            best_weight = weight;
        }
    }
    return best_link;
}

/* Works for 'x' in the range [1,65536], which is all we need.  */
static unsigned int
round_up_pow2(unsigned int x)
{
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    return x + 1;
}

static uint16_t
algorithm_iter_hash(uint32_t hash, unsigned int n_links, unsigned int modulo)
{
    uint16_t link;
    int i;

    if (modulo < n_links || modulo / 2 > n_links) {
        modulo = round_up_pow2(n_links);
    }

    i = 0;
    do {
        link = hash_2words(hash, i++) % modulo;
    } while (link >= n_links);

    return link;
}

static uint16_t
multipath_algorithm(uint32_t hash, enum nx_mp_algorithm algorithm,
                    unsigned int n_links, unsigned int arg)
{
    switch (algorithm) {
    case NX_MP_ALG_MODULO_N:
        return hash % n_links;

    case NX_MP_ALG_HASH_THRESHOLD:
        return hash / (UINT32_MAX / n_links);

    case NX_MP_ALG_HRW:
        return (n_links <= 64
                ? algorithm_hrw(hash, n_links)
                : algorithm_iter_hash(hash, n_links, 0));

    case NX_MP_ALG_ITER_HASH:
        return algorithm_iter_hash(hash, n_links, arg);
    }

    NOT_REACHED();
}

/* multipath_parse(). */

void
multipath_parse(struct nx_action_multipath *mp, const char *s_)
{
    char *s = xstrdup(s_);
    char *save_ptr = NULL;
    char *fields, *basis, *algorithm, *n_links, *arg, *dst;
    uint32_t header;
    int ofs, n_bits;

    fields = strtok_r(s, ", ", &save_ptr);
    basis = strtok_r(NULL, ", ", &save_ptr);
    algorithm = strtok_r(NULL, ", ", &save_ptr);
    n_links = strtok_r(NULL, ", ", &save_ptr);
    arg = strtok_r(NULL, ", ", &save_ptr);
    dst = strtok_r(NULL, ", ", &save_ptr);
    if (!dst) {
        ovs_fatal(0, "%s: not enough arguments to multipath action", s);
    }

    memset(mp, 0, sizeof *mp);
    mp->type = htons(OFPAT_VENDOR);
    mp->len = htons(sizeof *mp);
    mp->vendor = htonl(NX_VENDOR_ID);
    mp->subtype = htons(NXAST_MULTIPATH);
    if (!strcasecmp(fields, "eth_src")) {
        mp->fields = htons(NX_MP_FIELDS_ETH_SRC);
    } else if (!strcasecmp(fields, "symmetric_l4")) {
        mp->fields = htons(NX_MP_FIELDS_SYMMETRIC_L4);
    } else {
        ovs_fatal(0, "%s: unknown fields `%s'", s, fields);
    }
    mp->basis = htons(atoi(basis));
    if (!strcasecmp(algorithm, "modulo_n")) {
        mp->algorithm = htons(NX_MP_ALG_MODULO_N);
    } else if (!strcasecmp(algorithm, "hash_threshold")) {
        mp->algorithm = htons(NX_MP_ALG_HASH_THRESHOLD);
    } else if (!strcasecmp(algorithm, "hrw")) {
        mp->algorithm = htons(NX_MP_ALG_HRW);
    } else if (!strcasecmp(algorithm, "iter_hash")) {
        mp->algorithm = htons(NX_MP_ALG_ITER_HASH);
    } else {
        ovs_fatal(0, "%s: unknown algorithm `%s'", s, algorithm);
    }
    mp->max_link = htons(atoi(n_links) - 1);
    mp->arg = htonl(atoi(arg));

    nxm_parse_field_bits(dst, &header, &ofs, &n_bits);
    mp->ofs_nbits = nxm_encode_ofs_nbits(ofs, n_bits);
    mp->dst = htonl(header);

    free(s);
}

void
multipath_format(const struct nx_action_multipath *mp, struct ds *s)
{
    const char *fields, *algorithm;

    uint16_t mp_fields    = ntohs(mp->fields);
    uint16_t mp_algorithm = ntohs(mp->algorithm);

    switch ((enum nx_mp_fields) mp_fields) {
    case NX_MP_FIELDS_ETH_SRC:
        fields = "eth_src";
        break;
    case NX_MP_FIELDS_SYMMETRIC_L4:
        fields = "symmetric_l4";
        break;
    default:
        fields = "<unknown>";
    }

    switch ((enum nx_mp_algorithm) mp_algorithm) {
    case NX_MP_ALG_MODULO_N:
        algorithm = "modulo_n";
        break;
    case NX_MP_ALG_HASH_THRESHOLD:
        algorithm = "hash_threshold";
        break;
    case NX_MP_ALG_HRW:
        algorithm = "hrw";
        break;
    case NX_MP_ALG_ITER_HASH:
        algorithm = "iter_hash";
        break;
    default:
        algorithm = "<unknown>";
    }

    ds_put_format(s, "multipath(%s,%"PRIu16",%s,%d,%"PRIu16",",
                  fields, ntohs(mp->basis), algorithm, ntohs(mp->max_link) + 1,
                  ntohl(mp->arg));
    nxm_format_field_bits(s, ntohl(mp->dst), nxm_decode_ofs(mp->ofs_nbits),
                          nxm_decode_n_bits(mp->ofs_nbits));
    ds_put_char(s, ')');
}
