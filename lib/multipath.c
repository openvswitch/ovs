/*
 * Copyright (c) 2010, 2011, 2012 Nicira, Inc.
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
#include "meta-flow.h"
#include "nx-match.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "openflow/nicira-ext.h"
#include "packets.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(multipath);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* multipath_check(). */
enum ofperr
multipath_check(const struct nx_action_multipath *mp, const struct flow *flow)
{
    uint32_t n_links = ntohs(mp->max_link) + 1;
    size_t min_n_bits = log_2_ceil(n_links);
    struct mf_subfield dst;
    enum ofperr error;

    nxm_decode(&dst, mp->dst, mp->ofs_nbits);
    error = mf_check_dst(&dst, flow);
    if (error) {
        return error;
    }

    if (!flow_hash_fields_valid(ntohs(mp->fields))) {
        VLOG_WARN_RL(&rl, "unsupported fields %"PRIu16, ntohs(mp->fields));
    } else if (mp->algorithm != htons(NX_MP_ALG_MODULO_N)
               && mp->algorithm != htons(NX_MP_ALG_HASH_THRESHOLD)
               && mp->algorithm != htons(NX_MP_ALG_HRW)
               && mp->algorithm != htons(NX_MP_ALG_ITER_HASH)) {
        VLOG_WARN_RL(&rl, "unsupported algorithm %"PRIu16,
                     ntohs(mp->algorithm));
    } else if (dst.n_bits < min_n_bits) {
        VLOG_WARN_RL(&rl, "multipath action requires at least %zu bits for "
                     "%"PRIu32" links", min_n_bits, n_links);
    } else {
        return 0;
    }

    return OFPERR_OFPBAC_BAD_ARGUMENT;
}

/* multipath_execute(). */

static uint16_t multipath_algorithm(uint32_t hash, enum nx_mp_algorithm,
                                    unsigned int n_links, unsigned int arg);

void
multipath_execute(const struct nx_action_multipath *mp, struct flow *flow)
{
    /* Calculate value to store. */
    uint32_t hash = flow_hash_fields(flow, ntohs(mp->fields),
                                     ntohs(mp->basis));
    uint16_t link = multipath_algorithm(hash, ntohs(mp->algorithm),
                                        ntohs(mp->max_link) + 1,
                                        ntohl(mp->arg));
    struct mf_subfield dst;

    nxm_decode(&dst, mp->dst, mp->ofs_nbits);
    mf_set_subfield_value(&dst, link, flow);
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
        if (n_links == 1) {
            return 0;
        }
        return hash / (UINT32_MAX / n_links + 1);

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
    char *fields, *basis, *algorithm, *n_links_str, *arg, *dst_s;
    struct mf_subfield dst;
    int n_links;

    fields = strtok_r(s, ", ", &save_ptr);
    basis = strtok_r(NULL, ", ", &save_ptr);
    algorithm = strtok_r(NULL, ", ", &save_ptr);
    n_links_str = strtok_r(NULL, ", ", &save_ptr);
    arg = strtok_r(NULL, ", ", &save_ptr);
    dst_s = strtok_r(NULL, ", ", &save_ptr);
    if (!dst_s) {
        ovs_fatal(0, "%s: not enough arguments to multipath action", s_);
    }

    ofputil_init_NXAST_MULTIPATH(mp);
    if (!strcasecmp(fields, "eth_src")) {
        mp->fields = htons(NX_HASH_FIELDS_ETH_SRC);
    } else if (!strcasecmp(fields, "symmetric_l4")) {
        mp->fields = htons(NX_HASH_FIELDS_SYMMETRIC_L4);
    } else {
        ovs_fatal(0, "%s: unknown fields `%s'", s_, fields);
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
        ovs_fatal(0, "%s: unknown algorithm `%s'", s_, algorithm);
    }
    n_links = atoi(n_links_str);
    if (n_links < 1 || n_links > 65536) {
        ovs_fatal(0, "%s: n_links %d is not in valid range 1 to 65536",
                  s_, n_links);
    }
    mp->max_link = htons(n_links - 1);
    mp->arg = htonl(atoi(arg));

    mf_parse_subfield(&dst, dst_s);
    if (dst.n_bits < 16 && n_links > (1u << dst.n_bits)) {
        ovs_fatal(0, "%s: %d-bit destination field has %u possible values, "
                  "less than specified n_links %d",
                  s_, dst.n_bits, 1u << dst.n_bits, n_links);
    }
    mp->ofs_nbits = nxm_encode_ofs_nbits(dst.ofs, dst.n_bits);
    mp->dst = htonl(dst.field->nxm_header);

    free(s);
}

void
multipath_format(const struct nx_action_multipath *mp, struct ds *s)
{
    const char *fields, *algorithm;

    uint16_t mp_fields    = ntohs(mp->fields);
    uint16_t mp_algorithm = ntohs(mp->algorithm);

    struct mf_subfield dst;

    fields = flow_hash_fields_to_str(mp_fields);

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
    nxm_decode(&dst, mp->dst, mp->ofs_nbits);
    mf_format_subfield(&dst, s);
    ds_put_char(s, ')');
}
