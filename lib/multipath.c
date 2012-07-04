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
#include "nx-match.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "openflow/nicira-ext.h"
#include "packets.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(multipath);

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Converts 'nam' into 'mp'.  Returns 0 if successful, otherwise an
 * OFPERR_*. */
enum ofperr
multipath_from_openflow(const struct nx_action_multipath *nam,
                        struct ofpact_multipath *mp)
{
    uint32_t n_links = ntohs(nam->max_link) + 1;
    size_t min_n_bits = log_2_ceil(n_links);

    ofpact_init_MULTIPATH(mp);
    mp->fields = ntohs(nam->fields);
    mp->basis = ntohs(nam->basis);
    mp->algorithm = ntohs(nam->algorithm);
    mp->max_link = ntohs(nam->max_link);
    mp->arg = ntohl(nam->arg);
    mp->dst.field = mf_from_nxm_header(ntohl(nam->dst));
    mp->dst.ofs = nxm_decode_ofs(nam->ofs_nbits);
    mp->dst.n_bits = nxm_decode_n_bits(nam->ofs_nbits);

    if (!flow_hash_fields_valid(mp->fields)) {
        VLOG_WARN_RL(&rl, "unsupported fields %d", (int) mp->fields);
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    } else if (mp->algorithm != NX_MP_ALG_MODULO_N
               && mp->algorithm != NX_MP_ALG_HASH_THRESHOLD
               && mp->algorithm != NX_MP_ALG_HRW
               && mp->algorithm != NX_MP_ALG_ITER_HASH) {
        VLOG_WARN_RL(&rl, "unsupported algorithm %d", (int) mp->algorithm);
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    } else if (mp->dst.n_bits < min_n_bits) {
        VLOG_WARN_RL(&rl, "multipath action requires at least %zu bits for "
                     "%"PRIu32" links", min_n_bits, n_links);
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return multipath_check(mp, NULL);
}

/* Checks that 'mp' is valid on flow.  Returns 0 if it is valid, otherwise an
 * OFPERR_*. */
enum ofperr
multipath_check(const struct ofpact_multipath *mp,
                const struct flow *flow)
{
    return mf_check_dst(&mp->dst, flow);
}

/* Converts 'mp' into an OpenFlow NXAST_MULTIPATH action, which it appends to
 * 'openflow'. */
void
multipath_to_nxast(const struct ofpact_multipath *mp, struct ofpbuf *openflow)
{
    struct nx_action_multipath *nam = ofputil_put_NXAST_MULTIPATH(openflow);

    nam->fields = htons(mp->fields);
    nam->basis = htons(mp->basis);
    nam->algorithm = htons(mp->algorithm);
    nam->max_link = htons(mp->max_link);
    nam->arg = htonl(mp->arg);
    nam->ofs_nbits = nxm_encode_ofs_nbits(mp->dst.ofs, mp->dst.n_bits);
    nam->dst = htonl(mp->dst.field->nxm_header);
}

/* multipath_execute(). */

static uint16_t multipath_algorithm(uint32_t hash, enum nx_mp_algorithm,
                                    unsigned int n_links, unsigned int arg);

/* Executes 'mp' based on the current contents of 'flow', writing the results
 * back into 'flow'. */
void
multipath_execute(const struct ofpact_multipath *mp, struct flow *flow)
{
    /* Calculate value to store. */
    uint32_t hash = flow_hash_fields(flow, mp->fields, mp->basis);
    uint16_t link = multipath_algorithm(hash, mp->algorithm,
                                        mp->max_link + 1, mp->arg);

    nxm_reg_load(&mp->dst, link, flow);
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

/* Parses 's_' as a set of arguments to the "multipath" action and initializes
 * 'mp' accordingly.  ovs-ofctl(8) describes the format parsed.
 *
 * Prints an error on stderr and aborts the program if 's_' syntax is
 * invalid. */
void
multipath_parse(struct ofpact_multipath *mp, const char *s_)
{
    char *s = xstrdup(s_);
    char *save_ptr = NULL;
    char *fields, *basis, *algorithm, *n_links_str, *arg, *dst;
    int n_links;

    fields = strtok_r(s, ", ", &save_ptr);
    basis = strtok_r(NULL, ", ", &save_ptr);
    algorithm = strtok_r(NULL, ", ", &save_ptr);
    n_links_str = strtok_r(NULL, ", ", &save_ptr);
    arg = strtok_r(NULL, ", ", &save_ptr);
    dst = strtok_r(NULL, ", ", &save_ptr);
    if (!dst) {
        ovs_fatal(0, "%s: not enough arguments to multipath action", s_);
    }

    ofpact_init_MULTIPATH(mp);
    if (!strcasecmp(fields, "eth_src")) {
        mp->fields = NX_HASH_FIELDS_ETH_SRC;
    } else if (!strcasecmp(fields, "symmetric_l4")) {
        mp->fields = NX_HASH_FIELDS_SYMMETRIC_L4;
    } else {
        ovs_fatal(0, "%s: unknown fields `%s'", s_, fields);
    }
    mp->basis = atoi(basis);
    if (!strcasecmp(algorithm, "modulo_n")) {
        mp->algorithm = NX_MP_ALG_MODULO_N;
    } else if (!strcasecmp(algorithm, "hash_threshold")) {
        mp->algorithm = NX_MP_ALG_HASH_THRESHOLD;
    } else if (!strcasecmp(algorithm, "hrw")) {
        mp->algorithm = NX_MP_ALG_HRW;
    } else if (!strcasecmp(algorithm, "iter_hash")) {
        mp->algorithm = NX_MP_ALG_ITER_HASH;
    } else {
        ovs_fatal(0, "%s: unknown algorithm `%s'", s_, algorithm);
    }
    n_links = atoi(n_links_str);
    if (n_links < 1 || n_links > 65536) {
        ovs_fatal(0, "%s: n_links %d is not in valid range 1 to 65536",
                  s_, n_links);
    }
    mp->max_link = n_links - 1;
    mp->arg = atoi(arg);

    mf_parse_subfield(&mp->dst, dst);
    if (mp->dst.n_bits < 16 && n_links > (1u << mp->dst.n_bits)) {
        ovs_fatal(0, "%s: %d-bit destination field has %u possible values, "
                  "less than specified n_links %d",
                  s_, mp->dst.n_bits, 1u << mp->dst.n_bits, n_links);
    }

    free(s);
}

/* Appends a description of 'mp' to 's', in the format that ovs-ofctl(8)
 * describes. */
void
multipath_format(const struct ofpact_multipath *mp, struct ds *s)
{
    const char *fields, *algorithm;

    fields = flow_hash_fields_to_str(mp->fields);

    switch (mp->algorithm) {
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
                  fields, mp->basis, algorithm, mp->max_link + 1,
                  mp->arg);
    mf_format_subfield(&mp->dst, s);
    ds_put_char(s, ')');
}
