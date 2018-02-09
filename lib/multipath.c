/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2016, 2017 Nicira, Inc.
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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include "colors.h"
#include "nx-match.h"
#include "openflow/nicira-ext.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-errors.h"
#include "packets.h"
#include "util.h"

/* Checks that 'mp' is valid on flow.  Returns 0 if it is valid, otherwise an
 * OFPERR_*. */
enum ofperr
multipath_check(const struct ofpact_multipath *mp,
                const struct match *match)
{
    return mf_check_dst(&mp->dst, match);
}

/* multipath_execute(). */

static uint16_t multipath_algorithm(uint32_t hash, enum nx_mp_algorithm,
                                    unsigned int n_links, unsigned int arg);

/* Executes 'mp' based on the current contents of 'flow', writing the results
 * back into 'flow'.  Sets fields in 'wc' that were used to calculate
 * the result. */
void
multipath_execute(const struct ofpact_multipath *mp, struct flow *flow,
                  struct flow_wildcards *wc)
{
    /* Calculate value to store. */
    uint32_t hash = flow_hash_fields(flow, mp->fields, mp->basis);
    uint16_t link = multipath_algorithm(hash, mp->algorithm,
                                        mp->max_link + 1, mp->arg);

    flow_mask_hash_fields(flow, wc, mp->fields);
    nxm_reg_load(&mp->dst, link, flow, wc);
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

    OVS_NOT_REACHED();
}

/* Parses 's_' as a set of arguments to the "multipath" action and initializes
 * 'mp' accordingly.  ovs-ofctl(8) describes the format parsed.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string.*/
static char * OVS_WARN_UNUSED_RESULT
multipath_parse__(struct ofpact_multipath *mp, const char *s_, char *s)
{
    char *save_ptr = NULL;
    char *fields, *basis, *algorithm, *n_links_str, *arg, *dst;
    char *error;
    int n_links;

    fields = strtok_r(s, ", ", &save_ptr);
    basis = strtok_r(NULL, ", ", &save_ptr);
    algorithm = strtok_r(NULL, ", ", &save_ptr);
    n_links_str = strtok_r(NULL, ", ", &save_ptr);
    arg = strtok_r(NULL, ", ", &save_ptr);
    dst = strtok_r(NULL, ", ", &save_ptr);
    if (!dst) {
        return xasprintf("%s: not enough arguments to multipath action", s_);
    }

    ofpact_init_MULTIPATH(mp);
    if (!strcasecmp(fields, "eth_src")) {
        mp->fields = NX_HASH_FIELDS_ETH_SRC;
    } else if (!strcasecmp(fields, "symmetric_l4")) {
        mp->fields = NX_HASH_FIELDS_SYMMETRIC_L4;
    } else if (!strcasecmp(fields, "symmetric_l3l4")) {
        mp->fields = NX_HASH_FIELDS_SYMMETRIC_L3L4;
    } else if (!strcasecmp(fields, "symmetric_l3l4+udp")) {
        mp->fields = NX_HASH_FIELDS_SYMMETRIC_L3L4_UDP;
    } else if (!strcasecmp(fields, "nw_src")) {
        mp->fields = NX_HASH_FIELDS_NW_SRC;
    } else if (!strcasecmp(fields, "nw_dst")) {
        mp->fields = NX_HASH_FIELDS_NW_DST;
    } else {
        return xasprintf("%s: unknown fields `%s'", s_, fields);
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
        return xasprintf("%s: unknown algorithm `%s'", s_, algorithm);
    }
    n_links = atoi(n_links_str);
    if (n_links < 1 || n_links > 65536) {
        return xasprintf("%s: n_links %d is not in valid range 1 to 65536",
                         s_, n_links);
    }
    mp->max_link = n_links - 1;
    mp->arg = atoi(arg);

    error = mf_parse_subfield(&mp->dst, dst);
    if (error) {
        return error;
    }
    if (!mf_nxm_header(mp->dst.field->id)) {
        return xasprintf("%s: experimenter OXM field '%s' not supported",
                         s, dst);
    }
    if (mp->dst.n_bits < 16 && n_links > (1u << mp->dst.n_bits)) {
        return xasprintf("%s: %d-bit destination field has %u possible "
                         "values, less than specified n_links %d",
                         s_, mp->dst.n_bits, 1u << mp->dst.n_bits, n_links);
    }

    return NULL;
}

/* Parses 's_' as a set of arguments to the "multipath" action and initializes
 * 'mp' accordingly.  ovs-ofctl(8) describes the format parsed.
 *
 * Returns NULL if successful, otherwise a malloc()'d string describing the
 * error.  The caller is responsible for freeing the returned string. */
char * OVS_WARN_UNUSED_RESULT
multipath_parse(struct ofpact_multipath *mp, const char *s_)
{
    char *s = xstrdup(s_);
    char *error = multipath_parse__(mp, s_, s);
    free(s);
    return error;
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

    ds_put_format(s, "%smultipath(%s%s,%"PRIu16",%s,%d,%"PRIu32",",
                  colors.paren, colors.end, fields, mp->basis, algorithm,
                  mp->max_link + 1, mp->arg);
    mf_format_subfield(&mp->dst, s);
    ds_put_format(s, "%s)%s", colors.paren, colors.end);
}
