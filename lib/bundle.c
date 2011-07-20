/* Copyright (c) 2011 Nicira Networks.
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

#include "bundle.h"

#include <arpa/inet.h>
#include <inttypes.h>

#include "dynamic-string.h"
#include "multipath.h"
#include "nx-match.h"
#include "ofpbuf.h"
#include "ofp-util.h"
#include "openflow/nicira-ext.h"
#include "vlog.h"

#define BUNDLE_MAX_SLAVES 2048

VLOG_DEFINE_THIS_MODULE(bundle);

static uint16_t
execute_ab(const struct nx_action_bundle *nab,
           bool (*slave_enabled)(uint16_t ofp_port, void *aux), void *aux)
{
    size_t i;

    for (i = 0; i < ntohs(nab->n_slaves); i++) {
        uint16_t slave = bundle_get_slave(nab, i);

        if (slave_enabled(slave, aux)) {
            return slave;
        }
    }

    return OFPP_NONE;
}

static uint16_t
execute_hrw(const struct nx_action_bundle *nab, const struct flow *flow,
            bool (*slave_enabled)(uint16_t ofp_port, void *aux), void *aux)
{
    uint32_t flow_hash, best_hash;
    int best, i;

    flow_hash = flow_hash_fields(flow, ntohs(nab->fields), ntohs(nab->basis));
    best = -1;
    best_hash = 0;

    for (i = 0; i < ntohs(nab->n_slaves); i++) {
        if (slave_enabled(bundle_get_slave(nab, i), aux)) {
            uint32_t hash = hash_2words(i, flow_hash);

            if (best < 0 || hash > best_hash) {
                best_hash = hash;
                best = i;
            }
        }
    }

    return best >= 0 ? bundle_get_slave(nab, best) : OFPP_NONE;
}

/* Executes 'nab' on 'flow'.  Uses 'slave_enabled' to determine if the slave
 * designated by 'ofp_port' is up.  Returns the chosen slave, or OFPP_NONE if
 * none of the slaves are acceptable. */
uint16_t
bundle_execute(const struct nx_action_bundle *nab, const struct flow *flow,
               bool (*slave_enabled)(uint16_t ofp_port, void *aux), void *aux)
{
    switch (ntohs(nab->algorithm)) {
    case NX_BD_ALG_HRW: return execute_hrw(nab, flow, slave_enabled, aux);
    case NX_BD_ALG_ACTIVE_BACKUP: return execute_ab(nab, slave_enabled, aux);
    default: NOT_REACHED();
    }
}

void
bundle_execute_load(const struct nx_action_bundle *nab, struct flow *flow,
                    bool (*slave_enabled)(uint16_t ofp_port, void *aux),
                    void *aux)
{
    nxm_reg_load(nab->dst, nab->ofs_nbits,
                 bundle_execute(nab, flow, slave_enabled, aux), flow);
}

/* Checks that 'nab' specifies a bundle action which is supported by this
 * bundle module.  Uses the 'max_ports' parameter to validate each port using
 * ofputil_check_output_port().  Returns 0 if 'nab' is supported, otherwise an
 * OpenFlow error code (as returned by ofp_mkerr()). */
int
bundle_check(const struct nx_action_bundle *nab, int max_ports,
             const struct flow *flow)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    uint16_t n_slaves, fields, algorithm, subtype;
    uint32_t slave_type;
    size_t slaves_size, i;
    int error;

    subtype = ntohs(nab->subtype);
    n_slaves = ntohs(nab->n_slaves);
    fields = ntohs(nab->fields);
    algorithm = ntohs(nab->algorithm);
    slave_type = ntohl(nab->slave_type);
    slaves_size = ntohs(nab->len) - sizeof *nab;

    error = ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
    if (!flow_hash_fields_valid(fields)) {
        VLOG_WARN_RL(&rl, "unsupported fields %"PRIu16, fields);
    } else if (n_slaves > BUNDLE_MAX_SLAVES) {
        VLOG_WARN_RL(&rl, "too may slaves");
    } else if (algorithm != NX_BD_ALG_HRW
               && algorithm != NX_BD_ALG_ACTIVE_BACKUP) {
        VLOG_WARN_RL(&rl, "unsupported algorithm %"PRIu16, algorithm);
    } else if (slave_type != NXM_OF_IN_PORT) {
        VLOG_WARN_RL(&rl, "unsupported slave type %"PRIu16, slave_type);
    } else {
        error = 0;
    }

    for (i = 0; i < sizeof(nab->zero); i++) {
        if (nab->zero[i]) {
            VLOG_WARN_RL(&rl, "reserved field is nonzero");
            error = ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
        }
    }

    if (subtype == NXAST_BUNDLE && (nab->ofs_nbits || nab->dst)) {
        VLOG_WARN_RL(&rl, "bundle action has nonzero reserved fields");
        error = ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
    }

    if (subtype == NXAST_BUNDLE_LOAD) {
        error = nxm_dst_check(nab->dst, nab->ofs_nbits, 16, flow) || error;
    }

    if (slaves_size < n_slaves * sizeof(ovs_be16)) {
        VLOG_WARN_RL(&rl, "Nicira action %"PRIu16" only has %zu bytes "
                     "allocated for slaves.  %zu bytes are required for "
                     "%"PRIu16" slaves.", subtype, slaves_size,
                     n_slaves * sizeof(ovs_be16), n_slaves);
        error = ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    for (i = 0; i < n_slaves; i++) {
        uint16_t ofp_port = bundle_get_slave(nab, i);
        int ofputil_error = ofputil_check_output_port(ofp_port, max_ports);

        if (ofputil_error) {
            VLOG_WARN_RL(&rl, "invalid slave %"PRIu16, ofp_port);
            error = ofputil_error;
        }

        /* Controller slaves are unsupported due to the lack of a max_len
         * argument. This may or may not change in the future.  There doesn't
         * seem to be a real-world use-case for supporting it. */
        if (ofp_port == OFPP_CONTROLLER) {
            VLOG_WARN_RL(&rl, "unsupported controller slave");
            error = ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
        }
    }

    return error;
}

/* Helper for bundle_parse and bundle_parse_load. */
static void
bundle_parse__(struct ofpbuf *b, const char *s, char **save_ptr,
               const char *fields, const char *basis, const char *algorithm,
               const char *slave_type, const char *dst,
               const char *slave_delim)
{
    struct nx_action_bundle *nab;
    uint16_t n_slaves;

    if (!slave_delim) {
        ovs_fatal(0, "%s: not enough arguments to bundle action", s);
    }

    if (strcasecmp(slave_delim, "slaves")) {
        ovs_fatal(0, "%s: missing slave delimiter, expected `slaves' got `%s'",
                   s, slave_delim);
    }

    b->l2 = ofpbuf_put_zeros(b, sizeof *nab);

    n_slaves = 0;
    for (;;) {
        ovs_be16 slave_be;
        char *slave;

        slave = strtok_r(NULL, ", ", save_ptr);
        if (!slave || n_slaves >= BUNDLE_MAX_SLAVES) {
            break;
        }

        slave_be = htons(atoi(slave));
        ofpbuf_put(b, &slave_be, sizeof slave_be);

        n_slaves++;
    }

    /* Slaves array must be multiple of 8 bytes long. */
    if (b->size % 8) {
        ofpbuf_put_zeros(b, 8 - (b->size % 8));
    }

    nab = b->l2;
    nab->type = htons(OFPAT_VENDOR);
    nab->len = htons(b->size - ((char *) b->l2 - (char *) b->data));
    nab->vendor = htonl(NX_VENDOR_ID);
    nab->subtype = htons(dst ? NXAST_BUNDLE_LOAD: NXAST_BUNDLE);
    nab->n_slaves = htons(n_slaves);
    nab->basis = htons(atoi(basis));

    if (!strcasecmp(fields, "eth_src")) {
        nab->fields = htons(NX_HASH_FIELDS_ETH_SRC);
    } else if (!strcasecmp(fields, "symmetric_l4")) {
        nab->fields = htons(NX_HASH_FIELDS_SYMMETRIC_L4);
    } else {
        ovs_fatal(0, "%s: unknown fields `%s'", s, fields);
    }

    if (!strcasecmp(algorithm, "active_backup")) {
        nab->algorithm = htons(NX_BD_ALG_ACTIVE_BACKUP);
    } else if (!strcasecmp(algorithm, "hrw")) {
        nab->algorithm = htons(NX_BD_ALG_HRW);
    } else {
        ovs_fatal(0, "%s: unknown algorithm `%s'", s, algorithm);
    }

    if (!strcasecmp(slave_type, "ofport")) {
        nab->slave_type = htonl(NXM_OF_IN_PORT);
    } else {
        ovs_fatal(0, "%s: unknown slave_type `%s'", s, slave_type);
    }

    if (dst) {
        uint32_t reg;
        int ofs, n_bits;

        nxm_parse_field_bits(dst, &reg, &ofs, &n_bits);

        nab->dst = htonl(reg);
        nab->ofs_nbits = nxm_encode_ofs_nbits(ofs, n_bits);
    }

    b->l2 = NULL;
}

/* Converts a bundle action string contained in 's' to an nx_action_bundle and
 * stores it in 'b'.  Sets 'b''s l2 pointer to NULL. */
void
bundle_parse(struct ofpbuf *b, const char *s)
{
    char *fields, *basis, *algorithm, *slave_type, *slave_delim;
    char *tokstr, *save_ptr;

    save_ptr = NULL;
    tokstr = xstrdup(s);
    fields = strtok_r(tokstr, ", ", &save_ptr);
    basis = strtok_r(NULL, ", ", &save_ptr);
    algorithm = strtok_r(NULL, ", ", &save_ptr);
    slave_type = strtok_r(NULL, ", ", &save_ptr);
    slave_delim = strtok_r(NULL, ": ", &save_ptr);

    bundle_parse__(b, s, &save_ptr, fields, basis, algorithm, slave_type, NULL,
                   slave_delim);
    free(tokstr);
}

/* Converts a bundle_load action string contained in 's' to an nx_action_bundle
 * and stores it in 'b'.  Sets 'b''s l2 pointer to NULL. */
void
bundle_parse_load(struct ofpbuf *b, const char *s)
{
    char *fields, *basis, *algorithm, *slave_type, *dst, *slave_delim;
    char *tokstr, *save_ptr;

    save_ptr = NULL;
    tokstr = xstrdup(s);
    fields = strtok_r(tokstr, ", ", &save_ptr);
    basis = strtok_r(NULL, ", ", &save_ptr);
    algorithm = strtok_r(NULL, ", ", &save_ptr);
    slave_type = strtok_r(NULL, ", ", &save_ptr);
    dst = strtok_r(NULL, ", ", &save_ptr);
    slave_delim = strtok_r(NULL, ": ", &save_ptr);

    bundle_parse__(b, s, &save_ptr, fields, basis, algorithm, slave_type, dst,
                   slave_delim);

    free(tokstr);
}

/* Appends a human-readable representation of 'nab' to 's'. */
void
bundle_format(const struct nx_action_bundle *nab, struct ds *s)
{
    const char *action, *fields, *algorithm, *slave_type;
    size_t i;

    fields = flow_hash_fields_to_str(ntohs(nab->fields));

    switch (ntohs(nab->algorithm)) {
    case NX_BD_ALG_HRW:
        algorithm = "hrw";
        break;
    case NX_BD_ALG_ACTIVE_BACKUP:
        algorithm = "active_backup";
        break;
    default:
        algorithm = "<unknown>";
    }

    switch (ntohl(nab->slave_type)) {
    case NXM_OF_IN_PORT:
        slave_type = "ofport";
        break;
    default:
        slave_type = "<unknown>";
    }

    switch (ntohs(nab->subtype)) {
    case NXAST_BUNDLE:
        action = "bundle";
        break;
    case NXAST_BUNDLE_LOAD:
        action = "bundle_load";
        break;
    default:
        NOT_REACHED();
    }

    ds_put_format(s, "%s(%s,%"PRIu16",%s,%s,", action, fields,
                  ntohs(nab->basis), algorithm, slave_type);

    if (nab->subtype == htons(NXAST_BUNDLE_LOAD)) {
        nxm_format_field_bits(s, ntohl(nab->dst),
                              nxm_decode_ofs(nab->ofs_nbits),
                              nxm_decode_n_bits(nab->ofs_nbits));
        ds_put_cstr(s, ",");
    }

    ds_put_cstr(s, "slaves:");
    for (i = 0; i < ntohs(nab->n_slaves); i++) {
        if (i) {
            ds_put_cstr(s, ",");
        }

        ds_put_format(s, "%"PRIu16, bundle_get_slave(nab, i));
    }

    ds_put_cstr(s, ")");
}
