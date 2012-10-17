/* Copyright (c) 2011, 2012 Nicira, Inc.
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
#include "meta-flow.h"
#include "nx-match.h"
#include "ofpbuf.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "openflow/nicira-ext.h"
#include "vlog.h"

#define BUNDLE_MAX_SLAVES 2048

VLOG_DEFINE_THIS_MODULE(bundle);

static uint16_t
execute_ab(const struct ofpact_bundle *bundle,
           bool (*slave_enabled)(uint16_t ofp_port, void *aux), void *aux)
{
    size_t i;

    for (i = 0; i < bundle->n_slaves; i++) {
        uint16_t slave = bundle->slaves[i];
        if (slave_enabled(slave, aux)) {
            return slave;
        }
    }

    return OFPP_NONE;
}

static uint16_t
execute_hrw(const struct ofpact_bundle *bundle, const struct flow *flow,
            bool (*slave_enabled)(uint16_t ofp_port, void *aux), void *aux)
{
    uint32_t flow_hash, best_hash;
    int best, i;

    flow_hash = flow_hash_fields(flow, bundle->fields, bundle->basis);
    best = -1;
    best_hash = 0;

    for (i = 0; i < bundle->n_slaves; i++) {
        if (slave_enabled(bundle->slaves[i], aux)) {
            uint32_t hash = hash_2words(i, flow_hash);

            if (best < 0 || hash > best_hash) {
                best_hash = hash;
                best = i;
            }
        }
    }

    return best >= 0 ? bundle->slaves[best] : OFPP_NONE;
}

/* Executes 'bundle' on 'flow'.  Uses 'slave_enabled' to determine if the slave
 * designated by 'ofp_port' is up.  Returns the chosen slave, or OFPP_NONE if
 * none of the slaves are acceptable. */
uint16_t
bundle_execute(const struct ofpact_bundle *bundle, const struct flow *flow,
               bool (*slave_enabled)(uint16_t ofp_port, void *aux), void *aux)
{
    switch (bundle->algorithm) {
    case NX_BD_ALG_HRW:
        return execute_hrw(bundle, flow, slave_enabled, aux);

    case NX_BD_ALG_ACTIVE_BACKUP:
        return execute_ab(bundle, slave_enabled, aux);

    default:
        NOT_REACHED();
    }
}

/* Checks that 'nab' specifies a bundle action which is supported by this
 * bundle module.  Uses the 'max_ports' parameter to validate each port using
 * ofputil_check_output_port().  Returns 0 if 'nab' is supported, otherwise an
 * OFPERR_* error code. */
enum ofperr
bundle_from_openflow(const struct nx_action_bundle *nab,
                     struct ofpbuf *ofpacts)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    struct ofpact_bundle *bundle;
    uint16_t subtype;
    uint32_t slave_type;
    size_t slaves_size, i;
    enum ofperr error;

    bundle = ofpact_put_BUNDLE(ofpacts);

    subtype = ntohs(nab->subtype);
    bundle->n_slaves = ntohs(nab->n_slaves);
    bundle->basis = ntohs(nab->basis);
    bundle->fields = ntohs(nab->fields);
    bundle->algorithm = ntohs(nab->algorithm);
    slave_type = ntohl(nab->slave_type);
    slaves_size = ntohs(nab->len) - sizeof *nab;

    error = OFPERR_OFPBAC_BAD_ARGUMENT;
    if (!flow_hash_fields_valid(bundle->fields)) {
        VLOG_WARN_RL(&rl, "unsupported fields %d", (int) bundle->fields);
    } else if (bundle->n_slaves > BUNDLE_MAX_SLAVES) {
        VLOG_WARN_RL(&rl, "too may slaves");
    } else if (bundle->algorithm != NX_BD_ALG_HRW
               && bundle->algorithm != NX_BD_ALG_ACTIVE_BACKUP) {
        VLOG_WARN_RL(&rl, "unsupported algorithm %d", (int) bundle->algorithm);
    } else if (slave_type != NXM_OF_IN_PORT) {
        VLOG_WARN_RL(&rl, "unsupported slave type %"PRIu16, slave_type);
    } else {
        error = 0;
    }

    if (!is_all_zeros(nab->zero, sizeof nab->zero)) {
        VLOG_WARN_RL(&rl, "reserved field is nonzero");
        error = OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    if (subtype == NXAST_BUNDLE && (nab->ofs_nbits || nab->dst)) {
        VLOG_WARN_RL(&rl, "bundle action has nonzero reserved fields");
        error = OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    if (subtype == NXAST_BUNDLE_LOAD) {
        bundle->dst.field = mf_from_nxm_header(ntohl(nab->dst));
        bundle->dst.ofs = nxm_decode_ofs(nab->ofs_nbits);
        bundle->dst.n_bits = nxm_decode_n_bits(nab->ofs_nbits);

        if (bundle->dst.n_bits < 16) {
            VLOG_WARN_RL(&rl, "bundle_load action requires at least 16 bit "
                         "destination.");
            error = OFPERR_OFPBAC_BAD_ARGUMENT;
        }
    }

    if (slaves_size < bundle->n_slaves * sizeof(ovs_be16)) {
        VLOG_WARN_RL(&rl, "Nicira action %"PRIu16" only has %zu bytes "
                     "allocated for slaves.  %zu bytes are required for "
                     "%"PRIu16" slaves.", subtype, slaves_size,
                     bundle->n_slaves * sizeof(ovs_be16), bundle->n_slaves);
        error = OFPERR_OFPBAC_BAD_LEN;
    }

    for (i = 0; i < bundle->n_slaves; i++) {
        uint16_t ofp_port = ntohs(((ovs_be16 *)(nab + 1))[i]);
        ofpbuf_put(ofpacts, &ofp_port, sizeof ofp_port);
    }

    bundle = ofpacts->l2;
    ofpact_update_len(ofpacts, &bundle->ofpact);

    if (!error) {
        error = bundle_check(bundle, OFPP_MAX, NULL);
    }
    return error;
}

enum ofperr
bundle_check(const struct ofpact_bundle *bundle, int max_ports,
             const struct flow *flow)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    size_t i;

    if (bundle->dst.field) {
        enum ofperr error = mf_check_dst(&bundle->dst, flow);
        if (error) {
            return error;
        }
    }

    for (i = 0; i < bundle->n_slaves; i++) {
        uint16_t ofp_port = bundle->slaves[i];
        enum ofperr error;

        error = ofputil_check_output_port(ofp_port, max_ports);
        if (error) {
            VLOG_WARN_RL(&rl, "invalid slave %"PRIu16, ofp_port);
            return error;
        }

        /* Controller slaves are unsupported due to the lack of a max_len
         * argument. This may or may not change in the future.  There doesn't
         * seem to be a real-world use-case for supporting it. */
        if (ofp_port == OFPP_CONTROLLER) {
            VLOG_WARN_RL(&rl, "unsupported controller slave");
            return OFPERR_OFPBAC_BAD_OUT_PORT;
        }
    }

    return 0;
}

void
bundle_to_nxast(const struct ofpact_bundle *bundle, struct ofpbuf *openflow)
{
    int slaves_len = ROUND_UP(2 * bundle->n_slaves, OFP_ACTION_ALIGN);
    struct nx_action_bundle *nab;
    ovs_be16 *slaves;
    size_t i;

    nab = (bundle->dst.field
           ? ofputil_put_NXAST_BUNDLE_LOAD(openflow)
           : ofputil_put_NXAST_BUNDLE(openflow));
    nab->len = htons(ntohs(nab->len) + slaves_len);
    nab->algorithm = htons(bundle->algorithm);
    nab->fields = htons(bundle->fields);
    nab->basis = htons(bundle->basis);
    nab->slave_type = htonl(NXM_OF_IN_PORT);
    nab->n_slaves = htons(bundle->n_slaves);
    if (bundle->dst.field) {
        nab->ofs_nbits = nxm_encode_ofs_nbits(bundle->dst.ofs,
                                              bundle->dst.n_bits);
        nab->dst = htonl(bundle->dst.field->nxm_header);
    }

    slaves = ofpbuf_put_zeros(openflow, slaves_len);
    for (i = 0; i < bundle->n_slaves; i++) {
        slaves[i] = htons(bundle->slaves[i]);
    }
}

/* Helper for bundle_parse and bundle_parse_load. */
static void
bundle_parse__(const char *s, char **save_ptr,
               const char *fields, const char *basis, const char *algorithm,
               const char *slave_type, const char *dst,
               const char *slave_delim, struct ofpbuf *ofpacts)
{
    struct ofpact_bundle *bundle;

    if (!slave_delim) {
        ovs_fatal(0, "%s: not enough arguments to bundle action", s);
    }

    if (strcasecmp(slave_delim, "slaves")) {
        ovs_fatal(0, "%s: missing slave delimiter, expected `slaves' got `%s'",
                   s, slave_delim);
    }

    bundle = ofpact_put_BUNDLE(ofpacts);

    for (;;) {
        uint16_t slave_port;
        char *slave;

        slave = strtok_r(NULL, ", []", save_ptr);
        if (!slave || bundle->n_slaves >= BUNDLE_MAX_SLAVES) {
            break;
        }

        if (!ofputil_port_from_string(slave, &slave_port)) {
            ovs_fatal(0, "%s: bad port number", slave);
        }
        ofpbuf_put(ofpacts, &slave_port, sizeof slave_port);

        bundle = ofpacts->l2;
        bundle->n_slaves++;
    }
    ofpact_update_len(ofpacts, &bundle->ofpact);

    bundle->basis = atoi(basis);

    if (!strcasecmp(fields, "eth_src")) {
        bundle->fields = NX_HASH_FIELDS_ETH_SRC;
    } else if (!strcasecmp(fields, "symmetric_l4")) {
        bundle->fields = NX_HASH_FIELDS_SYMMETRIC_L4;
    } else {
        ovs_fatal(0, "%s: unknown fields `%s'", s, fields);
    }

    if (!strcasecmp(algorithm, "active_backup")) {
        bundle->algorithm = NX_BD_ALG_ACTIVE_BACKUP;
    } else if (!strcasecmp(algorithm, "hrw")) {
        bundle->algorithm = NX_BD_ALG_HRW;
    } else {
        ovs_fatal(0, "%s: unknown algorithm `%s'", s, algorithm);
    }

    if (strcasecmp(slave_type, "ofport")) {
        ovs_fatal(0, "%s: unknown slave_type `%s'", s, slave_type);
    }

    if (dst) {
        mf_parse_subfield(&bundle->dst, dst);
    }
}

/* Converts a bundle action string contained in 's' to an nx_action_bundle and
 * stores it in 'b'.  Sets 'b''s l2 pointer to NULL. */
void
bundle_parse(const char *s, struct ofpbuf *ofpacts)
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

    bundle_parse__(s, &save_ptr, fields, basis, algorithm, slave_type, NULL,
                   slave_delim, ofpacts);
    free(tokstr);
}

/* Converts a bundle_load action string contained in 's' to an nx_action_bundle
 * and stores it in 'b'.  Sets 'b''s l2 pointer to NULL. */
void
bundle_parse_load(const char *s, struct ofpbuf *ofpacts)
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

    bundle_parse__(s, &save_ptr, fields, basis, algorithm, slave_type, dst,
                   slave_delim, ofpacts);

    free(tokstr);
}

/* Appends a human-readable representation of 'nab' to 's'. */
void
bundle_format(const struct ofpact_bundle *bundle, struct ds *s)
{
    const char *action, *fields, *algorithm;
    size_t i;

    fields = flow_hash_fields_to_str(bundle->fields);

    switch (bundle->algorithm) {
    case NX_BD_ALG_HRW:
        algorithm = "hrw";
        break;
    case NX_BD_ALG_ACTIVE_BACKUP:
        algorithm = "active_backup";
        break;
    default:
        algorithm = "<unknown>";
    }

    action = bundle->dst.field ? "bundle_load" : "bundle";

    ds_put_format(s, "%s(%s,%"PRIu16",%s,%s,", action, fields,
                  bundle->basis, algorithm, "ofport");

    if (bundle->dst.field) {
        mf_format_subfield(&bundle->dst, s);
        ds_put_cstr(s, ",");
    }

    ds_put_cstr(s, "slaves:");
    for (i = 0; i < bundle->n_slaves; i++) {
        if (i) {
            ds_put_cstr(s, ",");
        }

        ofputil_format_port(bundle->slaves[i], s);
    }

    ds_put_cstr(s, ")");
}
