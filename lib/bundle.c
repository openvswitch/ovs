/* Copyright (c) 2011, 2012, 2013, 2014 Nicira, Inc.
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

VLOG_DEFINE_THIS_MODULE(bundle);

static ofp_port_t
execute_ab(const struct ofpact_bundle *bundle,
           bool (*slave_enabled)(ofp_port_t ofp_port, void *aux), void *aux)
{
    size_t i;

    for (i = 0; i < bundle->n_slaves; i++) {
        ofp_port_t slave = bundle->slaves[i];
        if (slave_enabled(slave, aux)) {
            return slave;
        }
    }

    return OFPP_NONE;
}

static ofp_port_t
execute_hrw(const struct ofpact_bundle *bundle,
            const struct flow *flow, struct flow_wildcards *wc,
            bool (*slave_enabled)(ofp_port_t ofp_port, void *aux), void *aux)
{
    uint32_t flow_hash, best_hash;
    int best, i;

    if (bundle->n_slaves > 1) {
        flow_mask_hash_fields(flow, wc, bundle->fields);
    }

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

/* Executes 'bundle' on 'flow'.  Sets fields in 'wc' that were used to
 * calculate the result.  Uses 'slave_enabled' to determine if the slave
 * designated by 'ofp_port' is up.  Returns the chosen slave, or
 * OFPP_NONE if none of the slaves are acceptable. */
ofp_port_t
bundle_execute(const struct ofpact_bundle *bundle,
               const struct flow *flow, struct flow_wildcards *wc,
               bool (*slave_enabled)(ofp_port_t ofp_port, void *aux),
               void *aux)
{
    switch (bundle->algorithm) {
    case NX_BD_ALG_HRW:
        return execute_hrw(bundle, flow, wc, slave_enabled, aux);

    case NX_BD_ALG_ACTIVE_BACKUP:
        return execute_ab(bundle, slave_enabled, aux);

    default:
        OVS_NOT_REACHED();
    }
}

enum ofperr
bundle_check(const struct ofpact_bundle *bundle, ofp_port_t max_ports,
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
        ofp_port_t ofp_port = bundle->slaves[i];
        enum ofperr error;

        error = ofpact_check_output_port(ofp_port, max_ports);
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
