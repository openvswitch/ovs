/*
 * Copyright (c) 2011, 2012 Nicira, Inc.
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

#include "autopath.h"

#include <inttypes.h>
#include <stdlib.h>

#include "flow.h"
#include "meta-flow.h"
#include "nx-match.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-util.h"
#include "openflow/nicira-ext.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(autopath);

void
autopath_parse(struct ofpact_autopath *ap, const char *s_)
{
    char *s;
    char *id_str, *dst, *save_ptr;
    uint16_t port;

    ofpact_init_AUTOPATH(ap);

    s = xstrdup(s_);
    save_ptr = NULL;
    id_str = strtok_r(s, ", ", &save_ptr);
    dst = strtok_r(NULL, ", ", &save_ptr);

    if (!dst) {
        ovs_fatal(0, "%s: not enough arguments to autopath action", s_);
    }

    if (!ofputil_port_from_string(id_str, &port)) {
        ovs_fatal(0, "%s: bad port number", s_);
    }
    ap->port = port;

    mf_parse_subfield(&ap->dst, dst);
    if (ap->dst.n_bits < 16) {
        ovs_fatal(0, "%s: %d-bit destination field has %u possible values, "
                  "less than required 65536",
                  s_, ap->dst.n_bits, 1u << ap->dst.n_bits);
    }

    free(s);
}

enum ofperr
autopath_from_openflow(const struct nx_action_autopath *nap,
                       struct ofpact_autopath *autopath)
{
    ofpact_init_AUTOPATH(autopath);
    autopath->dst.field = mf_from_nxm_header(ntohl(nap->dst));
    autopath->dst.ofs = nxm_decode_ofs(nap->ofs_nbits);
    autopath->dst.n_bits = nxm_decode_n_bits(nap->ofs_nbits);
    autopath->port = ntohl(nap->id);

    if (autopath->dst.n_bits < 16) {
        VLOG_WARN("at least 16 bit destination is required for autopath "
                  "action.");
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return autopath_check(autopath, NULL);
}

enum ofperr
autopath_check(const struct ofpact_autopath *autopath, const struct flow *flow)
{
    VLOG_WARN_ONCE("The autopath action is deprecated and may be removed in"
                   " February 2013.  Please email dev@openvswitch.org with"
                   " concerns.");
    return mf_check_dst(&autopath->dst, flow);
}

void
autopath_to_nxast(const struct ofpact_autopath *autopath,
                  struct ofpbuf *openflow)
{
    struct nx_action_autopath *ap;

    ap = ofputil_put_NXAST_AUTOPATH__DEPRECATED(openflow);
    ap->ofs_nbits = nxm_encode_ofs_nbits(autopath->dst.ofs,
                                         autopath->dst.n_bits);
    ap->dst = htonl(autopath->dst.field->nxm_header);
    ap->id = htonl(autopath->port);
}
