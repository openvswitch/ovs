/*
 * Copyright (c) 2011 Nicira, Inc.
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
#include "ofp-errors.h"
#include "ofp-util.h"
#include "openflow/nicira-ext.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(autopath);

/* Loads 'ofp_port' into the appropriate register in accordance with the
 * autopath action. */
void
autopath_execute(const struct nx_action_autopath *ap, struct flow *flow,
                 uint16_t ofp_port)
{
    struct mf_subfield dst;

    nxm_decode(&dst, ap->dst, ap->ofs_nbits);
    mf_set_subfield_value(&dst, ofp_port, flow);
}

void
autopath_parse(struct nx_action_autopath *ap, const char *s_)
{
    char *s;
    char *id_str, *dst_s, *save_ptr;
    struct mf_subfield dst;
    int id_int;

    s = xstrdup(s_);
    save_ptr = NULL;
    id_str = strtok_r(s, ", ", &save_ptr);
    dst_s = strtok_r(NULL, ", ", &save_ptr);

    if (!dst_s) {
        ovs_fatal(0, "%s: not enough arguments to autopath action", s_);
    }

    id_int = atoi(id_str);
    if (id_int < 1 || id_int > UINT32_MAX) {
        ovs_fatal(0, "%s: autopath id %d is not in valid range "
                  "1 to %"PRIu32, s_, id_int, UINT32_MAX);
    }

    mf_parse_subfield(&dst, dst_s);
    if (dst.n_bits < 16) {
        ovs_fatal(0, "%s: %d-bit destination field has %u possible values, "
                  "less than required 65536",
                  s_, dst.n_bits, 1u << dst.n_bits);
    }

    ofputil_init_NXAST_AUTOPATH(ap);
    ap->id = htonl(id_int);
    ap->ofs_nbits = nxm_encode_ofs_nbits(dst.ofs, dst.n_bits);
    ap->dst = htonl(dst.field->nxm_header);

    free(s);
}

enum ofperr
autopath_check(const struct nx_action_autopath *ap, const struct flow *flow)
{
    struct mf_subfield dst;

    nxm_decode(&dst, ap->dst, ap->ofs_nbits);
    if (dst.n_bits < 16) {
        VLOG_WARN("at least 16 bit destination is required for autopath "
                  "action.");
        return OFPERR_OFPBAC_BAD_ARGUMENT;
    }

    return mf_check_dst(&dst, flow);
}
