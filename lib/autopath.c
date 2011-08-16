/*
 * Copyright (c) 2011 Nicira Networks.
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
#include "nx-match.h"
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
    nxm_reg_load(ap->dst, ap->ofs_nbits, ofp_port, flow);
}

void
autopath_parse(struct nx_action_autopath *ap, const char *s_)
{
    char *s;
    uint32_t reg;
    int id_int, ofs, n_bits;
    char *id_str, *dst, *save_ptr;

    s = xstrdup(s_);
    save_ptr = NULL;
    id_str = strtok_r(s, ", ", &save_ptr);
    dst = strtok_r(NULL, ", ", &save_ptr);

    if (!dst) {
        ovs_fatal(0, "%s: not enough arguments to autopath action", s_);
    }

    id_int = atoi(id_str);
    if (id_int < 1 || id_int > UINT32_MAX) {
        ovs_fatal(0, "%s: autopath id %d is not in valid range "
                  "1 to %"PRIu32, s_, id_int, UINT32_MAX);
    }

    nxm_parse_field_bits(dst, &reg, &ofs, &n_bits);
    if (n_bits < 16) {
        ovs_fatal(0, "%s: %d-bit destination field has %u possible values, "
                  "less than required 65536", s_, n_bits, 1u << n_bits);
    }

    ofputil_init_NXAST_AUTOPATH(ap);
    ap->id = htonl(id_int);
    ap->ofs_nbits = nxm_encode_ofs_nbits(ofs, n_bits);
    ap->dst = htonl(reg);

    free(s);
}

int
autopath_check(const struct nx_action_autopath *ap, const struct flow *flow)
{
    int n_bits = nxm_decode_n_bits(ap->ofs_nbits);
    int ofs = nxm_decode_ofs(ap->ofs_nbits);

    if (n_bits < 16) {
        VLOG_WARN("at least 16 bit destination is required for autopath "
                  "action.");
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
    }

    return nxm_dst_check(ap->dst, ofs, n_bits, flow);
}
