/*
 * Copyright (c) 2014 Netronome.
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

#ifndef OPENFLOW_NETRONOME_EXT_H
#define OPENFLOW_NETRONOME_EXT_H 1

#include "openflow/openflow.h"
#include "openvswitch/types.h"

/* The following vendor extension, proposed by Netronome, is not yet
 * standardized, so they are not included in openflow.h.  It may
 * be suitable for standardization */


/* Netronome enhanced select group */

enum ntr_group_mod_subtype {
        NTRT_SELECTION_METHOD = 1,
};

#define NTR_MAX_SELECTION_METHOD_LEN 16

struct ntr_group_prop_selection_method {
    ovs_be16 type;                  /* OFPGPT15_EXPERIMENTER. */
    ovs_be16 length;                /* Length in bytes of this property
                                     * excluding trailing padding. */
    ovs_be32 experimenter;          /* NTR_VENDOR_ID. */
    ovs_be32 exp_type;              /* NTRT_SELECTION_METHOD. */
    ovs_be32 pad;
    char selection_method[NTR_MAX_SELECTION_METHOD_LEN];
                                    /* Null-terminated */
    ovs_be64 selection_method_param;  /* Non-Field parameter for
                                       * bucket selection. */

    /* Followed by:
     *   - Exactly (length - 40) (possibly 0) bytes containing OXM TLVs, then
     *   - Exactly ((length + 7)/8*8 - length) (between 0 and 7) bytes of
     *     all-zero bytes
     * In summary, ntr_group_prop_selection_method is padded as needed,
     * to make its overall size a multiple of 8, to preserve alignment
     * in structures using it.
     */
    /* uint8_t field_array[0]; */   /* Zero or more fields encoded as
                                     * OXM TLVs where the has_mask bit must
                                     * be zero and the value it specifies is
                                     * a mask to apply to packet fields and
                                     * then input them to the selection
                                     * method of a select group. */
    /* uint8_t pad2[0]; */
};
OFP_ASSERT(sizeof(struct ntr_group_prop_selection_method) == 40);

#endif /* openflow/netronome-ext.h */
