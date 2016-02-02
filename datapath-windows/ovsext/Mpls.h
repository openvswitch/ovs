/*
 * Copyright (c) 2015 Cloudbase Solutions Srl
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

#ifndef __MPLS_H_
#define __MPLS_H_ 1

#include "precomp.h"
#include "Ethernet.h"

/*
 * MPLS definitions
 */
#define FLOW_MAX_MPLS_LABELS    3

#define MPLS_HLEN               4
#define MPLS_BOS_MASK           0x00000100

/* Reference: RFC 5462, RFC 3032
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                Label                  | TC  |S|       TTL     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *	Label:  Label Value, 20 bits
 *	TC:     Traffic Class field, 3 bits
 *	S:      Bottom of Stack, 1 bit
 *	TTL:    Time to Live, 8 bits
 */

typedef struct MPLSHdr {
    ovs_be32 lse;
} MPLSHdr;

__inline BOOLEAN
OvsEthertypeIsMpls(ovs_be16 ethertype)
{
    return ethertype == htons(ETH_TYPE_MPLS) ||
           ethertype == htons(ETH_TYPE_MPLS_MCAST);
}

/* Returns the number of MPLS LSEs present in 'a'
 *
 * Counts 'flow''s MPLS label stack entries (LESs) stopping at the first
 * entry that has the bottom of stack (BOS) bit set. If no such entry exists,
 * then zero is returned, meaning that the maximum number of supported
 * MPLS LSEs exceeded.
 */
__inline UINT32
OvsCountMplsLabels(PNL_ATTR a)
{
    const MPLSHdr *mpls = NlAttrGet(a);
    UINT32 count = 0;
    BOOLEAN bos = FALSE;

    for (count = 0; count < FLOW_MAX_MPLS_LABELS; count++) {
        if ((mpls + count)->lse & htonl(MPLS_BOS_MASK)) {
            bos = TRUE;
            break;
        }
    }

    return bos ? ++count : 0;
}

#endif /* __MPLS_H_ */
