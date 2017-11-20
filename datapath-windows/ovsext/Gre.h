/*
 * Copyright (c) 2015, 2016 Cloudbase Solutions Srl
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __GRE_H_
#define __GRE_H_ 1

#include "Flow.h"
#include "IpHelper.h"
#include "NetProto.h"

typedef union _OVS_FWD_INFO *POVS_FWD_INFO;

typedef struct _OVS_GRE_VPORT {
    UINT64 ipId;
    /*
     * To be filled
     */
} OVS_GRE_VPORT, *POVS_GRE_VPORT;


/* GRE RFC 2890 header based on http://tools.ietf.org/html/rfc2890
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |C| |K|S| Reserved0       | Ver |         Protocol Type         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Checksum (optional)      |       Reserved1 (Optional)    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Key (optional)                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Sequence Number (Optional)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct GREHdr {
    UINT16 flags;
    UINT16 protocolType;
} GREHdr, *PGREHdr;

/* Transparent Ethernet Bridging */
#define GRE_NET_TEB     0x5865
/* GRE Flags*/
#define GRE_CSUM    0x0080
#define GRE_KEY     0x0020
/* The maximum GRE header length that we can process */
#define OVS_MAX_GRE_LGTH (sizeof(EthHdr) + sizeof(IPHdr) + sizeof(GREHdr) + 12)

NTSTATUS OvsInitGreTunnel(POVS_VPORT_ENTRY vport);

VOID OvsCleanupGreTunnel(POVS_VPORT_ENTRY vport);


void OvsCleanupGreTunnel(POVS_VPORT_ENTRY vport);

NDIS_STATUS OvsEncapGre(POVS_VPORT_ENTRY vport,
                        PNET_BUFFER_LIST curNbl,
                        OvsIPv4TunnelKey *tunKey,
                        POVS_SWITCH_CONTEXT switchContext,
                        POVS_PACKET_HDR_INFO layers,
                        PNET_BUFFER_LIST *newNbl,
                        POVS_FWD_INFO switchFwdInfo);

NDIS_STATUS OvsDecapGre(POVS_SWITCH_CONTEXT switchContext,
                        PNET_BUFFER_LIST curNbl,
                        OvsIPv4TunnelKey *tunKey,
                        PNET_BUFFER_LIST *newNbl);

static __inline UINT16
OvsTunnelFlagsToGreFlags(UINT16 tunnelflags)
{
    UINT16 flags = 0;

    if (tunnelflags & OVS_TNL_F_CSUM) {
        flags |= GRE_CSUM;
    }

    if (tunnelflags & OVS_TNL_F_KEY) {
        flags |= GRE_KEY;
    }

    return flags;
}

static __inline UINT32
GreTunHdrSize(UINT16 flags)
{
    UINT32 sum = sizeof(EthHdr) + sizeof(IPHdr) + sizeof(GREHdr);
    sum += (flags & GRE_CSUM) ? 4 : 0;
    sum += (flags & GRE_KEY) ? 4 : 0;

    return sum;
}

static __inline UINT32
GreTunHdrSizeFromLayers(UINT16 flags, POVS_PACKET_HDR_INFO layers)
{
    UINT32 sum = layers->l4Offset + sizeof(GREHdr);
    sum += (flags & GRE_CSUM) ? 4 : 0;
    sum += (flags & GRE_KEY) ? 4 : 0;

    return sum;
}

static __inline UINT32
GreMaxLengthFromLayers(POVS_PACKET_HDR_INFO layers)
{
    return (layers->l4Offset + sizeof(GREHdr) + 12);
}

#endif /*__GRE_H_ */
