/*
 * Copyright (c) 2016 VMware, Inc.
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


#ifndef __GENEVE_H_
#define __GENEVE_H_ 1

#include "NetProto.h"

typedef union _OVS_FWD_INFO *POVS_FWD_INFO;

typedef struct _OVS_GENEVE_VPORT {
    UINT16 dstPort;
    UINT64 filterID;
    UINT64 ipId;
    /*
     * To be filled
     */
} OVS_GENEVE_VPORT, *POVS_GENEVE_VPORT;

/* Geneve Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Virtual Network Identifier (VNI)       |    Reserved   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Variable Length Options                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Option Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Option Class         |      Type     |R|R|R| Length  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Variable Option Data                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct GeneveHdr {
    /* Length of options fields in int32 excluding the common header */
    UINT32   optLen : 6;
    /* Version. */
    UINT32   version:2;
    /* Reserved. */
    UINT32   reserved1 : 6;
    /* Critical options present */
    UINT32   critical : 1;
    /* This packet contains a control message instead of a data payload */
    UINT32   oam:1;
    /* Protocol Type. */
    UINT32   protocol:16;
    /* VNI */
    UINT32   vni:24;
    /* Reserved. */
    UINT32   reserved2:8;
} GeneveHdr;

typedef struct GeneveOptionHdr {
    /* Namespace for the 'type' field. */
    UINT32   optionClass:16;
    /* Format of data contained in the option. */
    UINT32   type:8;
    /* Length of option in int32 excluding the option header. */
    UINT32   length:5;
    /* Reserved. */
    UINT32   reserved:3;
} GeneveOptionHdr;

#define GENEVE_CRIT_OPT_TYPE (1 << 7)

NTSTATUS OvsInitGeneveTunnel(POVS_VPORT_ENTRY vport,
                             UINT16 udpDestPort);

VOID OvsCleanupGeneveTunnel(POVS_VPORT_ENTRY vport);


NDIS_STATUS OvsEncapGeneve(POVS_VPORT_ENTRY vport,
                           PNET_BUFFER_LIST curNbl,
                           OvsIPv4TunnelKey *tunKey,
                           POVS_SWITCH_CONTEXT switchContext,
                           POVS_PACKET_HDR_INFO layers,
                           PNET_BUFFER_LIST *newNbl,
                           POVS_FWD_INFO switchFwdInfo);

NDIS_STATUS OvsDecapGeneve(POVS_SWITCH_CONTEXT switchContext,
                           PNET_BUFFER_LIST curNbl,
                           OvsIPv4TunnelKey *tunKey,
                           PNET_BUFFER_LIST *newNbl);

static __inline UINT32
OvsGetGeneveTunHdrMinSize(VOID)
{
    /* XXX: Can L2 include VLAN at all? */
    return sizeof (EthHdr) + sizeof (IPHdr) + sizeof (UDPHdr) +
           sizeof (GeneveHdr);
}

static __inline UINT32
OvsGetGeneveTunHdrMaxSize(VOID)
{
    /* XXX: Can L2 include VLAN at all? */
    return OvsGetGeneveTunHdrMinSize() + TUN_OPT_MAX_LEN;
}

#define GENEVE_UDP_PORT 6081
#define GENEVE_UDP_PORT_NBO 0xC117
#define GENEVE_VER 0
#define GENEVE_DEFAULT_TTL 64
#define GENEVE_ID_IS_VALID(geneveID) (0 < (geneveID) && (vxlanID) <= 0xffffff)
#define GENEVE_TUNNELID_TO_VNI(_tID)   (UINT32)(((UINT64)(_tID)) >> 40)
#define GENEVE_VNI_TO_TUNNELID(_vni) (((UINT64)(_vni)) << 40)
#define ETH_P_TEB_NBO       0x5865          /* Trans Ether Bridging */

#endif /* __GENEVE_H_ */
