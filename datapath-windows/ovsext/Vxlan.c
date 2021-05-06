/*
 * Copyright (c) 2014, 2016 VMware, Inc.
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

#include "precomp.h"

#include "Atomic.h"
#include "Debug.h"
#include "Flow.h"
#include "IpHelper.h"
#include "NetProto.h"
#include "Offload.h"
#include "PacketIO.h"
#include "PacketParser.h"
#include "Switch.h"
#include "User.h"
#include "Vport.h"
#include "Vxlan.h"

#pragma warning( push )
#pragma warning( disable:4127 )


#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_VXLAN

/* Helper macro to check if a VXLAN ID is valid. */
#define VXLAN_ID_IS_VALID(vxlanID) (0 < (vxlanID) && (vxlanID) <= 0xffffff)
#define VXLAN_TUNNELID_TO_VNI(_tID)   (UINT32)(((UINT64)(_tID)) >> 40)
#define VXLAN_VNI_TO_TUNNELID(_vni) (((UINT64)(_vni)) << 40)
#define IP_DF_NBO 0x0040
#define VXLAN_DEFAULT_TTL 64
#define VXLAN_MULTICAST_TTL 64
#define VXLAN_DEFAULT_INSTANCE_ID 1

/* Move to a header file */
extern POVS_SWITCH_CONTEXT gOvsSwitchContext;

/*
 *----------------------------------------------------------------------------
 * This function verifies if the VXLAN tunnel already exists, in order to
 * avoid sending a duplicate request to the WFP base filtering engine.
 *----------------------------------------------------------------------------
 */
static BOOLEAN
OvsIsTunnelFilterCreated(POVS_SWITCH_CONTEXT switchContext,
                         UINT16 udpPortDest)
{
    for (UINT hash = 0; hash < OVS_MAX_VPORT_ARRAY_SIZE; hash++) {
        PLIST_ENTRY head, link, next;

        head = &(switchContext->portNoHashArray[hash & OVS_VPORT_MASK]);
        LIST_FORALL_SAFE(head, link, next) {
            POVS_VPORT_ENTRY vport = NULL;
            POVS_VXLAN_VPORT vxlanPort = NULL;
            vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, portNoLink);
            vxlanPort = (POVS_VXLAN_VPORT)vport->priv;
            if (vxlanPort) {
                if ((udpPortDest == vxlanPort->dstPort)) {
                    /* The VXLAN tunnel was already created. */
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

/*
 *----------------------------------------------------------------------------
 * This function allocates and initializes the OVS_VXLAN_VPORT. The function
 * also creates a WFP tunnel filter for the necessary destination port. The
 * tunnel filter create request is passed to the tunnel filter threads that
 * will complete the request at a later time when IRQL is lowered to
 * PASSIVE_LEVEL.
 *
 * udpDestPort: the vxlan is set as payload to a udp frame. If the destination
 * port of an udp frame is udpDestPort, we understand it to be vxlan.
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsInitVxlanTunnel(PIRP irp,
                   POVS_VPORT_ENTRY vport,
                   UINT16 udpDestPort,
                   PFNTunnelVportPendingOp callback,
                   PVOID tunnelContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    POVS_VXLAN_VPORT vxlanPort = NULL;

    vxlanPort = OvsAllocateMemoryWithTag(sizeof (*vxlanPort),
                                         OVS_VXLAN_POOL_TAG);
    if (vxlanPort == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(vxlanPort, sizeof(*vxlanPort));
    vxlanPort->dstPort = udpDestPort;
    vport->priv = (PVOID)vxlanPort;

    if (!OvsIsTunnelFilterCreated(gOvsSwitchContext, udpDestPort)) {
        status = OvsTunnelFilterCreate(irp,
                                       udpDestPort,
                                       &vxlanPort->filterID,
                                       callback,
                                       tunnelContext);
    } else {
        status = STATUS_OBJECT_NAME_EXISTS;
    }

    return status;
}

/*
 *----------------------------------------------------------------------------
 * This function releases the OVS_VXLAN_VPORT. The function also deletes the
 * WFP tunnel filter previously created. The tunnel filter delete request is
 * passed to the tunnel filter threads that will complete the request at a
 * later time when IRQL is lowered to PASSIVE_LEVEL.
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsCleanupVxlanTunnel(PIRP irp,
                      POVS_VPORT_ENTRY vport,
                      PFNTunnelVportPendingOp callback,
                      PVOID tunnelContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    POVS_VXLAN_VPORT vxlanPort = NULL;

    if (vport->ovsType != OVS_VPORT_TYPE_VXLAN ||
        vport->priv == NULL) {
        return STATUS_SUCCESS;
    }

    vxlanPort = (POVS_VXLAN_VPORT)vport->priv;

    if (vxlanPort->filterID != 0) {
        status = OvsTunnelFilterDelete(irp,
                                       vxlanPort->filterID,
                                       callback,
                                       tunnelContext);
    } else {
        OvsFreeMemoryWithTag(vport->priv, OVS_VXLAN_POOL_TAG);
        vport->priv = NULL;
    }

    return status;
}


/*
 *----------------------------------------------------------------------------
 * OvsDoEncapVxlan
 *     Encapsulates the packet.
 *----------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsDoEncapVxlan(POVS_VPORT_ENTRY vport,
                PNET_BUFFER_LIST curNbl,
                OvsIPv4TunnelKey *tunKey,
                POVS_FWD_INFO fwdInfo,
                POVS_PACKET_HDR_INFO layers,
                POVS_SWITCH_CONTEXT switchContext,
                PNET_BUFFER_LIST *newNbl)
{
    NDIS_STATUS status;
    PNET_BUFFER curNb;
    PMDL curMdl;
    PUINT8 bufferStart;
    EthHdr *ethHdr;
    IPHdr *ipHdr;
    UDPHdr *udpHdr;
    VXLANHdr *vxlanHdr;
    POVS_VXLAN_VPORT vportVxlan;
    UINT32 headRoom = OvsGetVxlanTunHdrSize();
    UINT32 packetLength;
    ULONG mss = 0;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;

    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    packetLength = NET_BUFFER_DATA_LENGTH(curNb);

    if (layers->isTcp) {
        mss = OVSGetTcpMSS(curNbl);

        OVS_LOG_TRACE("MSS %u packet len %u", mss,
                      packetLength);
        if (mss) {
            OVS_LOG_TRACE("l4Offset %d", layers->l4Offset);
            *newNbl = OvsTcpSegmentNBL(switchContext, curNbl, layers,
                                       mss, headRoom, FALSE);
            if (*newNbl == NULL) {
                OVS_LOG_ERROR("Unable to segment NBL");
                return NDIS_STATUS_FAILURE;
            }
            /* Clear out LSO flags after this point */
            NET_BUFFER_LIST_INFO(*newNbl, TcpLargeSendNetBufferListInfo) = 0;
        }
    }

    vportVxlan = (POVS_VXLAN_VPORT) GetOvsVportPriv(vport);
    ASSERT(vportVxlan);

    /* If we didn't split the packet above, make a copy now */
    if (*newNbl == NULL) {
        *newNbl = OvsPartialCopyNBL(switchContext, curNbl, 0, headRoom,
                                    FALSE /*NBL info*/);
        if (*newNbl == NULL) {
            OVS_LOG_ERROR("Unable to copy NBL");
            return NDIS_STATUS_FAILURE;
        }
        csumInfo.Value = NET_BUFFER_LIST_INFO(curNbl,
                                              TcpIpChecksumNetBufferListInfo);
        status = OvsApplySWChecksumOnNB(layers, *newNbl, &csumInfo);

        if (status != NDIS_STATUS_SUCCESS) {
            goto ret_error;
        }
    }

    curNbl = *newNbl;
    for (curNb = NET_BUFFER_LIST_FIRST_NB(curNbl); curNb != NULL;
            curNb = curNb->Next) {
        status = NdisRetreatNetBufferDataStart(curNb, headRoom, 0, NULL);
        if (status != NDIS_STATUS_SUCCESS) {
            goto ret_error;
        }

        curMdl = NET_BUFFER_CURRENT_MDL(curNb);
        bufferStart = (PUINT8)OvsGetMdlWithLowPriority(curMdl);
        if (!bufferStart) {
            status = NDIS_STATUS_RESOURCES;
            goto ret_error;
        }

        bufferStart += NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
        if (NET_BUFFER_NEXT_NB(curNb)) {
            OVS_LOG_TRACE("nb length %u next %u",
                          NET_BUFFER_DATA_LENGTH(curNb),
                          NET_BUFFER_DATA_LENGTH(curNb->Next));
        }

        /* L2 header */
        ethHdr = (EthHdr *)bufferStart;
        NdisMoveMemory(ethHdr->Destination, fwdInfo->dstMacAddr,
                       sizeof ethHdr->Destination);
        NdisMoveMemory(ethHdr->Source, fwdInfo->srcMacAddr,
                       sizeof ethHdr->Source);
        ethHdr->Type = htons(ETH_TYPE_IPV4);

        /* IP header */
        ipHdr = (IPHdr *)((PCHAR)ethHdr + sizeof *ethHdr);

        ipHdr->ihl = sizeof *ipHdr / 4;
        ipHdr->version = IPPROTO_IPV4;
        ipHdr->tos = tunKey->tos;
        ipHdr->tot_len = htons(NET_BUFFER_DATA_LENGTH(curNb) - sizeof *ethHdr);
        ipHdr->id = (uint16)atomic_add64(&vportVxlan->ipId,
                                         NET_BUFFER_DATA_LENGTH(curNb));
        ipHdr->frag_off = (tunKey->flags & OVS_TNL_F_DONT_FRAGMENT) ?
                          IP_DF_NBO : 0;
        ipHdr->ttl = tunKey->ttl ? tunKey->ttl : VXLAN_DEFAULT_TTL;
        ipHdr->protocol = IPPROTO_UDP;
        ASSERT(tunKey->dst == fwdInfo->dstIpAddr);
        ASSERT(tunKey->src == fwdInfo->srcIpAddr || tunKey->src == 0);
        ipHdr->saddr = fwdInfo->srcIpAddr;
        ipHdr->daddr = fwdInfo->dstIpAddr;

        ipHdr->check = 0;

        /* UDP header */
        udpHdr = (UDPHdr *)((PCHAR)ipHdr + sizeof *ipHdr);
        udpHdr->source = htons(tunKey->flow_hash | MAXINT16);
        udpHdr->dest = tunKey->dst_port ? tunKey->dst_port :
                                          htons(vportVxlan->dstPort);
        udpHdr->len = htons(NET_BUFFER_DATA_LENGTH(curNb) - headRoom +
                            sizeof *udpHdr + sizeof *vxlanHdr);

        if (tunKey->flags & OVS_TNL_F_CSUM) {
            udpHdr->check = IPPseudoChecksum(&ipHdr->saddr, &ipHdr->daddr,
                                             IPPROTO_UDP, ntohs(udpHdr->len));
        } else {
            udpHdr->check = 0;
        }

        /* VXLAN header */
        vxlanHdr = (VXLANHdr *)((PCHAR)udpHdr + sizeof *udpHdr);
        vxlanHdr->flags1 = 0;
        vxlanHdr->locallyReplicate = 0;
        vxlanHdr->flags2 = 0;
        vxlanHdr->reserved1 = 0;
        vxlanHdr->vxlanID = VXLAN_TUNNELID_TO_VNI(tunKey->tunnelId);
        vxlanHdr->instanceID = 1;
        vxlanHdr->reserved2 = 0;
    }

    csumInfo.Value = 0;
    csumInfo.Transmit.IpHeaderChecksum = 1;
    csumInfo.Transmit.IsIPv4 = 1;
    if (tunKey->flags & OVS_TNL_F_CSUM) {
        csumInfo.Transmit.UdpChecksum = 1;
    }
    NET_BUFFER_LIST_INFO(curNbl,
                         TcpIpChecksumNetBufferListInfo) = csumInfo.Value;


    return STATUS_SUCCESS;

ret_error:
    OvsCompleteNBL(switchContext, *newNbl, TRUE);
    *newNbl = NULL;
    return status;
}


/*
 *----------------------------------------------------------------------------
 * OvsEncapVxlan --
 *     Encapsulates the packet if L2/L3 for destination resolves. Otherwise,
 *     enqueues a callback that does encapsulation after resolution.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsEncapVxlan(POVS_VPORT_ENTRY vport,
              PNET_BUFFER_LIST curNbl,
              OvsIPv4TunnelKey *tunKey,
              POVS_SWITCH_CONTEXT switchContext,
              POVS_PACKET_HDR_INFO layers,
              PNET_BUFFER_LIST *newNbl,
              POVS_FWD_INFO switchFwdInfo)
{
    NTSTATUS status;
    OVS_FWD_INFO fwdInfo;

    status = OvsLookupIPFwdInfo(tunKey->src, tunKey->dst, &fwdInfo);
    if (status != STATUS_SUCCESS) {
        OvsFwdIPHelperRequest(NULL, 0, tunKey, NULL, NULL, NULL);
        /*
         * XXX: Don't know if the completionList will make any sense when
         * accessed in the callback. Make sure the caveats are known.
         *
         * XXX: This code will work once we are able to grab locks in the
         * callback.
         */
        return NDIS_STATUS_FAILURE;
    }

    RtlCopyMemory(switchFwdInfo->value, fwdInfo.value, sizeof fwdInfo.value);

    return OvsDoEncapVxlan(vport, curNbl, tunKey, &fwdInfo, layers,
                           switchContext, newNbl);
}


/*
 *----------------------------------------------------------------------------
 * OvsDecapVxlan
 *     Decapsulates to tunnel header in 'curNbl' and puts into 'tunKey'.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsDecapVxlan(POVS_SWITCH_CONTEXT switchContext,
              PNET_BUFFER_LIST curNbl,
              OvsIPv4TunnelKey *tunKey,
              PNET_BUFFER_LIST *newNbl)
{
    PNET_BUFFER curNb;
    PMDL curMdl;
    EthHdr *ethHdr;
    IPHdr *ipHdr;
    UDPHdr *udpHdr;
    VXLANHdr *vxlanHdr;
    UINT32 tunnelSize, packetLength;
    PUINT8 bufferStart;
    NDIS_STATUS status;
    OVS_PACKET_HDR_INFO layers = { 0 };

    status = OvsExtractLayers(curNbl, &layers);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    /* Check the length of the UDP payload */
    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    packetLength = NET_BUFFER_DATA_LENGTH(curNb);
    tunnelSize = OvsGetVxlanTunHdrSizeFromLayers(&layers);
    if (packetLength < tunnelSize) {
        return NDIS_STATUS_INVALID_LENGTH;
    }

    /*
     * Create a copy of the NBL so that we have all the headers in one MDL.
     */
    *newNbl = OvsPartialCopyNBL(switchContext, curNbl,
                                tunnelSize, 0,
                                TRUE /*copy NBL info */);

    if (*newNbl == NULL) {
        return NDIS_STATUS_RESOURCES;
    }

    /* XXX: Handle VLAN header. */
    curNbl = *newNbl;
    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    bufferStart = (PUINT8)OvsGetMdlWithLowPriority(curMdl)
        + NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    if (!bufferStart) {
        status = NDIS_STATUS_RESOURCES;
        goto dropNbl;
    }

    ethHdr = (EthHdr *)bufferStart;
    /* XXX: Handle IP options. */
    ipHdr = (IPHdr *)(bufferStart + layers.l3Offset);
    tunKey->src = ipHdr->saddr;
    tunKey->dst = ipHdr->daddr;
    tunKey->tos = ipHdr->tos;
    tunKey->ttl = ipHdr->ttl;
    tunKey->pad = 0;
    udpHdr = (UDPHdr *)(bufferStart + layers.l4Offset);

    /* Validate if NIC has indicated checksum failure. */
    status = OvsValidateUDPChecksum(curNbl, udpHdr->check == 0);
    if (status != NDIS_STATUS_SUCCESS) {
        goto dropNbl;
    }

    /* Calculate and verify UDP checksum if NIC didn't do it. */
    if (udpHdr->check != 0) {
        tunKey->flags |= OVS_TNL_F_CSUM;
        status = OvsCalculateUDPChecksum(curNbl, curNb, ipHdr, udpHdr,
                                         packetLength, &layers);
        if (status != NDIS_STATUS_SUCCESS) {
            goto dropNbl;
        }
    }

    vxlanHdr = (VXLANHdr *)((PCHAR)udpHdr + sizeof *udpHdr);
    if (vxlanHdr->instanceID) {
        tunKey->flags |= OVS_TNL_F_KEY;
        tunKey->tunnelId = VXLAN_VNI_TO_TUNNELID(vxlanHdr->vxlanID);
    } else {
        tunKey->flags &= ~OVS_TNL_F_KEY;
        tunKey->tunnelId = 0;
    }

    /* Clear out the receive flag for the inner packet. */
    NET_BUFFER_LIST_INFO(curNbl, TcpIpChecksumNetBufferListInfo) = 0;
    NdisAdvanceNetBufferDataStart(curNb, tunnelSize, FALSE, NULL);
    return NDIS_STATUS_SUCCESS;

dropNbl:
    OvsCompleteNBL(switchContext, *newNbl, TRUE);
    *newNbl = NULL;
    return status;
}


NDIS_STATUS
OvsSlowPathDecapVxlan(const PNET_BUFFER_LIST packet,
                   OvsIPv4TunnelKey *tunnelKey)
{
    NDIS_STATUS status = NDIS_STATUS_FAILURE;
    UDPHdr udpStorage;
    const UDPHdr *udp;
    VXLANHdr *VxlanHeader;
    VXLANHdr  VxlanHeaderBuffer;
    struct IPHdr ip_storage;
    const struct IPHdr *nh;
    OVS_PACKET_HDR_INFO layers;

    layers.value = 0;

    do {
        nh = OvsGetIp(packet, layers.l3Offset, &ip_storage);
        if (nh) {
            layers.l4Offset = layers.l3Offset + nh->ihl * 4;
        } else {
           status = NDIS_STATUS_INVALID_PACKET;
           break;
        }

        /* make sure it's a VXLAN packet */
        udp = OvsGetUdp(packet, layers.l4Offset, &udpStorage);
        if (udp) {
            layers.l7Offset = layers.l4Offset + sizeof *udp;
            if (udp->check != 0) {
                tunnelKey->flags |= OVS_TNL_F_CSUM;
            }
        } else {
            break;
        }

        VxlanHeader = (VXLANHdr *)OvsGetPacketBytes(packet,
                                                    sizeof(*VxlanHeader),
                                                    layers.l7Offset,
                                                    &VxlanHeaderBuffer);

        if (VxlanHeader) {
            tunnelKey->src = nh->saddr;
            tunnelKey->dst = nh->daddr;
            tunnelKey->ttl = nh->ttl;
            tunnelKey->tos = nh->tos;
            if (VxlanHeader->instanceID) {
                tunnelKey->flags |= OVS_TNL_F_KEY;
                tunnelKey->tunnelId = VXLAN_VNI_TO_TUNNELID(VxlanHeader->vxlanID);
            } else {
                tunnelKey->flags &= ~OVS_TNL_F_KEY;
                tunnelKey->tunnelId = 0;
            }
        } else {
            break;
        }
        status = NDIS_STATUS_SUCCESS;

    } while(FALSE);

    return status;
}

#pragma warning( pop )
