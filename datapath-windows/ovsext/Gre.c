/*
 * Copyright (c) 2015 Cloudbase Solutions Srl
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

#include "precomp.h"

#include "Atomic.h"
#include "Checksum.h"
#include "Flow.h"
#include "Gre.h"
#include "IpHelper.h"
#include "NetProto.h"
#include "PacketIO.h"
#include "PacketParser.h"
#include "Switch.h"
#include "User.h"
#include "Util.h"
#include "Vport.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_GRE
#include "Debug.h"

static NDIS_STATUS
OvsDoEncapGre(POVS_VPORT_ENTRY vport, PNET_BUFFER_LIST curNbl,
              const OvsIPv4TunnelKey *tunKey,
              const POVS_FWD_INFO fwdInfo,
              POVS_PACKET_HDR_INFO layers,
              POVS_SWITCH_CONTEXT switchContext,
              PNET_BUFFER_LIST *newNbl);

/*
 * --------------------------------------------------------------------------
 * OvsInitGreTunnel --
 *    Initialize GRE tunnel module.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsInitGreTunnel(POVS_VPORT_ENTRY vport)
{
    POVS_GRE_VPORT grePort;

    grePort = (POVS_GRE_VPORT)OvsAllocateMemoryWithTag(sizeof(*grePort),
                                                       OVS_GRE_POOL_TAG);
    if (!grePort) {
        OVS_LOG_ERROR("Insufficient memory, can't allocate OVS_GRE_VPORT");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(grePort, sizeof(*grePort));
    vport->priv = (PVOID)grePort;
    return STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsCleanupGreTunnel --
 *    Cleanup GRE Tunnel module.
 * --------------------------------------------------------------------------
 */
void
OvsCleanupGreTunnel(POVS_VPORT_ENTRY vport)
{
    if (vport->ovsType != OVS_VPORT_TYPE_GRE ||
        vport->priv == NULL) {
        return;
    }

    OvsFreeMemoryWithTag(vport->priv, OVS_GRE_POOL_TAG);
    vport->priv = NULL;
}

/*
 * --------------------------------------------------------------------------
 * OvsEncapGre --
 *     Encapsulates a packet with an GRE header.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsEncapGre(POVS_VPORT_ENTRY vport,
            PNET_BUFFER_LIST curNbl,
            OvsIPv4TunnelKey *tunKey,
            POVS_SWITCH_CONTEXT switchContext,
            POVS_PACKET_HDR_INFO layers,
            PNET_BUFFER_LIST *newNbl)
{
    OVS_FWD_INFO fwdInfo;
    NDIS_STATUS status;

    status = OvsLookupIPFwdInfo(tunKey->dst, &fwdInfo);
    if (status != STATUS_SUCCESS) {
        OvsFwdIPHelperRequest(NULL, 0, tunKey, NULL, NULL, NULL);
        return NDIS_STATUS_FAILURE;
    }

    status = OvsDoEncapGre(vport, curNbl, tunKey, &fwdInfo, layers,
                           switchContext, newNbl);
    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsDoEncapGre --
 *    Internal utility function which actually does the GRE encap.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsDoEncapGre(POVS_VPORT_ENTRY vport,
              PNET_BUFFER_LIST curNbl,
              const OvsIPv4TunnelKey *tunKey,
              const POVS_FWD_INFO fwdInfo,
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
    PGREHdr greHdr;
    POVS_GRE_VPORT vportGre;
    UINT32 headRoom = GreTunHdrSize(tunKey->flags);
#if DBG
    UINT32 counterHeadRoom;
#endif
    UINT32 packetLength;
    ULONG mss = 0;
    ASSERT(*newNbl == NULL);

    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    packetLength = NET_BUFFER_DATA_LENGTH(curNb);

    if (layers->isTcp) {
        NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO tsoInfo;

        tsoInfo.Value = NET_BUFFER_LIST_INFO(curNbl,
                                             TcpLargeSendNetBufferListInfo);
        switch (tsoInfo.Transmit.Type) {
            case NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE:
                mss = tsoInfo.LsoV1Transmit.MSS;
                break;
            case NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE:
                mss = tsoInfo.LsoV2Transmit.MSS;
                break;
            default:
                OVS_LOG_ERROR("Unknown LSO transmit type:%d",
                              tsoInfo.Transmit.Type);
        }
        OVS_LOG_TRACE("MSS %u packet len %u", mss,
                      packetLength);
        if (mss) {
            OVS_LOG_TRACE("l4Offset %d", layers->l4Offset);
            *newNbl = OvsTcpSegmentNBL(switchContext, curNbl, layers,
                                       mss, headRoom);
            if (*newNbl == NULL) {
                OVS_LOG_ERROR("Unable to segment NBL");
                return NDIS_STATUS_FAILURE;
            }
            /* Clear out LSO flags after this point */
            NET_BUFFER_LIST_INFO(*newNbl, TcpLargeSendNetBufferListInfo) = 0;
        }
    }

    vportGre = (POVS_GRE_VPORT)GetOvsVportPriv(vport);
    ASSERT(vportGre);

    /* If we didn't split the packet above, make a copy now */
    if (*newNbl == NULL) {
        *newNbl = OvsPartialCopyNBL(switchContext, curNbl, 0, headRoom,
                                    FALSE /*NBL info*/);
        if (*newNbl == NULL) {
            OVS_LOG_ERROR("Unable to copy NBL");
            return NDIS_STATUS_FAILURE;
        }
        /*
         * To this point we do not have GRE hardware offloading.
         * Apply defined checksums
         */
        curNb = NET_BUFFER_LIST_FIRST_NB(*newNbl);
        curMdl = NET_BUFFER_CURRENT_MDL(curNb);
        bufferStart = (PUINT8)MmGetSystemAddressForMdlSafe(curMdl,
                                                           LowPagePriority);
        if (!bufferStart) {
            status = NDIS_STATUS_RESOURCES;
            goto ret_error;
        }

        NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
        csumInfo.Value = NET_BUFFER_LIST_INFO(curNbl,
                                              TcpIpChecksumNetBufferListInfo);

        bufferStart += NET_BUFFER_CURRENT_MDL_OFFSET(curNb);

        if (layers->isIPv4) {
            IPHdr *ip = (IPHdr *)(bufferStart + layers->l3Offset);

            if (csumInfo.Transmit.IpHeaderChecksum) {
                ip->check = 0;
                ip->check = IPChecksum((UINT8 *)ip, 4 * ip->ihl, 0);
            }

            if (layers->isTcp && csumInfo.Transmit.TcpChecksum) {
                UINT16 csumLength = (UINT16)(packetLength - layers->l4Offset);
                TCPHdr *tcp = (TCPHdr *)(bufferStart + layers->l4Offset);
                tcp->check = IPPseudoChecksum(&ip->saddr, &ip->daddr,
                                              IPPROTO_TCP, csumLength);
                tcp->check = CalculateChecksumNB(curNb, csumLength,
                                                 (UINT32)(layers->l4Offset));
            } else if (layers->isUdp && csumInfo.Transmit.UdpChecksum) {
                UINT16 csumLength = (UINT16)(packetLength - layers->l4Offset);
                UDPHdr *udp = (UDPHdr *)((PCHAR)ip + sizeof *ip);
                udp->check = IPPseudoChecksum(&ip->saddr, &ip->daddr,
                                              IPPROTO_UDP, csumLength);
                udp->check = CalculateChecksumNB(curNb, csumLength,
                                                 (UINT32)(layers->l4Offset));
            }
        } else if (layers->isIPv6) {
            IPv6Hdr *ip = (IPv6Hdr *)(bufferStart + layers->l3Offset);

            if (layers->isTcp && csumInfo.Transmit.TcpChecksum) {
                UINT16 csumLength = (UINT16)(packetLength - layers->l4Offset);
                TCPHdr *tcp = (TCPHdr *)(bufferStart + layers->l4Offset);
                tcp->check = IPv6PseudoChecksum((UINT32 *) &ip->saddr,
                                                (UINT32 *) &ip->daddr,
                                                IPPROTO_TCP, csumLength);
                tcp->check = CalculateChecksumNB(curNb, csumLength,
                                                 (UINT32)(layers->l4Offset));
            } else if (layers->isUdp && csumInfo.Transmit.UdpChecksum) {
                UINT16 csumLength = (UINT16)(packetLength - layers->l4Offset);
                UDPHdr *udp = (UDPHdr *)((PCHAR)ip + sizeof *ip);
                udp->check = IPv6PseudoChecksum((UINT32 *) &ip->saddr,
                                                (UINT32 *) &ip->daddr,
                                                IPPROTO_UDP, csumLength);
                udp->check = CalculateChecksumNB(curNb, csumLength,
                                                 (UINT32)(layers->l4Offset));
            }
        }
        /* Clear out TcpIpChecksumNetBufferListInfo flag */
        NET_BUFFER_LIST_INFO(*newNbl, TcpIpChecksumNetBufferListInfo) = 0;
    }

    curNbl = *newNbl;
    for (curNb = NET_BUFFER_LIST_FIRST_NB(curNbl); curNb != NULL;
         curNb = curNb->Next) {
#if DBG
        counterHeadRoom = headRoom;
#endif
        status = NdisRetreatNetBufferDataStart(curNb, headRoom, 0, NULL);
        if (status != NDIS_STATUS_SUCCESS) {
            goto ret_error;
        }

        curMdl = NET_BUFFER_CURRENT_MDL(curNb);
        bufferStart = (PUINT8)MmGetSystemAddressForMdlSafe(curMdl,
                                                           LowPagePriority);
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
        ASSERT(((PCHAR)&fwdInfo->dstMacAddr + sizeof fwdInfo->dstMacAddr) ==
               (PCHAR)&fwdInfo->srcMacAddr);
        NdisMoveMemory(ethHdr->Destination, fwdInfo->dstMacAddr,
                       sizeof ethHdr->Destination + sizeof ethHdr->Source);
        ethHdr->Type = htons(ETH_TYPE_IPV4);
#if DBG
        counterHeadRoom -= sizeof *ethHdr;
#endif

        /* IP header */
        ipHdr = (IPHdr *)((PCHAR)ethHdr + sizeof *ethHdr);

        ipHdr->ihl = sizeof *ipHdr / 4;
        ipHdr->version = IPPROTO_IPV4;
        ipHdr->tos = tunKey->tos;
        ipHdr->tot_len = htons(NET_BUFFER_DATA_LENGTH(curNb) - sizeof *ethHdr);
        ipHdr->id = (uint16)atomic_add64(&vportGre->ipId,
                                         NET_BUFFER_DATA_LENGTH(curNb));
        ipHdr->frag_off = (tunKey->flags & OVS_TNL_F_DONT_FRAGMENT) ?
                          IP_DF_NBO : 0;
        ipHdr->ttl = tunKey->ttl ? tunKey->ttl : 64;
        ipHdr->protocol = IPPROTO_GRE;
        ASSERT(tunKey->dst == fwdInfo->dstIpAddr);
        ASSERT(tunKey->src == fwdInfo->srcIpAddr || tunKey->src == 0);
        ipHdr->saddr = fwdInfo->srcIpAddr;
        ipHdr->daddr = fwdInfo->dstIpAddr;

        ipHdr->check = 0;
        ipHdr->check = IPChecksum((UINT8 *)ipHdr, sizeof *ipHdr, 0);
#if DBG
        counterHeadRoom -= sizeof *ipHdr;
#endif

        /* GRE header */
        greHdr = (GREHdr *)((PCHAR)ipHdr + sizeof *ipHdr);
        greHdr->flags = OvsTunnelFlagsToGreFlags(tunKey->flags);
        greHdr->protocolType = GRE_NET_TEB;
#if DBG
        counterHeadRoom -= sizeof *greHdr;
#endif

        PCHAR currentOffset = (PCHAR)greHdr + sizeof *greHdr;

        if (tunKey->flags & OVS_TNL_F_CSUM) {
            RtlZeroMemory(currentOffset, 4);
            currentOffset += 4;
#if DBG
            counterHeadRoom -= 4;
#endif
        }

        if (tunKey->flags & OVS_TNL_F_KEY) {
            RtlZeroMemory(currentOffset, 4);
            UINT32 key = (tunKey->tunnelId >> 32);
            RtlCopyMemory(currentOffset, &key, sizeof key);
            currentOffset += 4;
#if DBG
            counterHeadRoom -= 4;
#endif
        }

#if DBG
        ASSERT(counterHeadRoom == 0);
#endif

    }
    return STATUS_SUCCESS;

ret_error:
    OvsCompleteNBL(switchContext, *newNbl, TRUE);
    *newNbl = NULL;
    return status;
}

NDIS_STATUS
OvsDecapGre(POVS_SWITCH_CONTEXT switchContext,
            PNET_BUFFER_LIST curNbl,
            OvsIPv4TunnelKey *tunKey,
            PNET_BUFFER_LIST *newNbl)
{
    PNET_BUFFER curNb;
    PMDL curMdl;
    EthHdr *ethHdr;
    IPHdr *ipHdr;
    GREHdr *greHdr;
    UINT32 tunnelSize = 0, packetLength = 0;
    UINT32 headRoom = 0;
    PUINT8 bufferStart;
    NDIS_STATUS status;

    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    packetLength = NET_BUFFER_DATA_LENGTH(curNb);
    tunnelSize = GreTunHdrSize(tunKey->flags);
    if (packetLength <= tunnelSize) {
        return NDIS_STATUS_INVALID_LENGTH;
    }

    /*
     * Create a copy of the NBL so that we have all the headers in one MDL.
     */
    *newNbl = OvsPartialCopyNBL(switchContext, curNbl,
                                tunnelSize + OVS_DEFAULT_COPY_SIZE, 0,
                                TRUE /*copy NBL info */);

    if (*newNbl == NULL) {
        return NDIS_STATUS_RESOURCES;
    }

    curNbl = *newNbl;
    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    bufferStart = (PUINT8)MmGetSystemAddressForMdlSafe(curMdl, LowPagePriority) +
                  NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    if (!bufferStart) {
        status = NDIS_STATUS_RESOURCES;
        goto dropNbl;
    }

    ethHdr = (EthHdr *)bufferStart;
    headRoom += sizeof *ethHdr;

    ipHdr = (IPHdr *)((PCHAR)ethHdr + sizeof *ethHdr);
    tunKey->src = ipHdr->saddr;
    tunKey->dst = ipHdr->daddr;
    tunKey->tos = ipHdr->tos;
    tunKey->ttl = ipHdr->ttl;
    tunKey->pad = 0;
    headRoom += sizeof *ipHdr;

    greHdr = (GREHdr *)((PCHAR)ipHdr + sizeof *ipHdr);
    headRoom += sizeof *greHdr;

    /* Validate if GRE header protocol type. */
    if (greHdr->protocolType != GRE_NET_TEB) {
        status = STATUS_NDIS_INVALID_PACKET;
        goto dropNbl;
    }

    PCHAR currentOffset = (PCHAR)greHdr + sizeof *greHdr;

    if (greHdr->flags & GRE_CSUM) {
        tunKey->flags |= OVS_TNL_F_CSUM;
        currentOffset += 4;
        headRoom += 4;
    }

    if (greHdr->flags & GRE_KEY) {
        tunKey->flags |= OVS_TNL_F_KEY;
        UINT32 key = 0;
        RtlCopyMemory(&key, currentOffset, 4);
        tunKey->tunnelId = (UINT64)key << 32;
        currentOffset += 4;
        headRoom += 4;
    }

    /* Clear out the receive flag for the inner packet. */
    NET_BUFFER_LIST_INFO(curNbl, TcpIpChecksumNetBufferListInfo) = 0;
    NdisAdvanceNetBufferDataStart(curNb, GreTunHdrSize(tunKey->flags), FALSE,
                                  NULL);
    ASSERT(headRoom == GreTunHdrSize(tunKey->flags));
    return NDIS_STATUS_SUCCESS;

dropNbl:
    OvsCompleteNBL(switchContext, *newNbl, TRUE);
    *newNbl = NULL;
    return status;
}
