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

#include "precomp.h"

#include "Atomic.h"
#include "Debug.h"
#include "Flow.h"
#include "IpHelper.h"
#include "Jhash.h"
#include "NetProto.h"
#include "Offload.h"
#include "PacketIO.h"
#include "PacketParser.h"
#include "Geneve.h"
#include "Switch.h"
#include "User.h"
#include "Util.h"
#include "Vport.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_GENEVE


NTSTATUS OvsInitGeneveTunnel(POVS_VPORT_ENTRY vport,
                             UINT16 udpDestPort)
{
    POVS_GENEVE_VPORT genevePort;

    genevePort = (POVS_GENEVE_VPORT)
        OvsAllocateMemoryWithTag(sizeof(*genevePort), OVS_GENEVE_POOL_TAG);
    if (!genevePort) {
        OVS_LOG_ERROR("Insufficient memory, can't allocate GENEVE_VPORT");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(genevePort, sizeof(*genevePort));
    genevePort->dstPort = udpDestPort;
    vport->priv = (PVOID) genevePort;
    return STATUS_SUCCESS;
}

VOID
OvsCleanupGeneveTunnel(POVS_VPORT_ENTRY vport)
{
    if (vport->ovsType != OVS_VPORT_TYPE_GENEVE ||
        vport->priv == NULL) {
        return;
    }

    OvsFreeMemoryWithTag(vport->priv, OVS_GENEVE_POOL_TAG);
    vport->priv = NULL;
}

NDIS_STATUS OvsEncapGeneve(POVS_VPORT_ENTRY vport,
                           PNET_BUFFER_LIST curNbl,
                           OvsIPv4TunnelKey *tunKey,
                           POVS_SWITCH_CONTEXT switchContext,
                           POVS_PACKET_HDR_INFO layers,
                           PNET_BUFFER_LIST *newNbl,
                           POVS_FWD_INFO switchFwdInfo)
{
    NTSTATUS status;
    OVS_FWD_INFO fwdInfo;
    PNET_BUFFER curNb;
    PMDL curMdl;
    PUINT8 bufferStart;
    EthHdr *ethHdr;
    IPHdr *ipHdr;
    UDPHdr *udpHdr;
    GeneveHdr *geneveHdr;
    GeneveOptionHdr *optHdr;
    POVS_GENEVE_VPORT vportGeneve;
    UINT32 headRoom = OvsGetGeneveTunHdrMinSize() + tunKey->tunOptLen;
    UINT32 packetLength;
    ULONG mss = 0;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;

    status = OvsLookupIPFwdInfo(tunKey->src, tunKey->dst, &fwdInfo);
    if (status != STATUS_SUCCESS) {
        OvsFwdIPHelperRequest(NULL, 0, tunKey, NULL, NULL, NULL);
        // return NDIS_STATUS_PENDING;
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

    vportGeneve = (POVS_GENEVE_VPORT) GetOvsVportPriv(vport);
    ASSERT(vportGeneve != NULL);

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
        NdisMoveMemory(ethHdr->Destination, fwdInfo.dstMacAddr,
                       sizeof ethHdr->Destination);
        NdisMoveMemory(ethHdr->Source, fwdInfo.srcMacAddr,
                       sizeof ethHdr->Source);
        ethHdr->Type = htons(ETH_TYPE_IPV4);

        /* IP header */
        ipHdr = (IPHdr *)((PCHAR)ethHdr + sizeof *ethHdr);

        ipHdr->ihl = sizeof *ipHdr / 4;
        ipHdr->version = IPPROTO_IPV4;
        ipHdr->tos = tunKey->tos;
        ipHdr->tot_len = htons(NET_BUFFER_DATA_LENGTH(curNb) - sizeof *ethHdr);
        ipHdr->id = (uint16)atomic_add64(&vportGeneve->ipId,
                                         NET_BUFFER_DATA_LENGTH(curNb));
        ipHdr->frag_off = (tunKey->flags & OVS_TNL_F_DONT_FRAGMENT) ?
                          IP_DF_NBO : 0;
        ipHdr->ttl = tunKey->ttl ? tunKey->ttl : GENEVE_DEFAULT_TTL;
        ipHdr->protocol = IPPROTO_UDP;
        ASSERT(tunKey->dst == fwdInfo.dstIpAddr);
        ASSERT(tunKey->src == fwdInfo.srcIpAddr || tunKey->src == 0);
        ipHdr->saddr = fwdInfo.srcIpAddr;
        ipHdr->daddr = fwdInfo.dstIpAddr;
        ipHdr->check = 0;

        /* UDP header */
        udpHdr = (UDPHdr *)((PCHAR)ipHdr + sizeof *ipHdr);
        udpHdr->source = htons(tunKey->flow_hash | MAXINT16);
        udpHdr->dest = tunKey->dst_port ? tunKey->dst_port :
                                          htons(vportGeneve->dstPort);
        udpHdr->len = htons(NET_BUFFER_DATA_LENGTH(curNb) - headRoom +
                            sizeof *udpHdr + sizeof *geneveHdr +
                            tunKey->tunOptLen);
        if (tunKey->flags & OVS_TNL_F_CSUM) {
            UINT16 udpChksumLen = (UINT16) NET_BUFFER_DATA_LENGTH(curNb) -
                                   sizeof *ipHdr - sizeof *ethHdr;
            udpHdr->check = IPPseudoChecksum(&ipHdr->saddr, &ipHdr->daddr,
                                             IPPROTO_UDP, udpChksumLen);
        } else {
            udpHdr->check = 0;
        }
        /* Geneve header */
        geneveHdr = (GeneveHdr *)((PCHAR)udpHdr + sizeof *udpHdr);
        geneveHdr->version = GENEVE_VER;
        geneveHdr->optLen = tunKey->tunOptLen / 4;
        geneveHdr->oam = !!(tunKey->flags & OVS_TNL_F_OAM);
        geneveHdr->critical = !!(tunKey->flags & OVS_TNL_F_CRT_OPT);
        geneveHdr->reserved1 = 0;
        geneveHdr->protocol = ETH_P_TEB_NBO;
        geneveHdr->vni = GENEVE_TUNNELID_TO_VNI(tunKey->tunnelId);
        geneveHdr->reserved2 = 0;

        /* Geneve header options */
        optHdr = (GeneveOptionHdr *)(geneveHdr + 1);
        memcpy(optHdr, TunnelKeyGetOptions(tunKey), tunKey->tunOptLen);

        csumInfo.Value = 0;
        csumInfo.Transmit.IpHeaderChecksum = 1;
        csumInfo.Transmit.IsIPv4 = 1;
        if (tunKey->flags & OVS_TNL_F_CSUM) {
            csumInfo.Transmit.UdpChecksum = 1;
        }
        NET_BUFFER_LIST_INFO(curNbl,
                             TcpIpChecksumNetBufferListInfo) = csumInfo.Value;
    }
    return STATUS_SUCCESS;

ret_error:
    OvsCompleteNBL(switchContext, *newNbl, TRUE);
    *newNbl = NULL;
    return status;
}

NDIS_STATUS OvsDecapGeneve(POVS_SWITCH_CONTEXT switchContext,
                           PNET_BUFFER_LIST curNbl,
                           OvsIPv4TunnelKey *tunKey,
                           PNET_BUFFER_LIST *newNbl)
{
    PNET_BUFFER curNb;
    PMDL curMdl;
    EthHdr *ethHdr;
    IPHdr *ipHdr;
    UDPHdr *udpHdr;
    GeneveHdr *geneveHdr;
    UINT32 tunnelSize;
    UINT32 packetLength;
    PUINT8 bufferStart;
    PVOID optStart;
    NDIS_STATUS status;
    OVS_PACKET_HDR_INFO layers = { 0 };

    status = OvsExtractLayers(curNbl, &layers);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    /* Check the length of the UDP payload */
    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    tunnelSize = OvsGetGeneveTunHdrSizeFromLayers(&layers);
    packetLength = NET_BUFFER_DATA_LENGTH(curNb);
    if (packetLength <= tunnelSize) {
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
        status = OvsCalculateUDPChecksum(curNbl, curNb, ipHdr, udpHdr,
                                         packetLength, &layers);
        tunKey->flags |= OVS_TNL_F_CSUM;
        if (status != NDIS_STATUS_SUCCESS) {
            goto dropNbl;
        }
    }

    geneveHdr = (GeneveHdr *)((PCHAR)udpHdr + sizeof *udpHdr);
    if (geneveHdr->protocol != ETH_P_TEB_NBO) {
        status = STATUS_NDIS_INVALID_PACKET;
        goto dropNbl;
    }
    /* Update tunnelKey flags. */
    tunKey->flags = OVS_TNL_F_KEY | (geneveHdr->oam ? OVS_TNL_F_OAM : 0) |
                    (geneveHdr->critical ? OVS_TNL_F_CRT_OPT : 0);

    tunKey->tunnelId = GENEVE_VNI_TO_TUNNELID(geneveHdr->vni);
    tunKey->tunOptLen = (uint8)geneveHdr->optLen * 4;
    if (tunKey->tunOptLen > TUN_OPT_MAX_LEN ||
        packetLength < tunnelSize + tunKey->tunOptLen) {
        status = NDIS_STATUS_INVALID_LENGTH;
        goto dropNbl;
    }
    /* Clear out the receive flag for the inner packet. */
    NET_BUFFER_LIST_INFO(curNbl, TcpIpChecksumNetBufferListInfo) = 0;

    NdisAdvanceNetBufferDataStart(curNb, tunnelSize, FALSE, NULL);
    if (tunKey->tunOptLen > 0) {
        optStart = NdisGetDataBuffer(curNb, tunKey->tunOptLen,
                                     TunnelKeyGetOptions(tunKey), 1, 0);

        /* If data is contiguous in the buffer, NdisGetDataBuffer will not copy
           data to the storage. Manual copy is needed. */
        if (optStart != TunnelKeyGetOptions(tunKey)) {
            memcpy(TunnelKeyGetOptions(tunKey), optStart, tunKey->tunOptLen);
        }
        NdisAdvanceNetBufferDataStart(curNb, tunKey->tunOptLen, FALSE, NULL);
        tunKey->flags |= OVS_TNL_F_GENEVE_OPT;
    }

    return NDIS_STATUS_SUCCESS;

dropNbl:
    OvsCompleteNBL(switchContext, *newNbl, TRUE);
    *newNbl = NULL;
    return status;
}
