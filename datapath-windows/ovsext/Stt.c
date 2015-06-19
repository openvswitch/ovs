/*
 * Copyright (c) 2015 VMware, Inc.
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
#include "NetProto.h"
#include "Switch.h"
#include "Vport.h"
#include "Flow.h"
#include "Stt.h"
#include "IpHelper.h"
#include "Checksum.h"
#include "User.h"
#include "PacketIO.h"
#include "Flow.h"
#include "PacketParser.h"
#include "Atomic.h"
#include "Util.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_STT
#include "Debug.h"

static NDIS_STATUS
OvsDoEncapStt(POVS_VPORT_ENTRY vport, PNET_BUFFER_LIST curNbl,
              const OvsIPv4TunnelKey *tunKey,
              const POVS_FWD_INFO fwdInfo,
              POVS_PACKET_HDR_INFO layers,
              POVS_SWITCH_CONTEXT switchContext,
              PNET_BUFFER_LIST *newNbl);

/*
 * --------------------------------------------------------------------------
 * OvsInitSttTunnel --
 *    Initialize STT tunnel module.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsInitSttTunnel(POVS_VPORT_ENTRY vport,
                 UINT16 tcpDestPort)
{
    POVS_STT_VPORT sttPort;

    sttPort = (POVS_STT_VPORT) OvsAllocateMemoryWithTag(sizeof(*sttPort),
                                                        OVS_STT_POOL_TAG);
    if (!sttPort) {
        OVS_LOG_ERROR("Insufficient memory, can't allocate STT_VPORT");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(sttPort, sizeof(*sttPort));
    sttPort->dstPort = tcpDestPort;
    vport->priv = (PVOID) sttPort;
    return STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsCleanupSttTunnel --
 *    Cleanup STT Tunnel module.
 * --------------------------------------------------------------------------
 */
void
OvsCleanupSttTunnel(POVS_VPORT_ENTRY vport)
{
    if (vport->ovsType != OVS_VPORT_TYPE_STT ||
        vport->priv == NULL) {
        return;
    }

    OvsFreeMemoryWithTag(vport->priv, OVS_STT_POOL_TAG);
    vport->priv = NULL;
}

/*
 * --------------------------------------------------------------------------
 * OvsEncapStt --
 *     Encapsulates a packet with an STT header.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsEncapStt(POVS_VPORT_ENTRY vport,
            PNET_BUFFER_LIST curNbl,
            OvsIPv4TunnelKey *tunKey,
            POVS_SWITCH_CONTEXT switchContext,
            POVS_PACKET_HDR_INFO layers,
            PNET_BUFFER_LIST *newNbl)
{
    OVS_FWD_INFO fwdInfo;
    NDIS_STATUS status;

    UNREFERENCED_PARAMETER(switchContext);
    status = OvsLookupIPFwdInfo(tunKey->dst, &fwdInfo);
    if (status != STATUS_SUCCESS) {
        OvsFwdIPHelperRequest(NULL, 0, tunKey, NULL, NULL, NULL);
        /*
         * XXX This case where the ARP table is not populated is
         * currently not handled
         */
        return NDIS_STATUS_FAILURE;
    }

    status = OvsDoEncapStt(vport, curNbl, tunKey, &fwdInfo, layers,
                           switchContext, newNbl);
    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsDoEncapStt --
 *    Internal utility function which actually does the STT encap.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsDoEncapStt(POVS_VPORT_ENTRY vport,
              PNET_BUFFER_LIST curNbl,
              const OvsIPv4TunnelKey *tunKey,
              const POVS_FWD_INFO fwdInfo,
              POVS_PACKET_HDR_INFO layers,
              POVS_SWITCH_CONTEXT switchContext,
              PNET_BUFFER_LIST *newNbl)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PMDL curMdl = NULL;
    PNET_BUFFER curNb;
    PUINT8 buf = NULL;
    EthHdr *outerEthHdr;
    IPHdr *outerIpHdr;
    TCPHdr *outerTcpHdr;
    SttHdr *sttHdr;
    UINT32 innerFrameLen, ipTotalLen;
    POVS_STT_VPORT vportStt;
    UINT32 headRoom = OvsGetSttTunHdrSize();
    UINT32 tcpChksumLen;

    UNREFERENCED_PARAMETER(layers);

    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    if (layers->isTcp) {
        NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO lsoInfo;

        lsoInfo.Value = NET_BUFFER_LIST_INFO(curNbl,
                TcpLargeSendNetBufferListInfo);
        if (lsoInfo.LsoV1Transmit.MSS) {
            /* XXX We don't handle LSO yet */
            OVS_LOG_ERROR("LSO on STT is not supported");
            return NDIS_STATUS_FAILURE;
        }
    }

    vportStt = (POVS_STT_VPORT) GetOvsVportPriv(vport);
    ASSERT(vportStt);

    *newNbl = OvsPartialCopyNBL(switchContext, curNbl, 0, headRoom,
                                FALSE /*copy NblInfo*/);
    if (*newNbl == NULL) {
        OVS_LOG_ERROR("Unable to copy NBL");
        return NDIS_STATUS_FAILURE;
    }

    curNbl = *newNbl;
    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    /* NB Chain should be split before */
    ASSERT(NET_BUFFER_NEXT_NB(curNb) == NULL);

    innerFrameLen = NET_BUFFER_DATA_LENGTH(curNb);
    /*
     * External port can't be removed as we hold the dispatch lock
     * We also check if the external port was removed beforecalling
     * port encapsulation functions
     */
    if (innerFrameLen > OvsGetExternalMtu(switchContext) - headRoom) {
        OVS_LOG_ERROR("Packet too large (size %d, mtu %d). Can't encapsulate",
                innerFrameLen, OvsGetExternalMtu(switchContext));
        status = NDIS_STATUS_FAILURE;
        goto ret_error;
    }

    status = NdisRetreatNetBufferDataStart(curNb, headRoom, 0, NULL);
    if (status != NDIS_STATUS_SUCCESS) {
        ASSERT(!"Unable to NdisRetreatNetBufferDataStart(headroom)");
        OVS_LOG_ERROR("Unable to NdisRetreatNetBufferDataStart(headroom)");
        goto ret_error;
    }

    /*
     * Make sure that the headroom for the tunnel header is continguous in
     * memory.
     */
    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    ASSERT((int) (MmGetMdlByteCount(curMdl) - NET_BUFFER_CURRENT_MDL_OFFSET(curNb))
                >= (int) headRoom);

    buf = (PUINT8) MmGetSystemAddressForMdlSafe(curMdl, LowPagePriority);
    if (!buf) {
        ASSERT(!"MmGetSystemAddressForMdlSafe failed");
        OVS_LOG_ERROR("MmGetSystemAddressForMdlSafe failed");
        status = NDIS_STATUS_RESOURCES;
        goto ret_error;
    }

    buf += NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    outerEthHdr = (EthHdr *)buf;
    outerIpHdr = (IPHdr *) (outerEthHdr + 1);
    outerTcpHdr = (TCPHdr *) (outerIpHdr + 1);
    sttHdr = (SttHdr *) (outerTcpHdr + 1);

    /* L2 header */
    ASSERT(((PCHAR)&fwdInfo->dstMacAddr + sizeof fwdInfo->dstMacAddr) ==
            (PCHAR)&fwdInfo->srcMacAddr);
    NdisMoveMemory(outerEthHdr->Destination, fwdInfo->dstMacAddr,
                    sizeof outerEthHdr->Destination + sizeof outerEthHdr->Source);
    outerEthHdr->Type = htons(ETH_TYPE_IPV4);

    /* L3 header */
    outerIpHdr->ihl = sizeof(IPHdr) >> 2;
    outerIpHdr->version = IPPROTO_IPV4;
    outerIpHdr->tos = tunKey->tos;

    ipTotalLen = sizeof(IPHdr) + sizeof(TCPHdr) + STT_HDR_LEN + innerFrameLen;
    outerIpHdr->tot_len = htons(ipTotalLen);
    ASSERT(ipTotalLen < 65536);

    outerIpHdr->id = (uint16) atomic_add64(&vportStt->ipId, innerFrameLen);
    outerIpHdr->frag_off = (tunKey->flags & OVS_TNL_F_DONT_FRAGMENT) ?
                           IP_DF_NBO : 0;
    outerIpHdr->ttl = tunKey->ttl? tunKey->ttl : 64;
    outerIpHdr->protocol = IPPROTO_TCP;
    outerIpHdr->check = 0;
    outerIpHdr->saddr = fwdInfo->srcIpAddr;
    outerIpHdr->daddr = tunKey->dst;
    outerIpHdr->check = IPChecksum((uint8 *)outerIpHdr, sizeof *outerIpHdr, 0);

    /* L4 header */
    RtlZeroMemory(outerTcpHdr, sizeof *outerTcpHdr);
    outerTcpHdr->source = htons(tunKey->flow_hash | 32768);
    outerTcpHdr->dest = htons(vportStt->dstPort);
    outerTcpHdr->seq = htonl((STT_HDR_LEN + innerFrameLen) <<
                             STT_SEQ_LEN_SHIFT);
    outerTcpHdr->ack_seq = htonl(atomic_inc64(&vportStt->ackNo));
    outerTcpHdr->doff = sizeof(TCPHdr) >> 2;
    outerTcpHdr->psh = 1;
    outerTcpHdr->ack = 1;
    outerTcpHdr->window = (uint16) ~0;

    /* Calculate pseudo header chksum */
    tcpChksumLen = sizeof(TCPHdr) + STT_HDR_LEN + innerFrameLen;
    ASSERT(tcpChksumLen < 65535);
    outerTcpHdr->check = IPPseudoChecksum(&fwdInfo->srcIpAddr,(uint32 *) &tunKey->dst,
                                          IPPROTO_TCP, (uint16) tcpChksumLen);
    sttHdr->version = 0;

    /* XXX need to peek into the inner packet, hard code for now */
    sttHdr->flags = STT_PROTO_IPV4;
    sttHdr->l4Offset = 0;

    sttHdr->reserved = 0;
    /* XXX Used for large TCP packets.Not sure how it is used, clarify */
    sttHdr->mss = 0;
    sttHdr->vlanTCI = 0;
    sttHdr->key = tunKey->tunnelId;
    /* Zero out stt padding */
    *(uint16 *)(sttHdr + 1) = 0;

    /* Calculate software tcp checksum */
    outerTcpHdr->check = CalculateChecksumNB(curNb, (uint16) tcpChksumLen,
                                             sizeof(EthHdr) + sizeof(IPHdr));
    if (outerTcpHdr->check == 0) {
        status = NDIS_STATUS_FAILURE;
        goto ret_error;
    }

    return STATUS_SUCCESS;

ret_error:
    OvsCompleteNBL(switchContext, *newNbl, TRUE);
    *newNbl = NULL;
    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsDecapStt --
 *     Decapsulates an STT packet.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsDecapStt(POVS_SWITCH_CONTEXT switchContext,
            PNET_BUFFER_LIST curNbl,
            OvsIPv4TunnelKey *tunKey,
            PNET_BUFFER_LIST *newNbl)
{
    NDIS_STATUS status = NDIS_STATUS_FAILURE;
    PNET_BUFFER curNb;
    IPHdr *ipHdr;
    char *ipBuf[sizeof(IPHdr)];
    SttHdr *sttHdr;
    char *sttBuf[STT_HDR_LEN];
    UINT32 advanceCnt, hdrLen;

    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    ASSERT(NET_BUFFER_NEXT_NB(curNb) == NULL);

    if (NET_BUFFER_DATA_LENGTH(curNb) < OvsGetSttTunHdrSize()) {
        OVS_LOG_ERROR("Packet length received is less than the tunnel header:"
            " %d<%d\n", NET_BUFFER_DATA_LENGTH(curNb), OvsGetSttTunHdrSize());
        return NDIS_STATUS_INVALID_LENGTH;
    }

    /* Skip Eth header */
    hdrLen = sizeof(EthHdr);
    NdisAdvanceNetBufferDataStart(curNb, hdrLen, FALSE, NULL);
    advanceCnt = hdrLen;

    ipHdr = NdisGetDataBuffer(curNb, sizeof *ipHdr, (PVOID) &ipBuf,
                                                    1 /*no align*/, 0);
    ASSERT(ipHdr);

    /* Skip IP & TCP headers */
    hdrLen = sizeof(IPHdr) + sizeof(TCPHdr),
    NdisAdvanceNetBufferDataStart(curNb, hdrLen, FALSE, NULL);
    advanceCnt += hdrLen;

    /* STT Header */
    sttHdr = NdisGetDataBuffer(curNb, sizeof *sttHdr, (PVOID) &sttBuf,
                                                    1 /*no align*/, 0);
    ASSERT(sttHdr);

    /* Initialize the tunnel key */
    tunKey->dst = ipHdr->daddr;
    tunKey->src = ipHdr->saddr;
    tunKey->tunnelId = sttHdr->key;
    tunKey->flags = (OVS_TNL_F_CSUM | OVS_TNL_F_KEY);
    tunKey->tos = ipHdr->tos;
    tunKey->ttl = ipHdr->ttl;
    tunKey->pad = 0;

    /* Skip stt header, DataOffset points to inner pkt now. */
    hdrLen = STT_HDR_LEN;
    NdisAdvanceNetBufferDataStart(curNb, hdrLen, FALSE, NULL);
    advanceCnt += hdrLen;

    *newNbl = OvsPartialCopyNBL(switchContext, curNbl, OVS_DEFAULT_COPY_SIZE,
                                0, FALSE /*copy NBL info*/);

    ASSERT(advanceCnt == OvsGetSttTunHdrSize());
    status = NdisRetreatNetBufferDataStart(curNb, advanceCnt, 0, NULL);

    if (*newNbl == NULL) {
        OVS_LOG_ERROR("OvsDecapStt: Unable to allocate a new cloned NBL");
        status = NDIS_STATUS_RESOURCES;
    }

    return status;
}
