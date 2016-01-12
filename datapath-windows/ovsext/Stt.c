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

#include "Atomic.h"
#include "Checksum.h"
#include "Flow.h"
#include "IpHelper.h"
#include "NetProto.h"
#include "PacketIO.h"
#include "PacketParser.h"
#include "Stt.h"
#include "Switch.h"
#include "User.h"
#include "Util.h"
#include "Vport.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_STT
#include "Debug.h"
#include "Jhash.h"

KSTART_ROUTINE OvsSttDefragCleaner;
static PLIST_ENTRY OvsSttPktFragHash;
static NDIS_SPIN_LOCK OvsSttSpinLock;
static OVS_STT_THREAD_CTX sttDefragThreadCtx;

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
    PUINT8 bufferStart;
    ULONG mss = 0;
    NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO lsoInfo;

    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);

    /* Verify if inner checksum is verified */
    BOOLEAN innerChecksumVerified = FALSE;
    BOOLEAN innerPartialChecksum = FALSE;

    if (layers->isTcp) {
        lsoInfo.Value = NET_BUFFER_LIST_INFO(curNbl,
                TcpLargeSendNetBufferListInfo);

        switch (lsoInfo.Transmit.Type) {
            case NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE:
                mss = lsoInfo.LsoV1Transmit.MSS;
                break;
            case NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE:
                mss = lsoInfo.LsoV2Transmit.MSS;
                break;
            default:
                OVS_LOG_ERROR("Unknown LSO transmit type:%d",
                              lsoInfo.Transmit.Type);
        }
    }

    vportStt = (POVS_STT_VPORT) GetOvsVportPriv(vport);
    ASSERT(vportStt);

    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
    csumInfo.Value = NET_BUFFER_LIST_INFO(curNbl,
                                          TcpIpChecksumNetBufferListInfo);
    *newNbl = OvsPartialCopyNBL(switchContext, curNbl, 0, headRoom,
                                FALSE /*copy NblInfo*/);
    if (*newNbl == NULL) {
        OVS_LOG_ERROR("Unable to copy NBL");
        return NDIS_STATUS_FAILURE;
    }

    curNbl = *newNbl;
    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    /* NB Chain should be split before */
    ASSERT(NET_BUFFER_NEXT_NB(curNb) == NULL);
    innerFrameLen = NET_BUFFER_DATA_LENGTH(curNb);

    bufferStart = (PUINT8)MmGetSystemAddressForMdlSafe(curMdl,
                                                       LowPagePriority);
    bufferStart += NET_BUFFER_CURRENT_MDL_OFFSET(curNb);

    if (layers->isIPv4) {
        IPHdr *ip = (IPHdr *)(bufferStart + layers->l3Offset);
        if (!ip->tot_len) {
            ip->tot_len = htons(innerFrameLen - sizeof(EthHdr));
        }
        if (!ip->check) {
            ip->check = IPChecksum((UINT8 *)ip, ip->ihl * 4, 0);
        }
    }

    if (layers->isTcp) {
        if (mss) {
            innerPartialChecksum = TRUE;
        } else {
            if (!csumInfo.Transmit.TcpChecksum) {
                innerChecksumVerified = TRUE;
            } else {
                innerPartialChecksum = TRUE;
            }
        }
    } else if (layers->isUdp) {
        if(!csumInfo.Transmit.UdpChecksum) {
            innerChecksumVerified = TRUE;
        } else {
            innerPartialChecksum = TRUE;
        }
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

    /* Set STT Header */
    sttHdr->flags = 0;
    if (innerPartialChecksum) {
        sttHdr->flags |= STT_CSUM_PARTIAL;
        if (layers->isIPv4) {
            sttHdr->flags |= STT_PROTO_IPV4;
        }
        if (layers->isTcp) {
            sttHdr->flags |= STT_PROTO_TCP;
        }
        sttHdr->l4Offset = (UINT8) layers->l4Offset;
        sttHdr->mss = (UINT16) htons(mss);
    } else if (innerChecksumVerified) {
        sttHdr->flags = STT_CSUM_VERIFIED;
        sttHdr->l4Offset = 0;
        sttHdr->mss = 0;
    }

    sttHdr->reserved = 0;
    sttHdr->vlanTCI = 0;
    sttHdr->key = tunKey->tunnelId;
    /* Zero out stt padding */
    *(uint16 *)(sttHdr + 1) = 0;

    /* Offload IP and TCP checksum */
    ULONG tcpHeaderOffset = sizeof *outerEthHdr +
                        outerIpHdr->ihl * 4;
    csumInfo.Value = 0;
    csumInfo.Transmit.IpHeaderChecksum = 1;
    csumInfo.Transmit.TcpChecksum = 1;
    csumInfo.Transmit.IsIPv4 = 1;
    csumInfo.Transmit.TcpHeaderOffset = tcpHeaderOffset;
    NET_BUFFER_LIST_INFO(curNbl,
                         TcpIpChecksumNetBufferListInfo) = csumInfo.Value;

    UINT32 encapMss = OvsGetExternalMtu(switchContext) - sizeof(IPHdr) - sizeof(TCPHdr);
    if (ipTotalLen > encapMss) {
        lsoInfo.Value = 0;
        lsoInfo.LsoV2Transmit.TcpHeaderOffset = tcpHeaderOffset;
        lsoInfo.LsoV2Transmit.MSS = encapMss;
        lsoInfo.LsoV2Transmit.Type = NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE;
        lsoInfo.LsoV2Transmit.IPVersion = NDIS_TCP_LARGE_SEND_OFFLOAD_IPv4;
        NET_BUFFER_LIST_INFO(curNbl,
                             TcpLargeSendNetBufferListInfo) = lsoInfo.Value;
    }

    return STATUS_SUCCESS;

ret_error:
    OvsCompleteNBL(switchContext, *newNbl, TRUE);
    *newNbl = NULL;
    return status;
}

/*
 *----------------------------------------------------------------------------
 * OvsValidateTCPChecksum
 *     Validate TCP checksum
 *----------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsValidateTCPChecksum(PNET_BUFFER_LIST curNbl, PNET_BUFFER curNb)
{
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
    csumInfo.Value = NET_BUFFER_LIST_INFO(curNbl,
                                          TcpIpChecksumNetBufferListInfo);

    /* Check if NIC has indicated TCP checksum failure */
    if (csumInfo.Receive.TcpChecksumFailed) {
        return NDIS_STATUS_INVALID_PACKET;
    }

    UINT16 checkSum;

    /* Check if TCP Checksum has been calculated by NIC */
    if (csumInfo.Receive.TcpChecksumSucceeded) {
        return NDIS_STATUS_SUCCESS;
    }

    EthHdr *eth = (EthHdr *)NdisGetDataBuffer(curNb, sizeof(EthHdr),
                                              NULL, 1, 0);

    if (eth->Type == ntohs(NDIS_ETH_TYPE_IPV4)) {
        IPHdr *ip = (IPHdr *)((PCHAR)eth + sizeof *eth);
        UINT32 l4Payload = ntohs(ip->tot_len) - ip->ihl * 4;
        TCPHdr *tcp = (TCPHdr *)((PCHAR)ip + ip->ihl * 4);
        checkSum = tcp->check;

        tcp->check = 0;
        tcp->check = IPPseudoChecksum(&ip->saddr, &ip->daddr,
                                      IPPROTO_TCP, (UINT16)l4Payload);
        tcp->check = CalculateChecksumNB(curNb, (UINT16)(l4Payload),
                                         sizeof(EthHdr) + ip->ihl * 4);
        if (checkSum != tcp->check) {
            return NDIS_STATUS_INVALID_PACKET;
        }
    } else {
        OVS_LOG_ERROR("IPv6 on STT is not supported");
        return NDIS_STATUS_INVALID_PACKET;
    }

    csumInfo.Receive.TcpChecksumSucceeded = 1;
    NET_BUFFER_LIST_INFO(curNbl,
                         TcpIpChecksumNetBufferListInfo) = csumInfo.Value;
    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsInitSttDefragmentation
 *     Initialize the components used by the stt lso defragmentation
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsInitSttDefragmentation()
{
    NTSTATUS status;
    HANDLE threadHandle = NULL;

    /* Init the sync-lock */
    NdisAllocateSpinLock(&OvsSttSpinLock);

    /* Init the Hash Buffer */
    OvsSttPktFragHash = OvsAllocateMemoryWithTag(sizeof(LIST_ENTRY)
                                                 * STT_HASH_TABLE_SIZE,
                                                 OVS_STT_POOL_TAG);
    if (OvsSttPktFragHash == NULL) {
        NdisFreeSpinLock(&OvsSttSpinLock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (int i = 0; i < STT_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&OvsSttPktFragHash[i]);
    }

    /* Init Defrag Cleanup Thread */
    KeInitializeEvent(&sttDefragThreadCtx.event, NotificationEvent, FALSE);
    status = PsCreateSystemThread(&threadHandle, SYNCHRONIZE, NULL, NULL,
                                  NULL, OvsSttDefragCleaner,
                                  &sttDefragThreadCtx);

    if (status != STATUS_SUCCESS) {
        OvsCleanupSttDefragmentation();
        return status;
    }

    ObReferenceObjectByHandle(threadHandle, SYNCHRONIZE, NULL, KernelMode,
                              &sttDefragThreadCtx.threadObject, NULL);
    ZwClose(threadHandle);
    threadHandle = NULL;
    return STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsCleanupSttDefragmentation
 *     Cleanup memory and thread that were spawned for STT LSO defragmentation
 *----------------------------------------------------------------------------
 */
VOID
OvsCleanupSttDefragmentation(VOID)
{
    NdisAcquireSpinLock(&OvsSttSpinLock);
    sttDefragThreadCtx.exit = 1;
    KeSetEvent(&sttDefragThreadCtx.event, 0, FALSE);
    NdisReleaseSpinLock(&OvsSttSpinLock);

    KeWaitForSingleObject(sttDefragThreadCtx.threadObject, Executive,
                          KernelMode, FALSE, NULL);
    ObDereferenceObject(sttDefragThreadCtx.threadObject);

    if (OvsSttPktFragHash) {
        OvsFreeMemoryWithTag(OvsSttPktFragHash, OVS_STT_POOL_TAG);
        OvsSttPktFragHash = NULL;
    }

    NdisFreeSpinLock(&OvsSttSpinLock);
}

/*
 *----------------------------------------------------------------------------
 * OvsSttDefragCleaner
 *     Runs periodically and cleans up the buffer to remove expired segments
 *----------------------------------------------------------------------------
 */
VOID
OvsSttDefragCleaner(PVOID data)
{
    POVS_STT_THREAD_CTX context = (POVS_STT_THREAD_CTX)data;
    PLIST_ENTRY link, next;
    POVS_STT_PKT_ENTRY entry;
    BOOLEAN success = TRUE;

    while (success) {
        NdisAcquireSpinLock(&OvsSttSpinLock);
        if (context->exit) {
            NdisReleaseSpinLock(&OvsSttSpinLock);
            break;
        }

        /* Set the timeout for the thread and cleanup */
        UINT64 currentTime, threadSleepTimeout;
        NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
        threadSleepTimeout = currentTime + STT_CLEANUP_INTERVAL;

        for (int i = 0; i < STT_HASH_TABLE_SIZE; i++) {
            LIST_FORALL_SAFE(&OvsSttPktFragHash[i], link, next) {
                entry = CONTAINING_RECORD(link, OVS_STT_PKT_ENTRY, link);
                if (entry->timeout < currentTime) {
                    RemoveEntryList(&entry->link);
                    OvsFreeMemoryWithTag(entry->packetBuf, OVS_STT_POOL_TAG);
                    OvsFreeMemoryWithTag(entry, OVS_STT_POOL_TAG);
                }
            }
        }

        NdisReleaseSpinLock(&OvsSttSpinLock);
        KeWaitForSingleObject(&context->event, Executive, KernelMode,
                              FALSE, (LARGE_INTEGER *)&threadSleepTimeout);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static OVS_STT_PKT_KEY
OvsGeneratePacketKey(IPHdr *ipHdr, TCPHdr *tcpHdr)
{
    OVS_STT_PKT_KEY key;
    key.sAddr = ipHdr->saddr;
    key.dAddr = ipHdr->daddr;
    key.ackSeq = ntohl(tcpHdr->ack_seq);
    return key;
}

static UINT32
OvsSttGetPktHash(OVS_STT_PKT_KEY *pktKey)
{
    UINT32 arr[3];
    arr[0] = pktKey->ackSeq;
    arr[1] = pktKey->dAddr;
    arr[2] = pktKey->sAddr;
    return OvsJhashWords(arr, 3, OVS_HASH_BASIS);
}

static VOID *
OvsLookupPktFrag(OVS_STT_PKT_KEY *pktKey, UINT32 hash)
{
    PLIST_ENTRY link;
    POVS_STT_PKT_ENTRY entry;

    LIST_FORALL(&OvsSttPktFragHash[hash & STT_HASH_TABLE_MASK], link) {
        entry = CONTAINING_RECORD(link, OVS_STT_PKT_ENTRY, link);
        if (entry->ovsPktKey.ackSeq == pktKey->ackSeq &&
            entry->ovsPktKey.dAddr == pktKey->dAddr &&
            entry->ovsPktKey.sAddr == pktKey->sAddr) {
            return entry;
        }
    }
    return NULL;
}

/*
*
--------------------------------------------------------------------------
* OvsSttReassemble --
*     Reassemble an LSO packet from multiple STT-Fragments.
*
--------------------------------------------------------------------------
*/
PNET_BUFFER_LIST
OvsSttReassemble(POVS_SWITCH_CONTEXT switchContext,
                 PNET_BUFFER_LIST curNbl,
                 IPHdr *ipHdr,
                 TCPHdr *tcp,
                 SttHdr *newSttHdr,
                 UINT16 payloadLen)
{
    UINT32 seq = ntohl(tcp->seq);
    UINT32 innerPacketLen = (seq >> STT_SEQ_LEN_SHIFT) - STT_HDR_LEN;
    UINT32 segOffset = STT_SEGMENT_OFF(seq);
    UINT32 offset = segOffset == 0 ? 0 : segOffset - STT_HDR_LEN;
    UINT32 startOffset = 0;
    OVS_STT_PKT_ENTRY *pktFragEntry;
    PNET_BUFFER_LIST targetPNbl = NULL;
    BOOLEAN lastPacket = FALSE;
    PNET_BUFFER sourceNb;
    UINT32 fragmentLength = payloadLen;
    SttHdr stt;
    SttHdr *sttHdr = NULL;
    sourceNb = NET_BUFFER_LIST_FIRST_NB(curNbl);

    /* XXX optimize this lock */
    NdisAcquireSpinLock(&OvsSttSpinLock);

    /* If this is the first fragment, copy the STT header */
    if (segOffset == 0) {
        sttHdr = NdisGetDataBuffer(sourceNb, sizeof(SttHdr), &stt, 1, 0);
        if (sttHdr == NULL) {
            OVS_LOG_ERROR("Unable to retrieve STT header");
            return NULL;
        }
        fragmentLength = fragmentLength - STT_HDR_LEN;
        startOffset = startOffset + STT_HDR_LEN;
    }

    /* Lookup fragment */
    OVS_STT_PKT_KEY pktKey = OvsGeneratePacketKey(ipHdr, tcp);
    UINT32 hash = OvsSttGetPktHash(&pktKey);
    pktFragEntry = OvsLookupPktFrag(&pktKey, hash);

    if (pktFragEntry == NULL) {
        /* Create a new Packet Entry */
        POVS_STT_PKT_ENTRY entry;
        entry = OvsAllocateMemoryWithTag(sizeof(OVS_STT_PKT_ENTRY),
                                         OVS_STT_POOL_TAG);
        RtlZeroMemory(entry, sizeof (OVS_STT_PKT_ENTRY));

        /* Update Key, timestamp and recvdLen */
        NdisMoveMemory(&entry->ovsPktKey, &pktKey, sizeof (OVS_STT_PKT_KEY));

        entry->recvdLen = fragmentLength;

        UINT64 currentTime;
        NdisGetCurrentSystemTime((LARGE_INTEGER *) &currentTime);
        entry->timeout = currentTime + STT_ENTRY_TIMEOUT;

        if (segOffset == 0) {
            entry->sttHdr = *sttHdr;
        }

        /* Copy the data from Source to new buffer */
        entry->packetBuf = OvsAllocateMemoryWithTag(innerPacketLen,
                                                    OVS_STT_POOL_TAG);
        if (OvsGetPacketBytes(curNbl, fragmentLength, startOffset,
                              entry->packetBuf + offset) == NULL) {
            OVS_LOG_ERROR("Error when obtaining bytes from Packet");
            goto handle_error;
        }

        /* Insert the entry in the Static Buffer */
        InsertHeadList(&OvsSttPktFragHash[hash & STT_HASH_TABLE_MASK],
                       &entry->link);
    } else {
        /* Add to recieved length to identify if this is the last fragment */
        pktFragEntry->recvdLen += fragmentLength;
        lastPacket = (pktFragEntry->recvdLen == innerPacketLen);

        if (segOffset == 0) {
            pktFragEntry->sttHdr = *sttHdr;
        }

        /* Copy the fragment data from Source to existing buffer */
        if (OvsGetPacketBytes(curNbl, fragmentLength, startOffset,
                              pktFragEntry->packetBuf + offset) == NULL) {
            OVS_LOG_ERROR("Error when obtaining bytes from Packet");
            goto handle_error;
        }
    }

handle_error:
    if (lastPacket) {
        /* Retrieve the original STT header */
        NdisMoveMemory(newSttHdr, &pktFragEntry->sttHdr, sizeof (SttHdr));
        targetPNbl = OvsAllocateNBLFromBuffer(switchContext, pktFragEntry->packetBuf,
                                              innerPacketLen);

        /* Delete this entry and free up the memory/ */
        RemoveEntryList(&pktFragEntry->link);
        OvsFreeMemoryWithTag(pktFragEntry->packetBuf, OVS_STT_POOL_TAG);
        OvsFreeMemoryWithTag(pktFragEntry, OVS_STT_POOL_TAG);
    }

    NdisReleaseSpinLock(&OvsSttSpinLock);
    return lastPacket ? targetPNbl : NULL;
}

VOID
OvsDecapSetOffloads(PNET_BUFFER_LIST curNbl, SttHdr *sttHdr)
{
    if ((sttHdr->flags & STT_CSUM_VERIFIED)
        || !(sttHdr->flags & STT_CSUM_PARTIAL)) {
        return;
    }

    UINT8 protoType;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
    csumInfo.Value = 0;
    csumInfo.Transmit.IpHeaderChecksum = 0;
    csumInfo.Transmit.TcpHeaderOffset = sttHdr->l4Offset;
    protoType = sttHdr->flags & STT_PROTO_TYPES;
    switch (protoType) {
        case (STT_PROTO_IPV4 | STT_PROTO_TCP):
            /* TCP/IPv4 */
            csumInfo.Transmit.IsIPv4 = 1;
            csumInfo.Transmit.TcpChecksum = 1;
            break;
        case STT_PROTO_TCP:
            /* TCP/IPv6 */
            csumInfo.Transmit.IsIPv6 = 1;
            csumInfo.Transmit.TcpChecksum = 1;
            break;
        case STT_PROTO_IPV4:
            /* UDP/IPv4 */
            csumInfo.Transmit.IsIPv4 = 1;
            csumInfo.Transmit.UdpChecksum = 1;
            break;
        default:
            /* UDP/IPv6 */
            csumInfo.Transmit.IsIPv6 = 1;
            csumInfo.Transmit.UdpChecksum = 1;
    }
    NET_BUFFER_LIST_INFO(curNbl,
                         TcpIpChecksumNetBufferListInfo) = csumInfo.Value;

    if (sttHdr->mss) {
        NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO lsoInfo;
        lsoInfo.Value = 0;
        lsoInfo.LsoV2Transmit.TcpHeaderOffset = sttHdr->l4Offset;
        lsoInfo.LsoV2Transmit.MSS = ETH_DEFAULT_MTU
                                    - sizeof(IPHdr)
                                    - sizeof(TCPHdr);
        lsoInfo.LsoV2Transmit.Type = NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE;
        if (sttHdr->flags & STT_PROTO_IPV4) {
            lsoInfo.LsoV2Transmit.IPVersion = NDIS_TCP_LARGE_SEND_OFFLOAD_IPv4;
        } else {
            lsoInfo.LsoV2Transmit.IPVersion = NDIS_TCP_LARGE_SEND_OFFLOAD_IPv6;
        }
        NET_BUFFER_LIST_INFO(curNbl,
                             TcpLargeSendNetBufferListInfo) = lsoInfo.Value;
    }
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
    PNET_BUFFER curNb, newNb;
    IPHdr *ipHdr;
    char *ipBuf[sizeof(IPHdr)];
    SttHdr stt;
    SttHdr *sttHdr;
    char *sttBuf[STT_HDR_LEN];
    UINT32 advanceCnt, hdrLen;
    BOOLEAN isLsoPacket = FALSE;

    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    ASSERT(NET_BUFFER_NEXT_NB(curNb) == NULL);

    /* Validate the TCP Checksum */
    status = OvsValidateTCPChecksum(curNbl, curNb);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    /* Skip Eth header */
    hdrLen = sizeof(EthHdr);
    NdisAdvanceNetBufferDataStart(curNb, hdrLen, FALSE, NULL);
    advanceCnt = hdrLen;

    ipHdr = NdisGetDataBuffer(curNb, sizeof *ipHdr, (PVOID) &ipBuf,
                                                    1 /*no align*/, 0);
    ASSERT(ipHdr);

    TCPHdr *tcp = (TCPHdr *)((PCHAR)ipHdr + ipHdr->ihl * 4);

    /* Skip IP & TCP headers */
    hdrLen = sizeof(IPHdr) + sizeof(TCPHdr),
    NdisAdvanceNetBufferDataStart(curNb, hdrLen, FALSE, NULL);
    advanceCnt += hdrLen;

    UINT32 seq = ntohl(tcp->seq);
    UINT32 totalLen = (seq >> STT_SEQ_LEN_SHIFT);
    UINT16 payloadLen = (UINT16)ntohs(ipHdr->tot_len)
                        - (ipHdr->ihl * 4)
                        - (sizeof * tcp);

    /* Check if incoming packet requires reassembly */
    if (totalLen != payloadLen) {
        sttHdr = &stt;
        PNET_BUFFER_LIST pNbl = OvsSttReassemble(switchContext, curNbl,
                                                 ipHdr, tcp, sttHdr,
                                                 payloadLen);
        if (pNbl == NULL) {
            return NDIS_STATUS_SUCCESS;
        }

        *newNbl = pNbl;
        isLsoPacket = TRUE;
    } else {
        /* STT Header */
        sttHdr = NdisGetDataBuffer(curNb, sizeof *sttHdr,
                                   (PVOID) &sttBuf, 1 /*no align*/, 0);
        /* Skip stt header, DataOffset points to inner pkt now. */
        hdrLen = STT_HDR_LEN;
        NdisAdvanceNetBufferDataStart(curNb, hdrLen, FALSE, NULL);
        advanceCnt += hdrLen;

        *newNbl = OvsPartialCopyNBL(switchContext, curNbl, 0,
                                    0, FALSE /*copy NBL info*/);
    }

    if (*newNbl == NULL) {
        OVS_LOG_ERROR("Unable to allocate a new cloned NBL");
        return NDIS_STATUS_RESOURCES;
    }

    status = NdisRetreatNetBufferDataStart(curNb, advanceCnt, 0, NULL);
    if (status != NDIS_STATUS_SUCCESS) {
        OvsCompleteNBL(switchContext, *newNbl, TRUE);
        return NDIS_STATUS_FAILURE;
    }
    newNb = NET_BUFFER_LIST_FIRST_NB(*newNbl);

    ASSERT(sttHdr);

    /* Initialize the tunnel key */
    tunKey->dst = ipHdr->daddr;
    tunKey->src = ipHdr->saddr;
    tunKey->tunnelId = sttHdr->key;
    tunKey->flags = OVS_TNL_F_KEY;
    tunKey->tos = ipHdr->tos;
    tunKey->ttl = ipHdr->ttl;
    tunKey->pad = 0;

    /* Set Checksum and LSO offload flags */
    OvsDecapSetOffloads(*newNbl, sttHdr);

    return NDIS_STATUS_SUCCESS;
}
