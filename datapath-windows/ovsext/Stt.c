/*
 * Copyright (c) 2015, 2016 VMware, Inc.
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
#include "Stt.h"
#include "Switch.h"
#include "User.h"
#include "Util.h"
#include "Vport.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_STT

#define OVS_MAX_STT_PACKET_LENGTH 0x10000
#define OVS_MAX_STT_L4_OFFSET_LENGTH 0xFF

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
            PNET_BUFFER_LIST *newNbl,
            POVS_FWD_INFO switchFwdInfo)
{
    OVS_FWD_INFO fwdInfo;
    NDIS_STATUS status;

    UNREFERENCED_PARAMETER(switchContext);
    status = OvsLookupIPFwdInfo(tunKey->src, tunKey->dst, &fwdInfo);
    if (status != STATUS_SUCCESS) {
        OvsFwdIPHelperRequest(NULL, 0, tunKey, NULL, NULL, NULL);
        /*
         * XXX This case where the ARP table is not populated is
         * currently not handled
         */
        return NDIS_STATUS_FAILURE;
    }

    RtlCopyMemory(switchFwdInfo->value, fwdInfo.value, sizeof fwdInfo.value);

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
    PVOID vlanTagValue;
    ULONG tcpHeaderOffset = sizeof(EthHdr) + sizeof(IPHdr);
    UINT32 encapMss = OvsGetExternalMtu(switchContext)
                                        - sizeof(IPHdr)
                                        - sizeof(TCPHdr);

    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);

    /* Verify if inner checksum is verified */
    BOOLEAN innerChecksumVerified = FALSE;
    BOOLEAN innerPartialChecksum = FALSE;

    if (layers->isTcp) {
        mss = OVSGetTcpMSS(curNbl);

        curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
        innerFrameLen = NET_BUFFER_DATA_LENGTH(curNb);

        /* If the length of the packet exceeds 64K or if the L4 offset is
           bigger than 255 bytes, then the packet cannot be offloaded to the
           network card */
        if ((innerFrameLen > OVS_MAX_STT_PACKET_LENGTH) ||
            (layers->l4Offset > OVS_MAX_STT_L4_OFFSET_LENGTH)) {
            *newNbl = OvsTcpSegmentNBL(switchContext, curNbl, layers,
                                       mss - headRoom, headRoom, FALSE);
            if (*newNbl == NULL) {
                OVS_LOG_ERROR("Unable to segment NBL");
                return NDIS_STATUS_FAILURE;
            }
            /* Clear out LSO flags after this point */
            NET_BUFFER_LIST_INFO(*newNbl, TcpLargeSendNetBufferListInfo) = 0;
        }
    }

    vportStt = (POVS_STT_VPORT) GetOvsVportPriv(vport);
    ASSERT(vportStt);

    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
    csumInfo.Value = NET_BUFFER_LIST_INFO(curNbl,
                                          TcpIpChecksumNetBufferListInfo);
    vlanTagValue = NET_BUFFER_LIST_INFO(curNbl, Ieee8021QNetBufferListInfo);
    if (*newNbl == NULL) {
        *newNbl = OvsPartialCopyNBL(switchContext, curNbl, 0, headRoom,
            FALSE /*copy NblInfo*/);
        if (*newNbl == NULL) {
            OVS_LOG_ERROR("Unable to copy NBL");
            return NDIS_STATUS_FAILURE;
        }
    }
    curNbl = *newNbl;
    for (curNb = NET_BUFFER_LIST_FIRST_NB(curNbl); curNb != NULL;
            curNb = curNb->Next) {
        curMdl = NET_BUFFER_CURRENT_MDL(curNb);
        innerFrameLen = NET_BUFFER_DATA_LENGTH(curNb);
        bufferStart = (PUINT8)MmGetSystemAddressForMdlSafe(curMdl,
                                                           LowPagePriority);
        if (bufferStart == NULL) {
            status = NDIS_STATUS_RESOURCES;
            goto ret_error;
        }
        bufferStart += NET_BUFFER_CURRENT_MDL_OFFSET(curNb);

        if (layers->isIPv4) {
            IPHdr *ip = (IPHdr *)(bufferStart + layers->l3Offset);
            if (!ip->tot_len) {
                ip->tot_len = htons(innerFrameLen - layers->l3Offset);
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
        ASSERT((int) (MmGetMdlByteCount(curMdl) -
                    NET_BUFFER_CURRENT_MDL_OFFSET(curNb)) >= (int) headRoom);

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
        NdisMoveMemory(outerEthHdr->Destination, fwdInfo->dstMacAddr,
                       sizeof outerEthHdr->Destination);
        NdisMoveMemory(outerEthHdr->Source, fwdInfo->srcMacAddr,
                       sizeof outerEthHdr->Source);
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
        outerTcpHdr->dest = tunKey->dst_port ? tunKey->dst_port:
                                               htons(vportStt->dstPort);
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
        sttHdr->version = 0;

        /* Set STT Header */
        sttHdr->flags = 0;
        sttHdr->mss = 0;
        sttHdr->l4Offset = 0;
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

        /* Set VLAN tag */
        sttHdr->vlanTCI = 0;
        if (vlanTagValue) {
            PNDIS_NET_BUFFER_LIST_8021Q_INFO vlanTag =
                (PNDIS_NET_BUFFER_LIST_8021Q_INFO)(PVOID *)&vlanTagValue;
            sttHdr->vlanTCI = htons(vlanTag->TagHeader.VlanId | OVSWIN_VLAN_CFI |
                                    (vlanTag->TagHeader.UserPriority << 13));
        }

        sttHdr->reserved = 0;
        sttHdr->key = tunKey->tunnelId;
        /* Zero out stt padding */
        *(uint16 *)(sttHdr + 1) = 0;

        /* The LSO offloading will be set only if the packet isn't
           segmented due to the 64K limit for the offloading or 255 bytes
           limit of L4 offset */
        if (ipTotalLen > encapMss) {
            /* For Windows LSO, the TCP pseudo checksum must contain Source IP
             * Address, Destination IP Address, and Protocol; the length of the
             * payload is excluded because the underlying miniport driver and NIC
             * generate TCP segments from the large packet that is passed down by
             * the TCP/IP transport, the transport does not know the size of the
             * TCP payload for each TCP segment and therefore cannot include the
             * TCP Length in the pseudo-header.
            */
            outerIpHdr->check = IPChecksum((UINT8 *)outerIpHdr,
                sizeof *outerIpHdr, 0);
            outerTcpHdr->check = IPPseudoChecksum(&fwdInfo->srcIpAddr,
                (uint32 *)&tunKey->dst,
                IPPROTO_TCP, (uint16)0);

            lsoInfo.Value = 0;
            lsoInfo.LsoV2Transmit.TcpHeaderOffset = tcpHeaderOffset;
            lsoInfo.LsoV2Transmit.MSS = encapMss;
            lsoInfo.LsoV2Transmit.Type = NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE;
            lsoInfo.LsoV2Transmit.IPVersion = NDIS_TCP_LARGE_SEND_OFFLOAD_IPv4;
            NET_BUFFER_LIST_INFO(curNbl,
                TcpLargeSendNetBufferListInfo) = lsoInfo.Value;
        } else {
            outerTcpHdr->check = IPPseudoChecksum(&fwdInfo->srcIpAddr,
                                            (uint32 *) &tunKey->dst,
                                            IPPROTO_TCP,
                                            (uint16) tcpChksumLen);
        }
    }

    /* Offload IP and TCP checksum.
       The offsets are the same for all segments if the packet was segmented */
    csumInfo.Value = 0;
    csumInfo.Transmit.IpHeaderChecksum = 1;
    csumInfo.Transmit.TcpChecksum = 1;
    csumInfo.Transmit.IsIPv4 = 1;
    csumInfo.Transmit.TcpHeaderOffset = tcpHeaderOffset;
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
    if (eth == NULL) {
        return NDIS_STATUS_RESOURCES;
    }

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

    if (offset + fragmentLength > innerPacketLen) {
        // avoid buffer overflow on copy
        return NULL;
    }

    /* XXX optimize this lock */
    NdisAcquireSpinLock(&OvsSttSpinLock);

    /* Lookup fragment */
    OVS_STT_PKT_KEY pktKey = OvsGeneratePacketKey(ipHdr, tcp);
    UINT32 hash = OvsSttGetPktHash(&pktKey);
    pktFragEntry = OvsLookupPktFrag(&pktKey, hash);

    if (pktFragEntry == NULL) {
        /* Create a new Packet Entry */
        POVS_STT_PKT_ENTRY entry;
        entry = OvsAllocateMemoryWithTag(sizeof(OVS_STT_PKT_ENTRY),
                                         OVS_STT_POOL_TAG);
        if (entry == NULL) {
            goto handle_error;
        }
        RtlZeroMemory(entry, sizeof (OVS_STT_PKT_ENTRY));

        /* Update Key, timestamp and recvdLen */
        NdisMoveMemory(&entry->ovsPktKey, &pktKey, sizeof (OVS_STT_PKT_KEY));

        entry->recvdLen = fragmentLength;
        if (ipHdr->ecn == IP_ECN_CE) {
            entry->ecn = IP_ECN_CE;
        }

        UINT64 currentTime;
        NdisGetCurrentSystemTime((LARGE_INTEGER *) &currentTime);
        entry->timeout = currentTime + STT_ENTRY_TIMEOUT;

        if (segOffset == 0) {
            ASSERT(sttHdr);
            entry->sttHdr = *sttHdr;
        }

        /* Copy the data from Source to new buffer */
        entry->allocatedLen = innerPacketLen;
        entry->packetBuf = OvsAllocateMemoryWithTag(innerPacketLen,
                                                    OVS_STT_POOL_TAG);
        if (entry->packetBuf == NULL) {
            OvsFreeMemoryWithTag(entry, OVS_STT_POOL_TAG);
            goto handle_error;
        }
        if (OvsGetPacketBytes(curNbl, fragmentLength, startOffset,
                              entry->packetBuf + offset) == NULL) {
            OVS_LOG_ERROR("Error when obtaining bytes from Packet");
            goto handle_error;
        }

        /* Insert the entry in the Static Buffer */
        InsertHeadList(&OvsSttPktFragHash[hash & STT_HASH_TABLE_MASK],
                       &entry->link);
    } else {
        if (offset + fragmentLength > pktFragEntry->allocatedLen) {
            // don't copy more than it is allocated
            goto handle_error;
        }

        if (segOffset == 0) {
            ASSERT(sttHdr);
            pktFragEntry->sttHdr = *sttHdr;
        }
        if (ipHdr->ecn == IP_ECN_CE) {
            pktFragEntry->ecn = IP_ECN_CE;
        }

        /* Copy the fragment data from Source to existing buffer */
        if (OvsGetPacketBytes(curNbl, fragmentLength, startOffset,
                              pktFragEntry->packetBuf + offset) == NULL) {
            OVS_LOG_ERROR("Error when obtaining bytes from Packet");
            goto handle_error;
        }

        /* Add to received length to identify if this is the last fragment */
        pktFragEntry->recvdLen += fragmentLength;
        lastPacket = (pktFragEntry->recvdLen == innerPacketLen);
    }

handle_error:
    if (lastPacket) {
        /* It is RECOMMENDED that if any segment of the received STT
        *  frame has the CE (congestion experienced) bit set
        *  in its IP header, then the CE bit SHOULD be set in the IP
        *  header of the decapsulated STT frame.*/
        if (pktFragEntry->ecn == IP_ECN_CE) {
            ipHdr->ecn = IP_ECN_CE;
        }

        /* Retrieve the original STT header */
        NdisMoveMemory(newSttHdr, &pktFragEntry->sttHdr, sizeof (SttHdr));
        targetPNbl = OvsAllocateNBLFromBuffer(switchContext,
                                              pktFragEntry->packetBuf,
                                              innerPacketLen);

        /* Delete this entry and free up the memory/ */
        RemoveEntryList(&pktFragEntry->link);
        OvsFreeMemoryWithTag(pktFragEntry->packetBuf, OVS_STT_POOL_TAG);
        OvsFreeMemoryWithTag(pktFragEntry, OVS_STT_POOL_TAG);
    }

    NdisReleaseSpinLock(&OvsSttSpinLock);
    return lastPacket ? targetPNbl : NULL;
}


/*
*----------------------------------------------------------------------------
* OvsDecapSetOffloads
*     Processes received STT header and sets TcpIpChecksumNetBufferListInfo
*     accordingly.
*     For TCP packets with total length bigger than destination MSS it
*     populates TcpLargeSendNetBufferListInfo.
*
* Returns NDIS_STATUS_SUCCESS normally.
* Fails only if packet data is invalid.
* (e.g. if OvsExtractLayers() returns an error).
*----------------------------------------------------------------------------
*/
NDIS_STATUS
OvsDecapSetOffloads(PNET_BUFFER_LIST *curNbl,
                    SttHdr *sttHdr,
                    OVS_PACKET_HDR_INFO *layers)
{
    if ((sttHdr->flags & STT_CSUM_VERIFIED)
        || !(sttHdr->flags & STT_CSUM_PARTIAL)) {
        return NDIS_STATUS_SUCCESS;
    }

    NDIS_STATUS status;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
    UINT8 protoType;

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
    NET_BUFFER_LIST_INFO(*curNbl,
                         TcpIpChecksumNetBufferListInfo) = csumInfo.Value;

    if (sttHdr->mss && (sttHdr->flags & STT_PROTO_TCP)) {
        NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO lsoInfo;
        PMDL curMdl = NULL;
        PNET_BUFFER curNb;
        PUINT8 buf = NULL;

        // if layers not initialized by the caller we extract layers here
        if (layers->value == 0) {
            status = OvsExtractLayers(*curNbl, layers);
            if (status != NDIS_STATUS_SUCCESS) {
                return status;
            }
        }

        curNb = NET_BUFFER_LIST_FIRST_NB(*curNbl);
        curMdl = NET_BUFFER_CURRENT_MDL(curNb);

        buf = (PUINT8)MmGetSystemAddressForMdlSafe(curMdl,
            LowPagePriority);
        if (buf == NULL) {
            return NDIS_STATUS_RESOURCES;
        }
        buf += NET_BUFFER_CURRENT_MDL_OFFSET(curNb);

        // apply pseudo checksum on extracted packet
        if (sttHdr->flags & STT_PROTO_IPV4) {
            IPHdr *ipHdr;
            TCPHdr *tcpHdr;

            ipHdr = (IPHdr *)(buf + layers->l3Offset);
            tcpHdr = (TCPHdr *)(buf + layers->l4Offset);

            tcpHdr->check = IPPseudoChecksum(&ipHdr->saddr,
                                             (uint32 *)&ipHdr->daddr,
                                             IPPROTO_TCP, 0);
        } else {
            IPv6Hdr *ipHdr;
            TCPHdr *tcpHdr;

            ipHdr = (IPv6Hdr *)(buf + layers->l3Offset);
            tcpHdr = (TCPHdr *)(buf + layers->l4Offset);

            tcpHdr->check = IPv6PseudoChecksum((UINT32*)&ipHdr->saddr,
                                        (UINT32*)&ipHdr->daddr,
                                        IPPROTO_TCP, 0);
        }

        // setup LSO
        lsoInfo.Value = 0;
        lsoInfo.LsoV2Transmit.TcpHeaderOffset = sttHdr->l4Offset;
        lsoInfo.LsoV2Transmit.MSS = ntohs(sttHdr->mss);
        lsoInfo.LsoV2Transmit.Type = NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE;
        if (sttHdr->flags & STT_PROTO_IPV4) {
            lsoInfo.LsoV2Transmit.IPVersion = NDIS_TCP_LARGE_SEND_OFFLOAD_IPv4;
        } else {
            lsoInfo.LsoV2Transmit.IPVersion = NDIS_TCP_LARGE_SEND_OFFLOAD_IPv6;
        }
        NET_BUFFER_LIST_INFO(*curNbl,
                             TcpLargeSendNetBufferListInfo) = lsoInfo.Value;
    }

    return NDIS_STATUS_SUCCESS;
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
    NDIS_STATUS status;
    PNET_BUFFER curNb;
    IPHdr *ipHdr;
    char *ipBuf[sizeof(IPHdr)];
    SttHdr stt;
    SttHdr *sttHdr;
    char *sttBuf[STT_HDR_LEN];
    UINT32 advanceCnt, hdrLen;

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
    if (ipHdr == NULL) {
        return NDIS_STATUS_RESOURCES;
    }

    TCPHdr *tcp = (TCPHdr *)((PCHAR)ipHdr + ipHdr->ihl * 4);

    /* Skip IP & TCP headers */
    hdrLen = (ipHdr->ihl * 4) + (tcp->doff * 4);
    NdisAdvanceNetBufferDataStart(curNb, hdrLen, FALSE, NULL);
    advanceCnt += hdrLen;

    UINT32 seq = ntohl(tcp->seq);
    UINT32 totalLen = (seq >> STT_SEQ_LEN_SHIFT);
    UINT16 payloadLen = (UINT16)ntohs(ipHdr->tot_len)
                        - (ipHdr->ihl * 4)
                        - (tcp->doff * 4);

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
    } else {
        /* STT Header */
        sttHdr = NdisGetDataBuffer(curNb, sizeof *sttHdr,
                                   (PVOID) &sttBuf, 1 /*no align*/, 0);
        if (sttHdr == NULL) {
            return NDIS_STATUS_RESOURCES;
        }
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
        status = NDIS_STATUS_FAILURE;
        goto dropNbl;
    }

    ASSERT(sttHdr);

    /* Initialize the tunnel key */
    tunKey->dst = ipHdr->daddr;
    tunKey->src = ipHdr->saddr;
    tunKey->tunnelId = sttHdr->key;
    tunKey->flags = OVS_TNL_F_KEY;
    tunKey->tos = ipHdr->tos;
    tunKey->ttl = ipHdr->ttl;
    tunKey->pad = 0;

    /* Handle ECN */
    OVS_PACKET_HDR_INFO layers = {0};
    if (0 != ipHdr->tos) {
        status = OvsExtractLayers(*newNbl, &layers);
        if (status != NDIS_STATUS_SUCCESS) {
            status = NDIS_STATUS_FAILURE;
            goto dropNbl;
        }

        if (layers.isIPv4) {
            IPHdr ip_storage;
            IPHdr *innerIpHdr;

            /*
            *  If CE is set for outer IP header, reset ECN of inner IP
            *  header to CE, all other values are kept the same
            */
            innerIpHdr = (IPHdr*)OvsGetIp(*newNbl,
                                          layers.l3Offset,
                                          &ip_storage);
            if (innerIpHdr) {
                if (ipHdr->ecn == IP_ECN_CE) {
                        innerIpHdr->ecn |= IP_ECN_CE;
                }
                /* copy DSCP from outer header to inner header */
                innerIpHdr->dscp = ipHdr->dscp;
                /* fix IP checksum */
                innerIpHdr->check = IPChecksum((UINT8 *)innerIpHdr,
                                                innerIpHdr->ihl * 4, 0);
            } else {
                status = NDIS_STATUS_INVALID_PACKET;
                goto dropNbl;
            }
        } else if (layers.isIPv6) {
            IPv6Hdr ipv6_storage;
            IPv6Hdr *innerIpv6Hdr = (IPv6Hdr*)OvsGetPacketBytes(
                                                      *newNbl,
                                                      sizeof *innerIpv6Hdr,
                                                      layers.l3Offset,
                                                      &ipv6_storage);
            if (innerIpv6Hdr) {
                /* copy ECN and DSCN to inner header */
                innerIpv6Hdr->priority = ipHdr->ecn
                                    | ((innerIpv6Hdr->flow_lbl[0] & 0x3) << 2);
                innerIpv6Hdr->flow_lbl[0] = (innerIpv6Hdr->flow_lbl[0] & 0xF)
                                             | ((ipHdr->tos & 0xF) << 4);
            } else {
                status = NDIS_STATUS_RESOURCES;
                goto dropNbl;
            }
        }
    }

    /* Apply VLAN tag if present */
    if (ntohs(sttHdr->vlanTCI) & OVSWIN_VLAN_CFI) {
        NDIS_NET_BUFFER_LIST_8021Q_INFO vlanTag;
        vlanTag.Value = 0;
        vlanTag.TagHeader.VlanId = ntohs(sttHdr->vlanTCI) & 0xfff;
        vlanTag.TagHeader.UserPriority = ntohs(sttHdr->vlanTCI) >> 13;
        NET_BUFFER_LIST_INFO(*newNbl,
            Ieee8021QNetBufferListInfo) = vlanTag.Value;
    }

    /* Set Checksum and LSO offload flags */
    OvsDecapSetOffloads(newNbl, sttHdr, &layers);

    return NDIS_STATUS_SUCCESS;

dropNbl:
    OvsCompleteNBL(switchContext, *newNbl, TRUE);
    *newNbl = NULL;
    return status;
}
