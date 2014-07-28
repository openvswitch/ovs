/*
 * Copyright (c) 2014 VMware, Inc.
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
#include "OvsNetProto.h"
#include "OvsUtil.h"
#include "OvsJhash.h"
#include "OvsFlow.h"
#include "OvsPacketParser.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_FLOW
#include "OvsDebug.h"

#pragma warning( push )
#pragma warning( disable:4127 )

extern PNDIS_SPIN_LOCK gOvsCtrlLock;
extern POVS_SWITCH_CONTEXT gOvsSwitchContext;

static NTSTATUS ReportFlowInfo(OvsFlow *flow, UINT32 getFlags,
                               UINT32 getActionsLen, OvsFlowInfo *info);
static NTSTATUS HandleFlowPut(OvsFlowPut *put,
                                  OVS_DATAPATH *datapath,
                                  struct OvsFlowStats *stats);
static NTSTATUS OvsPrepareFlow(OvsFlow **flow, const OvsFlowPut *put,
                               UINT64 hash);
static VOID RemoveFlow(OVS_DATAPATH *datapath, OvsFlow **flow);
static VOID DeleteAllFlows(OVS_DATAPATH *datapath);
static NTSTATUS AddFlow(OVS_DATAPATH *datapath, OvsFlow *flow);
static VOID FreeFlow(OvsFlow *flow);
static VOID __inline *GetStartAddrNBL(const NET_BUFFER_LIST *_pNB);

#define OVS_FLOW_TABLE_SIZE 2048
#define OVS_FLOW_TABLE_MASK (OVS_FLOW_TABLE_SIZE -1)
#define HASH_BUCKET(hash) ((hash) & OVS_FLOW_TABLE_MASK)

/*
 *----------------------------------------------------------------------------
 * OvsDeleteFlowTable --
 * Results:
 *    NDIS_STATUS_SUCCESS always.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsDeleteFlowTable(OVS_DATAPATH *datapath)
{
    if (datapath == NULL || datapath->flowTable == NULL) {
        return NDIS_STATUS_SUCCESS;
    }

    DeleteAllFlows(datapath);
    OvsFreeMemory(datapath->flowTable);
    datapath->flowTable = NULL;
    NdisFreeRWLock(datapath->lock);

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsAllocateFlowTable --
 * Results:
 *    NDIS_STATUS_SUCCESS on success.
 *    NDIS_STATUS_RESOURCES if memory couldn't be allocated
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsAllocateFlowTable(OVS_DATAPATH *datapath,
                     POVS_SWITCH_CONTEXT switchContext)
{
    PLIST_ENTRY bucket;
    int i;

    datapath->flowTable = OvsAllocateMemory(OVS_FLOW_TABLE_SIZE *
                                            sizeof (LIST_ENTRY));
    if (!datapath->flowTable) {
        return NDIS_STATUS_RESOURCES;
    }
    for (i = 0; i < OVS_FLOW_TABLE_SIZE; i++) {
        bucket = &(datapath->flowTable[i]);
        InitializeListHead(bucket);
    }
    datapath->lock = NdisAllocateRWLock(switchContext->NdisFilterHandle);

    return NDIS_STATUS_SUCCESS;
}


/*
 *----------------------------------------------------------------------------
 *  GetStartAddrNBL --
 *    Get the virtual address of the frame.
 *
 *  Results:
 *    Virtual address of the frame.
 *----------------------------------------------------------------------------
 */
static __inline VOID *
GetStartAddrNBL(const NET_BUFFER_LIST *_pNB)
{
    PMDL curMdl;
    PUINT8 curBuffer;
    PEthHdr curHeader;

    ASSERT(_pNB);

    // Ethernet Header is a guaranteed safe access.
    curMdl = (NET_BUFFER_LIST_FIRST_NB(_pNB))->CurrentMdl;
    curBuffer =  MmGetSystemAddressForMdlSafe(curMdl, LowPagePriority);
    if (!curBuffer) {
        return NULL;
    }

    curHeader = (PEthHdr)
    (curBuffer + (NET_BUFFER_LIST_FIRST_NB(_pNB))->CurrentMdlOffset);

    return (VOID *) curHeader;
}

VOID
OvsFlowUsed(OvsFlow *flow,
            const NET_BUFFER_LIST *packet,
            const POVS_PACKET_HDR_INFO layers)
{
    LARGE_INTEGER tickCount;

    KeQueryTickCount(&tickCount);
    flow->used = tickCount.QuadPart * ovsTimeIncrementPerTick;
    flow->used += ovsUserTimestampDelta;
    flow->packetCount++;
    flow->byteCount += OvsPacketLenNBL(packet);
    flow->tcpFlags |= OvsGetTcpFlags(packet, &flow->key, layers);
}


VOID
DeleteAllFlows(OVS_DATAPATH *datapath)
{
    INT i;
    PLIST_ENTRY bucket;

    for (i = 0; i < OVS_FLOW_TABLE_SIZE; i++) {
        PLIST_ENTRY next;
        bucket = &(datapath->flowTable[i]);
        while (!IsListEmpty(bucket)) {
            OvsFlow *flow;
            next = bucket->Flink;
            flow = CONTAINING_RECORD(next, OvsFlow, ListEntry);
            RemoveFlow(datapath, &flow);
        }
    }
}

/*
 *----------------------------------------------------------------------------
 * Initializes 'flow' members from 'packet', 'skb_priority', 'tun_id', and
 * 'ofp_in_port'.
 *
 * Initializes 'packet' header pointers as follows:
 *
 *    - packet->l2 to the start of the Ethernet header.
 *
 *    - packet->l3 to just past the Ethernet header, or just past the
 *      vlan_header if one is present, to the first byte of the payload of the
 *      Ethernet frame.
 *
 *    - packet->l4 to just past the IPv4 header, if one is present and has a
 *      correct length, and otherwise NULL.
 *
 *    - packet->l7 to just past the TCP or UDP or ICMP header, if one is
 *      present and has a correct length, and otherwise NULL.
 *
 * Returns NDIS_STATUS_SUCCESS normally.  Fails only if packet data cannot be accessed
 * (e.g. if Pkt_CopyBytesOut() returns an error).
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsExtractFlow(const NET_BUFFER_LIST *packet,
               UINT32 inPort,
               OvsFlowKey *flow,
               POVS_PACKET_HDR_INFO layers,
               OvsIPv4TunnelKey *tunKey)
{
    struct Eth_Header *eth;
    UINT8 offset = 0;
    PVOID vlanTagValue;

    layers->value = 0;

    if (tunKey) {
        ASSERT(tunKey->dst != 0);
        RtlMoveMemory(&flow->tunKey, tunKey, sizeof flow->tunKey);
        flow->l2.offset = 0;
    } else {
        flow->tunKey.dst = 0;
        flow->l2.offset = OVS_WIN_TUNNEL_KEY_SIZE;
    }

    flow->l2.inPort = inPort;

    if ( OvsPacketLenNBL(packet) < ETH_HEADER_LEN_DIX) {
        flow->l2.keyLen = OVS_WIN_TUNNEL_KEY_SIZE + 8 - flow->l2.offset;
        return NDIS_STATUS_SUCCESS;
    }

    /* Link layer. */
    eth = (Eth_Header *)GetStartAddrNBL((NET_BUFFER_LIST *)packet);
    memcpy(flow->l2.dlSrc, eth->src, ETH_ADDR_LENGTH);
    memcpy(flow->l2.dlDst, eth->dst, ETH_ADDR_LENGTH);

    /*
     * vlan_tci.
     */
    vlanTagValue = NET_BUFFER_LIST_INFO(packet, Ieee8021QNetBufferListInfo);
    if (vlanTagValue) {
        PNDIS_NET_BUFFER_LIST_8021Q_INFO vlanTag =
            (PNDIS_NET_BUFFER_LIST_8021Q_INFO)(PVOID *)&vlanTagValue;
        flow->l2.vlanTci = htons(vlanTag->TagHeader.VlanId | OVSWIN_VLAN_CFI |
                                 (vlanTag->TagHeader.UserPriority << 13));
    } else {
        if (eth->dix.typeNBO == ETH_TYPE_802_1PQ_NBO) {
            Eth_802_1pq_Tag *tag= (Eth_802_1pq_Tag *)&eth->dix.typeNBO;
            flow->l2.vlanTci = ((UINT16)tag->priority << 13) |
                               OVSWIN_VLAN_CFI |
                               ((UINT16)tag->vidHi << 8)  | tag->vidLo;
            offset = sizeof (Eth_802_1pq_Tag);
        } else {
            flow->l2.vlanTci = 0;
        }
        /*
        * XXX
        * Please note after this point, src mac and dst mac should
        * not be accessed through eth
        */
        eth = (Eth_Header *)((UINT8 *)eth + offset);
    }

    /*
     * dl_type.
     *
     * XXX assume that at least the first
     * 12 bytes of received packets are mapped.  This code has the stronger
     * assumption that at least the first 22 bytes of 'packet' is mapped (if my
     * arithmetic is right).
     */
    if (ETH_TYPENOT8023(eth->dix.typeNBO)) {
        flow->l2.dlType = eth->dix.typeNBO;
        layers->l3Offset = ETH_HEADER_LEN_DIX + offset;
    } else if (OvsPacketLenNBL(packet)  >= ETH_HEADER_LEN_802_3 &&
              eth->e802_3.llc.dsap == 0xaa &&
              eth->e802_3.llc.ssap == 0xaa &&
              eth->e802_3.llc.control == ETH_LLC_CONTROL_UFRAME &&
              eth->e802_3.snap.snapOrg[0] == 0x00 &&
              eth->e802_3.snap.snapOrg[1] == 0x00 &&
              eth->e802_3.snap.snapOrg[2] == 0x00) {
        flow->l2.dlType = eth->e802_3.snap.snapType.typeNBO;
        layers->l3Offset = ETH_HEADER_LEN_802_3 + offset;
    } else {
        flow->l2.dlType = htons(OVSWIN_DL_TYPE_NONE);
        layers->l3Offset = ETH_HEADER_LEN_DIX + offset;
    }

    flow->l2.keyLen = OVS_WIN_TUNNEL_KEY_SIZE + OVS_L2_KEY_SIZE - flow->l2.offset;
    /* Network layer. */
    if (flow->l2.dlType == htons(ETH_TYPE_IPV4)) {
        struct IPHdr ip_storage;
        const struct IPHdr *nh;
        IpKey *ipKey = &flow->ipKey;

        flow->l2.keyLen += OVS_IP_KEY_SIZE;
        layers->isIPv4 = 1;
        nh = OvsGetIp(packet, layers->l3Offset, &ip_storage);
        if (nh) {
            layers->l4Offset = layers->l3Offset + nh->ihl * 4;

            ipKey->nwSrc = nh->saddr;
            ipKey->nwDst = nh->daddr;
            ipKey->nwProto = nh->protocol;

            ipKey->nwTos = nh->tos;
            if (nh->frag_off & htons(IP_MF | IP_OFFSET)) {
                ipKey->nwFrag = OVSWIN_NW_FRAG_ANY;
                if (nh->frag_off & htons(IP_OFFSET)) {
                    ipKey->nwFrag |= OVSWIN_NW_FRAG_LATER;
                }
            } else {
                ipKey->nwFrag = 0;
            }

            ipKey->nwTtl = nh->ttl;
            ipKey->l4.tpSrc = 0;
            ipKey->l4.tpDst = 0;

            if (!(nh->frag_off & htons(IP_OFFSET))) {
                if (ipKey->nwProto == SOCKET_IPPROTO_TCP) {
                    OvsParseTcp(packet, &ipKey->l4, layers);
                } else if (ipKey->nwProto == SOCKET_IPPROTO_UDP) {
                    OvsParseUdp(packet, &ipKey->l4, layers);
                } else if (ipKey->nwProto == SOCKET_IPPROTO_ICMP) {
                    ICMPHdr icmpStorage;
                    const ICMPHdr *icmp;

                    icmp = OvsGetIcmp(packet, layers->l4Offset, &icmpStorage);
                    if (icmp) {
                        ipKey->l4.tpSrc = htons(icmp->type);
                        ipKey->l4.tpDst = htons(icmp->code);
                        layers->l7Offset = layers->l4Offset + sizeof *icmp;
                    }
                }
            }
        } else {
            ((UINT64 *)ipKey)[0] = 0;
            ((UINT64 *)ipKey)[1] = 0;
        }
    } else if (flow->l2.dlType == htons(ETH_TYPE_IPV6)) {
        NDIS_STATUS status;
        flow->l2.keyLen += OVS_IPV6_KEY_SIZE;
        status = OvsParseIPv6(packet, flow, layers);
        if (status != NDIS_STATUS_SUCCESS) {
            memset(&flow->ipv6Key, 0, sizeof (Ipv6Key));
            return status;
        }
        layers->isIPv6 = 1;
        flow->ipv6Key.l4.tpSrc = 0;
        flow->ipv6Key.l4.tpDst = 0;
        flow->ipv6Key.pad = 0;

        if (flow->ipv6Key.nwProto == SOCKET_IPPROTO_TCP) {
            OvsParseTcp(packet, &(flow->ipv6Key.l4), layers);
        } else if (flow->ipv6Key.nwProto == SOCKET_IPPROTO_UDP) {
            OvsParseUdp(packet, &(flow->ipv6Key.l4), layers);
        } else if (flow->ipv6Key.nwProto == SOCKET_IPPROTO_ICMPV6) {
            OvsParseIcmpV6(packet, flow, layers);
            flow->l2.keyLen += (OVS_ICMPV6_KEY_SIZE - OVS_IPV6_KEY_SIZE);
        }
    } else if (flow->l2.dlType == htons(ETH_TYPE_ARP)) {
        EtherArp arpStorage;
        const EtherArp *arp;
        ArpKey *arpKey = &flow->arpKey;
        ((UINT64 *)arpKey)[0] = 0;
        ((UINT64 *)arpKey)[1] = 0;
        ((UINT64 *)arpKey)[2] = 0;
        flow->l2.keyLen += OVS_ARP_KEY_SIZE;
        arp = OvsGetArp(packet, layers->l3Offset, &arpStorage);
        if (arp && arp->ea_hdr.ar_hrd == htons(1) &&
            arp->ea_hdr.ar_pro == htons(ETH_TYPE_IPV4) &&
            arp->ea_hdr.ar_hln == ETH_ADDR_LENGTH &&
            arp->ea_hdr.ar_pln == 4) {
            /* We only match on the lower 8 bits of the opcode. */
            if (ntohs(arp->ea_hdr.ar_op) <= 0xff) {
                arpKey->nwProto = (UINT8)ntohs(arp->ea_hdr.ar_op);
            }
            if (arpKey->nwProto == ARPOP_REQUEST
                || arpKey->nwProto == ARPOP_REPLY) {
                memcpy(&arpKey->nwSrc, arp->arp_spa, 4);
                memcpy(&arpKey->nwDst, arp->arp_tpa, 4);
                memcpy(arpKey->arpSha, arp->arp_sha, ETH_ADDR_LENGTH);
                memcpy(arpKey->arpTha, arp->arp_tha, ETH_ADDR_LENGTH);
            }
        }
    }

    return NDIS_STATUS_SUCCESS;
}

__inline BOOLEAN
FlowEqual(UINT64 *src, UINT64 *dst, UINT32 size)
{
    UINT32 i;
    ASSERT((size & 0x7) == 0);
    ASSERT(((UINT64)src & 0x7) == 0);
    ASSERT(((UINT64)dst & 0x7) == 0);
    for (i = 0; i < (size >> 3); i++) {
        if (src[i] != dst[i]) {
            return FALSE;
        }
    }
    return TRUE;
}


/*
 * ----------------------------------------------------------------------------
 * AddFlow --
 *    Add a flow to flow table.
 *
 * Results:
 *   NDIS_STATUS_SUCCESS if no same flow in the flow table.
 * ----------------------------------------------------------------------------
 */
NTSTATUS
AddFlow(OVS_DATAPATH *datapath, OvsFlow *flow)
{
    PLIST_ENTRY head;

    if (OvsLookupFlow(datapath, &flow->key, &flow->hash, TRUE) != NULL) {
        return STATUS_INVALID_HANDLE;
    }

    head = &(datapath->flowTable[HASH_BUCKET(flow->hash)]);
    /*
     * We need fence here to make sure flow's nextPtr is updated before
     * head->nextPtr is updated.
     */
    KeMemoryBarrier();

    //KeAcquireSpinLock(&FilterDeviceExtension->NblQueueLock, &oldIrql);
    InsertTailList(head, &flow->ListEntry);
    //KeReleaseSpinLock(&FilterDeviceExtension->NblQueueLock, oldIrql);

    datapath->nFlows++;

    return STATUS_SUCCESS;
}


/* ----------------------------------------------------------------------------
 * RemoveFlow --
 *   Remove a flow from flow table, and added to wait list
 * ----------------------------------------------------------------------------
 */
VOID
RemoveFlow(OVS_DATAPATH *datapath,
           OvsFlow **flow)
{
    OvsFlow *f = *flow;
    *flow = NULL;
    UNREFERENCED_PARAMETER(datapath);

    ASSERT(datapath->nFlows);
    datapath->nFlows--;
    // Remove the flow  from queue
    RemoveEntryList(&f->ListEntry);
    FreeFlow(f);
}


/*
 * ----------------------------------------------------------------------------
 * OvsLookupFlow --
 *
 *    Find flow from flow table based on flow key.
 *    Caller should either hold portset handle or should
 *    have a flowRef in datapath or Acquired datapath.
 *
 * Results:
 *    Flow pointer if lookup successful.
 *    NULL if not exists.
 * ----------------------------------------------------------------------------
 */
OvsFlow *
OvsLookupFlow(OVS_DATAPATH *datapath,
              const OvsFlowKey *key,
              UINT64 *hash,
              BOOLEAN hashValid)
{
    PLIST_ENTRY link, head;
    UINT16 offset = key->l2.offset;
    UINT16 size = key->l2.keyLen;
    UINT8 *start;

    ASSERT(key->tunKey.dst || offset == sizeof (OvsIPv4TunnelKey));
    ASSERT(!key->tunKey.dst || offset == 0);

    start = (UINT8 *)key + offset;

    if (!hashValid) {
        *hash = OvsJhashBytes(start, size, 0);
    }

    head = &datapath->flowTable[HASH_BUCKET(*hash)];
    link  = head->Flink;
    while (link != head) {
        OvsFlow *flow = CONTAINING_RECORD(link, OvsFlow, ListEntry);

        if (flow->hash == *hash &&
            flow->key.l2.val == key->l2.val &&
            FlowEqual((UINT64 *)((uint8 *)&flow->key + offset),
                         (UINT64 *)start, size)) {
            return flow;
        }
        link = link->Flink;
    }
    return NULL;
}


/*
 * ----------------------------------------------------------------------------
 * OvsHashFlow --
 *    Calculate the hash for the given flow key.
 * ----------------------------------------------------------------------------
 */
UINT64
OvsHashFlow(const OvsFlowKey *key)
{
    UINT16 offset = key->l2.offset;
    UINT16 size = key->l2.keyLen;
    UINT8 *start;

    ASSERT(key->tunKey.dst || offset == sizeof (OvsIPv4TunnelKey));
    ASSERT(!key->tunKey.dst || offset == 0);
    start = (UINT8 *)key + offset;
    return OvsJhashBytes(start, size, 0);
}


/*
 * ----------------------------------------------------------------------------
 * FreeFlow --
 *    Free a flow and its actions.
 * ----------------------------------------------------------------------------
 */
VOID
FreeFlow(OvsFlow *flow)
{
    ASSERT(flow);
    OvsFreeMemory(flow);
}

NTSTATUS
OvsDoDumpFlows(OvsFlowDumpInput *dumpInput,
               OvsFlowDumpOutput *dumpOutput,
               UINT32 *replyLen)
{
    UINT32 dpNo;
    OVS_DATAPATH *datapath = NULL;
    OvsFlow *flow;
    PLIST_ENTRY node, head;
    UINT32 column = 0;
    UINT32 rowIndex, columnIndex;
    LOCK_STATE_EX dpLockState;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN findNextNonEmpty = FALSE;

    dpNo = dumpInput->dpNo;
    NdisAcquireSpinLock(gOvsCtrlLock);
    if (gOvsSwitchContext == NULL ||
        gOvsSwitchContext->dpNo != dpNo) {
        status = STATUS_INVALID_PARAMETER;
        goto unlock;
    }

    rowIndex = dumpInput->position[0];
    if (rowIndex >= OVS_FLOW_TABLE_SIZE) {
        dumpOutput->n = 0;
        *replyLen = sizeof(*dumpOutput);
        goto unlock;
    }

    columnIndex = dumpInput->position[1];

    datapath = &gOvsSwitchContext->datapath;
    ASSERT(datapath);
    OvsAcquireDatapathRead(datapath, &dpLockState, FALSE);

    head = &datapath->flowTable[rowIndex];
    node = head->Flink;

    while (column < columnIndex) {
        if (node == head) {
            break;
        }
        node = node->Flink;
        column++;
    }

    if (node == head) {
        findNextNonEmpty = TRUE;
        columnIndex = 0;
    }

    if (findNextNonEmpty) {
        while (head == node) {
            if (++rowIndex >= OVS_FLOW_TABLE_SIZE) {
                dumpOutput->n = 0;
                goto dp_unlock;
            }
            head = &datapath->flowTable[rowIndex];
            node = head->Flink;
        }
    }

    ASSERT(node != head);
    ASSERT(rowIndex < OVS_FLOW_TABLE_SIZE);

    flow = CONTAINING_RECORD(node, OvsFlow, ListEntry);
    status = ReportFlowInfo(flow, dumpInput->getFlags, dumpInput->actionsLen,
                                                            &dumpOutput->flow);

    if (status == STATUS_BUFFER_TOO_SMALL) {
        dumpOutput->n = sizeof(OvsFlowDumpOutput) + flow->actionsLen;
        *replyLen = sizeof(*dumpOutput);
    } else {
        dumpOutput->n = 1; //one flow reported.
        *replyLen = sizeof(*dumpOutput) + dumpOutput->flow.actionsLen;
    }

    dumpOutput->position[0] = rowIndex;
    dumpOutput->position[1] = ++columnIndex;

dp_unlock:
    OvsReleaseDatapath(datapath, &dpLockState);

unlock:
    NdisReleaseSpinLock(gOvsCtrlLock);
    return status;
}

NTSTATUS
OvsDumpFlowIoctl(PVOID inputBuffer,
                 UINT32 inputLength,
                 PVOID outputBuffer,
                 UINT32 outputLength,
                 UINT32 *replyLen)
{
    OvsFlowDumpOutput *dumpOutput = (OvsFlowDumpOutput *)outputBuffer;
    OvsFlowDumpInput *dumpInput = (OvsFlowDumpInput *)inputBuffer;

    if (inputBuffer == NULL || outputBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((inputLength != sizeof(OvsFlowDumpInput))
        || (outputLength != sizeof *dumpOutput + dumpInput->actionsLen)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    return OvsDoDumpFlows(dumpInput, dumpOutput, replyLen);
}

static NTSTATUS
ReportFlowInfo(OvsFlow *flow,
               UINT32 getFlags,
               UINT32 getActionsLen,
               OvsFlowInfo *info)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (getFlags & FLOW_GET_KEY) {
        // always copy the tunnel key part
        RtlCopyMemory(&info->key, &flow->key,
                            flow->key.l2.keyLen + flow->key.l2.offset);
    }

    if (getFlags & FLOW_GET_STATS) {
        OvsFlowStats *stats = &info->stats;
        stats->packetCount = flow->packetCount;
        stats->byteCount = flow->byteCount;
        stats->used = (UINT32)flow->used;
        stats->tcpFlags = flow->tcpFlags;
    }

    if (getFlags & FLOW_GET_ACTIONS) {
        if (flow->actionsLen == 0) {
            info->actionsLen = 0;
        } else if (flow->actionsLen > getActionsLen) {
            info->actionsLen = 0;
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            RtlCopyMemory(info->actions, flow->actions, flow->actionsLen);
            info->actionsLen = flow->actionsLen;
        }
    }

    return status;
}

NTSTATUS
OvsPutFlowIoctl(PVOID inputBuffer,
                UINT32 inputLength,
                PVOID outputBuffer,
                UINT32 outputLength,
                UINT32 *replyLen)
{
    NTSTATUS status = STATUS_SUCCESS;
    OVS_DATAPATH *datapath = NULL;
    struct OvsFlowStats stats;
    ULONG actionsLen;
    OvsFlowPut *put;
    UINT32 dpNo;
    LOCK_STATE_EX dpLockState;

    if ((inputLength < sizeof(OvsFlowPut)) || (inputBuffer == NULL)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    if ((outputLength != sizeof(stats)) || (outputBuffer == NULL)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    put = (OvsFlowPut *)inputBuffer;
    if (put->actionsLen > 0) {
        actionsLen = put->actionsLen;
    } else {
        actionsLen = 0;
    }
    if (inputLength != actionsLen + sizeof(*put)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    dpNo = put->dpNo;
    NdisAcquireSpinLock(gOvsCtrlLock);
    if (gOvsSwitchContext == NULL ||
        gOvsSwitchContext->dpNo != dpNo) {
        status = STATUS_INVALID_PARAMETER;
        goto unlock;
    }

    datapath = &gOvsSwitchContext->datapath;
    ASSERT(datapath);
    RtlZeroMemory(&stats, sizeof(stats));
    OvsAcquireDatapathWrite(datapath, &dpLockState, FALSE);
    status = HandleFlowPut(put, datapath, &stats);
    OvsReleaseDatapath(datapath, &dpLockState);

    if (status == STATUS_SUCCESS) {
        // Copy stats to User mode app
        NdisMoveMemory(outputBuffer, (PVOID)&stats, sizeof(stats));
        *replyLen = sizeof stats;
    }

unlock:
    NdisReleaseSpinLock(gOvsCtrlLock);
    return status;
}


/* Handles flow add, modify as well as delete */
static NTSTATUS
HandleFlowPut(OvsFlowPut *put,
              OVS_DATAPATH *datapath,
              struct OvsFlowStats *stats)
{
    BOOLEAN   mayCreate, mayModify, mayDelete;
    OvsFlow   *KernelFlow;
    UINT64    hash;
    NTSTATUS  status = STATUS_SUCCESS;

    mayCreate = (put->flags & OVSWIN_FLOW_PUT_CREATE) != 0;
    mayModify = (put->flags & OVSWIN_FLOW_PUT_MODIFY) != 0;
    mayDelete = (put->flags & OVSWIN_FLOW_PUT_DELETE) != 0;

    if ((mayCreate || mayModify) == mayDelete) {
        return STATUS_INVALID_PARAMETER;
    }

    KernelFlow = OvsLookupFlow(datapath, &put->key, &hash, FALSE);
    if (!KernelFlow) {
        if (!mayCreate) {
            return STATUS_INVALID_PARAMETER;
        }

        status = OvsPrepareFlow(&KernelFlow, put, hash);
        if (status != STATUS_SUCCESS) {
            FreeFlow(KernelFlow);
            return STATUS_UNSUCCESSFUL;
        }

        status = AddFlow(datapath, KernelFlow);
        if (status != STATUS_SUCCESS) {
            FreeFlow(KernelFlow);
            return STATUS_UNSUCCESSFUL;
        }

        /* Validate the flow addition */
        {
            UINT64 newHash;
            OvsFlow *flow = OvsLookupFlow(datapath, &put->key, &newHash,
                                                                    FALSE);
            ASSERT(flow);
            ASSERT(newHash == hash);
            if (!flow || newHash != hash) {
                return STATUS_UNSUCCESSFUL;
            }
        }
    } else {
        stats->packetCount = KernelFlow->packetCount;
        stats->byteCount = KernelFlow->byteCount;
        stats->tcpFlags = KernelFlow->tcpFlags;
        stats->used = (UINT32)KernelFlow->used;

        if (mayModify) {
            OvsFlow *newFlow;
            status = OvsPrepareFlow(&newFlow, put, hash);
            if (status != STATUS_SUCCESS) {
                return STATUS_UNSUCCESSFUL;
            }

            KernelFlow = OvsLookupFlow(datapath, &put->key, &hash, TRUE);
            if (KernelFlow)  {
                if ((put->flags & OVSWIN_FLOW_PUT_CLEAR) == 0) {
                    newFlow->packetCount = KernelFlow->packetCount;
                    newFlow->byteCount = KernelFlow->byteCount;
                    newFlow->tcpFlags = KernelFlow->tcpFlags;
                }
                RemoveFlow(datapath, &KernelFlow);
            }  else  {
                if ((put->flags & OVSWIN_FLOW_PUT_CLEAR) == 0)  {
                    newFlow->packetCount = stats->packetCount;
                    newFlow->byteCount = stats->byteCount;
                    newFlow->tcpFlags = stats->tcpFlags;
                }
            }
            status = AddFlow(datapath, newFlow);
            ASSERT(status == STATUS_SUCCESS);

            /* Validate the flow addition */
            {
                UINT64 newHash;
                OvsFlow *testflow = OvsLookupFlow(datapath, &put->key,
                                                            &newHash, FALSE);
                ASSERT(testflow);
                ASSERT(newHash == hash);
                if (!testflow || newHash != hash) {
                    FreeFlow(newFlow);
                    return STATUS_UNSUCCESSFUL;
                }
            }
        } else {
            if (mayDelete) {
                if (KernelFlow) {
                    RemoveFlow(datapath, &KernelFlow);
                }
            } else {
                return STATUS_UNSUCCESSFUL;
            }
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
OvsPrepareFlow(OvsFlow **flow,
               const OvsFlowPut *put,
               UINT64 hash)
{
    OvsFlow     *localFlow = *flow;
    NTSTATUS status = STATUS_SUCCESS;

    do {
        *flow = localFlow =
            OvsAllocateMemory(sizeof(OvsFlow) + put->actionsLen);
        if (localFlow == NULL) {
            status = STATUS_NO_MEMORY;
            break;
        }

        localFlow->key = put->key;
        localFlow->actionsLen = put->actionsLen;
        if (put->actionsLen) {
            NdisMoveMemory((PUCHAR)localFlow->actions, put->actions,
                                       put->actionsLen);
        }
        localFlow->userActionsLen = 0;  // 0 indicate no conversion is made
        localFlow->used = 0;
        localFlow->packetCount = 0;
        localFlow->byteCount = 0;
        localFlow->tcpFlags = 0;
        localFlow->hash = hash;
    } while(FALSE);

    return status;
}

NTSTATUS
OvsGetFlowIoctl(PVOID inputBuffer,
                UINT32 inputLength,
                PVOID outputBuffer,
                UINT32 outputLength,
                UINT32 *replyLen)
{
    NTSTATUS status = STATUS_SUCCESS;
    OVS_DATAPATH *datapath = NULL;
    OvsFlow *flow;
    UINT32 getFlags, getActionsLen;
    OvsFlowGetInput *getInput;
    OvsFlowGetOutput *getOutput;
    UINT64 hash;
    UINT32 dpNo;
    LOCK_STATE_EX dpLockState;

    if (inputLength != sizeof(OvsFlowGetInput)
        || inputBuffer == NULL) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    getInput = (OvsFlowGetInput *) inputBuffer;
    getFlags = getInput->getFlags;
    getActionsLen = getInput->actionsLen;
    if (getInput->getFlags & FLOW_GET_KEY) {
        return STATUS_INVALID_PARAMETER;
    }

    if (outputBuffer == NULL
        || outputLength != (sizeof *getOutput +
                            getInput->actionsLen)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    dpNo = getInput->dpNo;
    NdisAcquireSpinLock(gOvsCtrlLock);
    if (gOvsSwitchContext == NULL ||
        gOvsSwitchContext->dpNo != dpNo) {
        status = STATUS_INVALID_PARAMETER;
        goto unlock;
    }

    datapath = &gOvsSwitchContext->datapath;
    ASSERT(datapath);
    OvsAcquireDatapathRead(datapath, &dpLockState, FALSE);
    flow = OvsLookupFlow(datapath, &getInput->key, &hash, FALSE);
    if (!flow) {
        status = STATUS_INVALID_PARAMETER;
        goto dp_unlock;
    }

    // XXX: can be optimized to return only how much is written out
    *replyLen = outputLength;
    getOutput = (OvsFlowGetOutput *)outputBuffer;
    ReportFlowInfo(flow, getFlags, getActionsLen, &getOutput->info);

dp_unlock:
    OvsReleaseDatapath(datapath, &dpLockState);
unlock:
    NdisReleaseSpinLock(gOvsCtrlLock);
    return status;
}

NTSTATUS
OvsFlushFlowIoctl(PVOID inputBuffer,
                  UINT32 inputLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    OVS_DATAPATH *datapath = NULL;
    UINT32 dpNo;
    LOCK_STATE_EX dpLockState;

    if (inputLength != sizeof(UINT32) || inputBuffer == NULL) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    dpNo = *(UINT32 *)inputBuffer;
    NdisAcquireSpinLock(gOvsCtrlLock);
    if (gOvsSwitchContext == NULL ||
        gOvsSwitchContext->dpNo != dpNo) {
        status = STATUS_INVALID_PARAMETER;
        goto unlock;
    }

    datapath = &gOvsSwitchContext->datapath;
    ASSERT(datapath);
    OvsAcquireDatapathWrite(datapath, &dpLockState, FALSE);
    DeleteAllFlows(datapath);
    OvsReleaseDatapath(datapath, &dpLockState);

unlock:
    NdisReleaseSpinLock(gOvsCtrlLock);
    return status;
}

#pragma warning( pop )
