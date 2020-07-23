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

#include "Conntrack.h"
#include "IpFragment.h"
#include "Jhash.h"
#include "PacketParser.h"
#include "Event.h"
#include "Conntrack-nat.h"

#pragma warning(push)
#pragma warning(disable:4311)

#define WINDOWS_TICK 10000000
#define SEC_TO_UNIX_EPOCH 11644473600LL
#define SEC_TO_NANOSEC 1000000000LL
#define CT_MAX_ZONE (UINT16_MAX + 1)

KSTART_ROUTINE OvsConntrackEntryCleaner;
static PLIST_ENTRY ovsConntrackTable;
static OVS_CT_THREAD_CTX ctThreadCtx;
static PNDIS_RW_LOCK_EX *ovsCtBucketLock = NULL;
static NDIS_SPIN_LOCK ovsCtZoneLock;
static POVS_CT_ZONE_INFO zoneInfo = NULL;
extern POVS_SWITCH_CONTEXT gOvsSwitchContext;
static ULONG ctTotalEntries;
static ULONG defaultCtLimit;

static __inline OvsCtFlush(UINT16 zone, struct ovs_key_ct_tuple_ipv4 *tuple);
static __inline NDIS_STATUS
MapNlToCtTuple(POVS_MESSAGE msgIn, PNL_ATTR attr,
               struct ovs_key_ct_tuple_ipv4 *ct_tuple);
/*
 *----------------------------------------------------------------------------
 * OvsInitConntrack
 *     Initialize the components used by Connection Tracking
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsInitConntrack(POVS_SWITCH_CONTEXT context)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE threadHandle = NULL;
    ctTotalEntries = 0;
    UINT32 numBucketLocks = CT_HASH_TABLE_SIZE;

    /* Init the Hash Buffer */
    ovsConntrackTable = OvsAllocateMemoryWithTag(sizeof(LIST_ENTRY)
                                                 * CT_HASH_TABLE_SIZE,
                                                 OVS_CT_POOL_TAG);
    if (ovsConntrackTable == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ovsCtBucketLock = OvsAllocateMemoryWithTag(sizeof(PNDIS_RW_LOCK_EX)
                                               * CT_HASH_TABLE_SIZE,
                                               OVS_CT_POOL_TAG);
    if (ovsCtBucketLock == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto freeTable;
    }

    for (UINT32 i = 0; i < CT_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&ovsConntrackTable[i]);
        ovsCtBucketLock[i] = NdisAllocateRWLock(context->NdisFilterHandle);
        if (ovsCtBucketLock[i] == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            numBucketLocks = i;
            goto freeBucketLock;
        }
    }

    /* Init CT Cleaner Thread */
    KeInitializeEvent(&ctThreadCtx.event, NotificationEvent, FALSE);
    status = PsCreateSystemThread(&threadHandle, SYNCHRONIZE, NULL, NULL,
                                  NULL, OvsConntrackEntryCleaner,
                                  &ctThreadCtx);

    if (status != STATUS_SUCCESS) {
        goto freeBucketLock;
    }

    ObReferenceObjectByHandle(threadHandle, SYNCHRONIZE, NULL, KernelMode,
                              &ctThreadCtx.threadObject, NULL);
    ZwClose(threadHandle);
    threadHandle = NULL;

    zoneInfo = OvsAllocateMemoryWithTag(sizeof(OVS_CT_ZONE_INFO) *
                                        CT_MAX_ZONE, OVS_CT_POOL_TAG);
    if (zoneInfo == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto freeBucketLock;
    }

    NdisAllocateSpinLock(&ovsCtZoneLock);
    defaultCtLimit = CT_MAX_ENTRIES;
    for (UINT32 i = 0; i < CT_MAX_ZONE; i++) {
        zoneInfo[i].entries = 0;
        zoneInfo[i].limit = defaultCtLimit;
    }

    status = OvsNatInit();

    if (status != STATUS_SUCCESS) {
        OvsCleanupConntrack();
    }
    return STATUS_SUCCESS;

freeBucketLock:
    for (UINT32 i = 0; i < numBucketLocks; i++) {
        if (ovsCtBucketLock[i] != NULL) {
            NdisFreeRWLock(ovsCtBucketLock[i]);
        }
    }
    OvsFreeMemoryWithTag(ovsCtBucketLock, OVS_CT_POOL_TAG);
    ovsCtBucketLock = NULL;
freeTable:
    OvsFreeMemoryWithTag(ovsConntrackTable, OVS_CT_POOL_TAG);
    ovsConntrackTable = NULL;
    return status;
}

/*
 *----------------------------------------------------------------------------
 * OvsCleanupConntrack
 *     Cleanup memory and thread that were spawned for Connection tracking
 *----------------------------------------------------------------------------
 */
VOID
OvsCleanupConntrack(VOID)
{
    ctThreadCtx.exit = 1;
    KeSetEvent(&ctThreadCtx.event, 0, FALSE);
    KeWaitForSingleObject(ctThreadCtx.threadObject, Executive,
                          KernelMode, FALSE, NULL);
    ObDereferenceObject(ctThreadCtx.threadObject);

    /* Force flush all entries before removing */
    OvsCtFlush(0, NULL);

    if (ovsConntrackTable) {
        OvsFreeMemoryWithTag(ovsConntrackTable, OVS_CT_POOL_TAG);
        ovsConntrackTable = NULL;
    }

    for (UINT32 i = 0; i < CT_HASH_TABLE_SIZE; i++) {
        /* Disabling the uninitialized memory warning because it should
         * always be initialized during OvsInitConntrack */
#pragma warning(suppress: 6001)
        if (ovsCtBucketLock[i] != NULL) {
            NdisFreeRWLock(ovsCtBucketLock[i]);
        }
    }
    OvsFreeMemoryWithTag(ovsCtBucketLock, OVS_CT_POOL_TAG);
    ovsCtBucketLock = NULL;
    OvsNatCleanup();
    NdisFreeSpinLock(&ovsCtZoneLock);
    if (zoneInfo) {
        OvsFreeMemoryWithTag(zoneInfo, OVS_CT_POOL_TAG);
    }
}

VOID
OvsCtSetZoneLimit(int zone, ULONG value) {
    NdisAcquireSpinLock(&ovsCtZoneLock);
    if (zone == -1) {
        /* Set default limit for all zones. */
        defaultCtLimit = value;
        for (UINT32 i = 0; i < CT_MAX_ZONE; i++) {
            zoneInfo[i].limit = value;
        }
    } else {
        zoneInfo[(UINT16)zone].limit = value;
    }
    NdisReleaseSpinLock(&ovsCtZoneLock);
}

/*
 *----------------------------------------------------------------------------
 * OvsCtHashKey
 *     Compute hash using 5-tuple and zone.
 *----------------------------------------------------------------------------
 */
UINT32
OvsCtHashKey(const OVS_CT_KEY *key)
{
    UINT32 hsrc, hdst, hash;
    hsrc = key->src.addr.ipv4 | ntohl(key->src.port);
    hdst = key->dst.addr.ipv4 | ntohl(key->dst.port);
    hash = hsrc ^ hdst; /* TO identify reverse traffic */
    hash = hash | (key->zone + key->nw_proto);
    hash = OvsJhashWords((uint32_t*) &hash, 1, hash);
    return hash;
}

static __inline VOID
OvsCtKeyReverse(OVS_CT_KEY *key)
{
    struct ct_endpoint tmp;
    tmp = key->src;
    key->src = key->dst;
    key->dst = tmp;
}

static __inline VOID
OvsCtUpdateFlowKey(struct OvsFlowKey *key,
                   UINT32 state,
                   UINT16 zone,
                   UINT32 mark,
                   struct ovs_key_ct_labels *labels)
{
    key->ct.state = state | OVS_CS_F_TRACKED;
    key->ct.zone = zone;
    key->ct.mark = mark;
    if (labels) {
        NdisMoveMemory(&key->ct.labels, labels,
                       sizeof(struct ovs_key_ct_labels));
    } else {
        memset(&key->ct.labels, 0,
               sizeof(struct ovs_key_ct_labels));
    }
}

/*
 *----------------------------------------------------------------------------
 * OvsPostCtEventEntry
 *     Assumes ct entry lock is acquired
 *     XXX Refactor OvsPostCtEvent() as it does not require ct entry lock.
 *----------------------------------------------------------------------------
 */
static __inline VOID
OvsPostCtEventEntry(POVS_CT_ENTRY entry, UINT8 type)
{
    OVS_CT_EVENT_ENTRY ctEventEntry = {0};
    NdisMoveMemory(&ctEventEntry.entry, entry, sizeof(OVS_CT_ENTRY));
    ctEventEntry.type = type;
    OvsPostCtEvent(&ctEventEntry);
}

static __inline VOID
OvsCtIncrementCounters(POVS_CT_ENTRY entry, BOOLEAN reply, PNET_BUFFER_LIST nbl)
{
    NdisAcquireSpinLock(&(entry->lock));
    if (reply) {
        entry->rev_key.byteCount+= OvsPacketLenNBL(nbl);
        entry->rev_key.packetCount++;
    } else {
        entry->key.byteCount += OvsPacketLenNBL(nbl);
        entry->key.packetCount++;
    }
    NdisReleaseSpinLock(&(entry->lock));
}

static __inline BOOLEAN
OvsCtAddEntry(POVS_CT_ENTRY entry,
              OvsConntrackKeyLookupCtx *ctx,
              PNAT_ACTION_INFO natInfo, UINT64 now)
{
    LOCK_STATE_EX lockState;
    NdisMoveMemory(&entry->key, &ctx->key, sizeof(OVS_CT_KEY));
    NdisMoveMemory(&entry->rev_key, &ctx->key, sizeof(OVS_CT_KEY));
    OvsCtKeyReverse(&entry->rev_key);

    /* NatInfo is always initialized to be disabled, so that if NAT action
     * fails, we will not end up deleting an non-existent NAT entry.
     */
    if (natInfo == NULL) {
        entry->natInfo.natAction = NAT_ACTION_NONE;
    } else {
        if (OvsIsForwardNat(natInfo->natAction)) {
            entry->natInfo = *natInfo;
            if (!OvsNatTranslateCtEntry(entry)) {
                return FALSE;
            }
            ctx->hash = OvsCtHashKey(&entry->key);
        } else {
            entry->natInfo.natAction = natInfo->natAction;
        }
    }

    entry->timestampStart = now;
    NdisAllocateSpinLock(&(entry->lock));
    UINT32 bucketIdx = ctx->hash & CT_HASH_TABLE_MASK;
    NdisAcquireRWLockWrite(ovsCtBucketLock[bucketIdx], &lockState, 0);
    InsertHeadList(&ovsConntrackTable[bucketIdx],
                   &entry->link);

    NdisInterlockedIncrement((PLONG)&ctTotalEntries);
    NdisInterlockedIncrement((PLONG)&zoneInfo[ctx->key.zone].entries);
    NdisReleaseRWLock(ovsCtBucketLock[bucketIdx], &lockState);
    return TRUE;
}

static __inline POVS_CT_ENTRY
OvsCtEntryCreate(OvsForwardingContext *fwdCtx,
                 UINT8 ipProto,
                 OVS_PACKET_HDR_INFO *layers,
                 OvsConntrackKeyLookupCtx *ctx,
                 OvsFlowKey *key,
                 PNAT_ACTION_INFO natInfo,
                 BOOLEAN commit,
                 UINT64 currentTime,
                 BOOLEAN *entryCreated)
{
    POVS_CT_ENTRY entry = NULL;
    UINT32 state = 0;
    POVS_CT_ENTRY parentEntry;
    PNET_BUFFER_LIST curNbl = fwdCtx->curNbl;

    *entryCreated = FALSE;
    state |= OVS_CS_F_NEW;
    switch (ipProto) {
    case IPPROTO_TCP:
    {
        UINT32 tcpPayloadLen;
        TCPHdr tcpStorage;
        const TCPHdr *tcp;
        tcp = OvsGetTcpHeader(curNbl, layers, &tcpStorage, &tcpPayloadLen);
        if (!OvsConntrackValidateTcpPacket(tcp)) {
            state = OVS_CS_F_INVALID;
            break;
        }

        if (commit) {
            entry = OvsConntrackCreateTcpEntry(tcp, currentTime,
                                               tcpPayloadLen);
        }
        break;
    }
    case IPPROTO_ICMP:
    {
        ICMPHdr storage;
        const ICMPHdr *icmp;
        icmp = OvsGetIcmp(curNbl, layers->l4Offset, &storage);
        if (!OvsConntrackValidateIcmpPacket(icmp)) {
            if(icmp) {
                OVS_LOG_TRACE("Invalid ICMP packet detected, icmp->type %u",
                              icmp->type);
            }
            state = OVS_CS_F_INVALID;
            break;
        }

        if (commit) {
            entry = OvsConntrackCreateIcmpEntry(currentTime);
        }
        break;
    }
    case IPPROTO_UDP:
    {
        if (commit) {
            entry = OvsConntrackCreateOtherEntry(currentTime);
        }
        break;
    }
    default:
        OVS_LOG_TRACE("Invalid packet detected, protocol not supported"
                      " ipProto %u", ipProto);
        state = OVS_CS_F_INVALID;
        break;
    }

    parentEntry = OvsCtRelatedLookup(ctx->key, currentTime);
    if (parentEntry != NULL && state != OVS_CS_F_INVALID) {
        state |= OVS_CS_F_RELATED;
    }
    if (state != OVS_CS_F_INVALID && commit) {
        if (entry) {
            entry->parent = parentEntry;
            if (OvsCtAddEntry(entry, ctx, natInfo, currentTime)) {
                *entryCreated = TRUE;
            } else {
                /* Unable to add entry to the list */
                OvsFreeMemoryWithTag(entry, OVS_CT_POOL_TAG);
                state = OVS_CS_F_INVALID;
                entry = NULL;
            }
        } else {
            /* OvsAllocateMemoryWithTag returned NULL; treat as invalid */
            state = OVS_CS_F_INVALID;
        }
    }

    OvsCtUpdateFlowKey(key, state, ctx->key.zone, 0, NULL);
    if (entry) {
        OvsCtIncrementCounters(entry, ctx->reply, curNbl);
    }
    return entry;
}

static enum CT_UPDATE_RES
OvsCtUpdateEntry(OVS_CT_ENTRY* entry,
                 PNET_BUFFER_LIST nbl,
                 UINT8 ipProto,
                 OVS_PACKET_HDR_INFO *layers,
                 BOOLEAN reply,
                 UINT64 now)
{
    CT_UPDATE_RES status;
    switch (ipProto) {
    case IPPROTO_TCP:
    {
        UINT32 tcpPayloadLen;
        TCPHdr tcpStorage;
        const TCPHdr *tcp;
        tcp = OvsGetTcpHeader(nbl, layers, &tcpStorage, &tcpPayloadLen);
        if (!tcp) {
            status = CT_UPDATE_INVALID;
            break;
        }
        NdisAcquireSpinLock(&(entry->lock));
        status = OvsConntrackUpdateTcpEntry(entry, tcp, reply, now,
                                            tcpPayloadLen);
        NdisReleaseSpinLock(&(entry->lock));
        break;
    }
    case IPPROTO_ICMP:
    {
        NdisAcquireSpinLock(&(entry->lock));
        status = OvsConntrackUpdateIcmpEntry(entry, reply, now);
        NdisReleaseSpinLock(&(entry->lock));
        break;
    }
    case IPPROTO_UDP:
    {
        NdisAcquireSpinLock(&(entry->lock));
        status = OvsConntrackUpdateOtherEntry(entry, reply, now);
        NdisReleaseSpinLock(&(entry->lock));
        break;
    }
    default:
        status = CT_UPDATE_INVALID;
        break;
    }
    return status;
}

/*
 *----------------------------------------------------------------------------
 * OvsCtEntryExpired
 *     Assumes ct entry lock is acquired
 *----------------------------------------------------------------------------
 */
static __inline BOOLEAN
OvsCtEntryExpired(POVS_CT_ENTRY entry)
{
    UINT64 currentTime;
    NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
    return entry->expiration < currentTime;
}

static __inline VOID
OvsCtEntryDelete(POVS_CT_ENTRY entry, BOOLEAN forceDelete)
{
    if (entry == NULL) {
        return;
    }
    KIRQL irql = KeGetCurrentIrql();
    OVS_ACQUIRE_SPIN_LOCK(&(entry->lock), irql);
    if (forceDelete || OvsCtEntryExpired(entry)) {
        if (entry->natInfo.natAction) {
            OvsNatDeleteKey(&entry->key);
        }
        NdisInterlockedDecrement((PLONG)&zoneInfo[entry->key.zone].entries);
        OvsPostCtEventEntry(entry, OVS_EVENT_CT_DELETE);
        RemoveEntryList(&entry->link);
        OVS_RELEASE_SPIN_LOCK(&(entry->lock), irql);
        NdisFreeSpinLock(&(entry->lock));
        if (entry->helper_name) {
            OvsFreeMemoryWithTag(entry->helper_name, OVS_CT_POOL_TAG);
        }
        OvsFreeMemoryWithTag(entry, OVS_CT_POOL_TAG);
        NdisInterlockedDecrement((PLONG)&ctTotalEntries);
        return;
    }
    OVS_RELEASE_SPIN_LOCK(&(entry->lock), irql);
}

static __inline NDIS_STATUS
OvsDetectCtPacket(OvsForwardingContext *fwdCtx,
                  OvsFlowKey *key)
{
    switch (ntohs(key->l2.dlType)) {
    case ETH_TYPE_IPV4:
        if (key->ipKey.nwFrag != OVS_FRAG_TYPE_NONE) {
            return OvsProcessIpv4Fragment(fwdCtx->switchContext,
                                          &fwdCtx->curNbl,
                                          fwdCtx->completionList,
                                          fwdCtx->fwdDetail->SourcePortId,
                                          &fwdCtx->layers,
                                          key->tunKey.tunnelId);
        }
        if (key->ipKey.nwProto == IPPROTO_TCP
            || key->ipKey.nwProto == IPPROTO_UDP
            || key->ipKey.nwProto == IPPROTO_ICMP) {
            return NDIS_STATUS_SUCCESS;
        }
        return NDIS_STATUS_NOT_SUPPORTED;
    case ETH_TYPE_IPV6:
        return NDIS_STATUS_NOT_SUPPORTED;
    }

    return NDIS_STATUS_NOT_SUPPORTED;
}

BOOLEAN
OvsCtEndpointsAreSame(OVS_CT_KEY ctxKey, OVS_CT_KEY entryKey)
{
    return ((NdisEqualMemory(&ctxKey.src, &entryKey.src,
                             sizeof(struct ct_endpoint))) &&
            (NdisEqualMemory(&ctxKey.dst, &entryKey.dst,
                             sizeof(struct ct_endpoint))));
}

POVS_CT_ENTRY
OvsCtLookup(OvsConntrackKeyLookupCtx *ctx)
{
    PLIST_ENTRY link;
    POVS_CT_ENTRY entry;
    BOOLEAN reply = FALSE;
    POVS_CT_ENTRY found = NULL;
    LOCK_STATE_EX lockStateTable;
    UINT32 bucketIdx;

    if (!ctTotalEntries) {
        return found;
    }

    /* Reverse NAT must be performed before OvsCtLookup, so here
     * we simply need to flip the src and dst in key and compare
     * they are equal. Note that flipped key is not equal to
     * rev_key due to NAT effect.
     */
    OVS_CT_KEY revCtxKey = ctx->key;
    OvsCtKeyReverse(&revCtxKey);

    KIRQL irql = KeGetCurrentIrql();
    bucketIdx = ctx->hash & CT_HASH_TABLE_MASK;
    NdisAcquireRWLockRead(ovsCtBucketLock[bucketIdx], &lockStateTable, 0);
    LIST_FORALL(&ovsConntrackTable[bucketIdx], link) {
        entry = CONTAINING_RECORD(link, OVS_CT_ENTRY, link);
        OVS_ACQUIRE_SPIN_LOCK(&(entry->lock), irql);

        if ((ctx->key.dl_type != entry->key.dl_type) ||
            (ctx->key.nw_proto != entry->key.nw_proto) ||
            (ctx->key.zone != entry->key.zone)) {
            OVS_RELEASE_SPIN_LOCK(&(entry->lock), irql);
            continue;
        }

        if (OvsCtEndpointsAreSame(ctx->key, entry->key)) {
            found = entry;
            reply = FALSE;
        }

        if (!found && OvsCtEndpointsAreSame(revCtxKey, entry->key)) {
            found = entry;
            reply = TRUE;
        }

        if (found) {
            if (OvsCtEntryExpired(found)) {
                found = NULL;
            } else {
                ctx->reply = reply;
            }
            OVS_RELEASE_SPIN_LOCK(&(entry->lock), irql);
            break;
        }
        OVS_RELEASE_SPIN_LOCK(&(entry->lock), irql);
    }

    NdisReleaseRWLock(ovsCtBucketLock[bucketIdx], &lockStateTable);
    ctx->entry = found;
    return found;
}

static UINT8
OvsReverseIcmpType(UINT8 type)
{
    switch (type) {
    case ICMP4_ECHO_REQUEST:
        return ICMP4_ECHO_REPLY;
    case ICMP4_ECHO_REPLY:
        return ICMP4_ECHO_REQUEST;
    case ICMP4_TIMESTAMP_REQUEST:
        return ICMP4_TIMESTAMP_REPLY;
    case ICMP4_TIMESTAMP_REPLY:
        return ICMP4_TIMESTAMP_REQUEST;
    case ICMP4_INFO_REQUEST:
        return ICMP4_INFO_REPLY;
    case ICMP4_INFO_REPLY:
        return ICMP4_INFO_REQUEST;
    default:
        return 0;
    }
}

static __inline NDIS_STATUS
OvsCtSetupLookupCtx(OvsFlowKey *flowKey,
                    UINT16 zone,
                    OvsConntrackKeyLookupCtx *ctx,
                    PNET_BUFFER_LIST curNbl,
                    UINT32 l4Offset)
{
    const OVS_NAT_ENTRY *natEntry;
    ctx->key.zone = zone;
    ctx->key.dl_type = flowKey->l2.dlType;
    ctx->related = FALSE;

    /* Extract L3 and L4*/
    if (flowKey->l2.dlType == htons(ETH_TYPE_IPV4)) {
        ctx->key.src.addr.ipv4 = flowKey->ipKey.nwSrc;
        ctx->key.dst.addr.ipv4 = flowKey->ipKey.nwDst;
        ctx->key.nw_proto = flowKey->ipKey.nwProto;

        ctx->key.src.port = flowKey->ipKey.l4.tpSrc;
        ctx->key.dst.port = flowKey->ipKey.l4.tpDst;
        if (flowKey->ipKey.nwProto == IPPROTO_ICMP) {
            ICMPHdr icmpStorage;
            const ICMPHdr *icmp;
            icmp = OvsGetIcmp(curNbl, l4Offset, &icmpStorage);
            ASSERT(icmp);

            /* Related bit is set when ICMP has an error */
            /* XXX parse out the appropriate src and dst from inner pkt */
            switch (icmp->type) {
            case ICMP4_ECHO_REQUEST:
            case ICMP4_ECHO_REPLY:
            case ICMP4_TIMESTAMP_REQUEST:
            case ICMP4_TIMESTAMP_REPLY:
            case ICMP4_INFO_REQUEST:
            case ICMP4_INFO_REPLY:
                if (icmp->code != 0) {
                    return NDIS_STATUS_INVALID_PACKET;
                }
                /* Separate ICMP connection: identified using id */
                ctx->key.dst.icmp_id = icmp->fields.echo.id;
                ctx->key.src.icmp_id = icmp->fields.echo.id;
                ctx->key.src.icmp_type = icmp->type;
                ctx->key.dst.icmp_type = OvsReverseIcmpType(icmp->type);
                break;
            case ICMP4_DEST_UNREACH:
            case ICMP4_TIME_EXCEEDED:
            case ICMP4_PARAM_PROB:
            case ICMP4_SOURCE_QUENCH:
            case ICMP4_REDIRECT: {
                /* XXX Handle inner packet */
                ctx->related = TRUE;
                break;
            }
            default:
                ctx->related = FALSE;
            }
        }
    } else if (flowKey->l2.dlType == htons(ETH_TYPE_IPV6)) {
        ctx->key.src.addr.ipv6 = flowKey->ipv6Key.ipv6Src;
        ctx->key.dst.addr.ipv6 = flowKey->ipv6Key.ipv6Dst;
        ctx->key.nw_proto = flowKey->ipv6Key.nwProto;

        ctx->key.src.port = flowKey->ipv6Key.l4.tpSrc;
        ctx->key.dst.port = flowKey->ipv6Key.l4.tpDst;
        /* XXX Handle ICMPv6 errors*/
    } else {
        return NDIS_STATUS_INVALID_PACKET;
    }

    natEntry = OvsNatLookup(&ctx->key, TRUE);
    if (natEntry) {
        /* Translate address first for reverse NAT */
        ctx->key = natEntry->ctEntry->key;
        OvsCtKeyReverse(&ctx->key);
    }

    ctx->hash = OvsCtHashKey(&ctx->key);
    return NDIS_STATUS_SUCCESS;
}

static __inline BOOLEAN
OvsDetectFtpPacket(OvsFlowKey *key) {
    return (key->ipKey.nwProto == IPPROTO_TCP &&
            (ntohs(key->ipKey.l4.tpDst) == IPPORT_FTP ||
            ntohs(key->ipKey.l4.tpSrc) == IPPORT_FTP));
}

/*
 *----------------------------------------------------------------------------
 * OvsProcessConntrackEntry
 *     Check the TCP flags and set the ct_state of the entry
 *----------------------------------------------------------------------------
 */
static __inline POVS_CT_ENTRY
OvsProcessConntrackEntry(OvsForwardingContext *fwdCtx,
                         OVS_PACKET_HDR_INFO *layers,
                         OvsConntrackKeyLookupCtx *ctx,
                         OvsFlowKey *key,
                         UINT16 zone,
                         NAT_ACTION_INFO *natInfo,
                         BOOLEAN commit,
                         UINT64 currentTime,
                         BOOLEAN *entryCreated)
{
    POVS_CT_ENTRY entry = ctx->entry;
    UINT32 state = 0;
    PNET_BUFFER_LIST curNbl = fwdCtx->curNbl;
    LOCK_STATE_EX lockStateTable;

    *entryCreated = FALSE;

    /* If an entry was found, update the state based on TCP flags */
    if (ctx->related) {
        state |= OVS_CS_F_RELATED;
        if (ctx->reply) {
            state |= OVS_CS_F_REPLY_DIR;
        }
    } else {
        CT_UPDATE_RES result;
        UINT32 bucketIdx;
        result = OvsCtUpdateEntry(entry, curNbl, key->ipKey.nwProto, layers,
                                  ctx->reply, currentTime);
        switch (result) {
        case CT_UPDATE_VALID:
            state |= OVS_CS_F_ESTABLISHED;
            if (ctx->reply) {
                state |= OVS_CS_F_REPLY_DIR;
            }
            break;
        case CT_UPDATE_INVALID:
            state |= OVS_CS_F_INVALID;
            break;
        case CT_UPDATE_NEW:
            //Delete and update the Conntrack
            bucketIdx = ctx->hash & CT_HASH_TABLE_MASK;
            NdisAcquireRWLockWrite(ovsCtBucketLock[bucketIdx], &lockStateTable, 0);
            OvsCtEntryDelete(ctx->entry, TRUE);
            NdisReleaseRWLock(ovsCtBucketLock[bucketIdx], &lockStateTable);
            ctx->entry = NULL;
            entry = OvsCtEntryCreate(fwdCtx, key->ipKey.nwProto, layers,
                                     ctx, key, natInfo, commit, currentTime,
                                     entryCreated);
            if (!entry) {
                return NULL;
            }
            break;
        case CT_UPDATE_VALID_NEW:
            state |= OVS_CS_F_NEW;
            break;
        }
    }
    if (entry) {
        NdisAcquireSpinLock(&(entry->lock));
        if (key->ipKey.nwProto == IPPROTO_TCP) {
            /* Update the related bit if there is a parent */
            if (entry->parent) {
                state |= OVS_CS_F_RELATED;
            } else {
                POVS_CT_ENTRY parentEntry;
                parentEntry = OvsCtRelatedLookup(ctx->key, currentTime);
                entry->parent = parentEntry;
                if (parentEntry != NULL) {
                    state |= OVS_CS_F_RELATED;
                }
            }
        }

        /* Copy mark and label from entry into flowKey. If actions specify
           different mark and label, update the flowKey. */
        OvsCtUpdateFlowKey(key, state, zone, entry->mark, &entry->labels);
        NdisReleaseSpinLock(&(entry->lock));
    } else {
        OvsCtUpdateFlowKey(key, state, zone, 0, NULL);
    }
    return entry;
}

static __inline VOID
OvsConntrackSetMark(OvsFlowKey *key,
                    POVS_CT_ENTRY entry,
                    MD_MARK *mark,
                    BOOLEAN *markChanged)
{
    POVS_CT_ENTRY parent = entry->parent;
    BOOLEAN changed = FALSE;
    UINT32 newMark = 0;

    if (parent && parent->mark) {
        newMark = parent->mark;
        changed = TRUE;
    } else if (mark) {
        newMark = mark->value | (entry->mark & ~(mark->mask));
        changed = TRUE;
    }

    if (changed && entry->mark != newMark) {
        entry->mark = newMark;
        key->ct.mark = newMark;
        *markChanged = TRUE;
    }
}

static __inline BOOLEAN
OvsConntrackIsLabelsNonZero(const struct ovs_key_ct_labels *labels)
{
    UINT8 i;

    for (i = 0; i < OVS_CT_LABELS_LEN_32; i++) {
        if (labels->ct_labels_32[i]) {
            return TRUE;
        }
    }

    return FALSE;
}

static __inline void
OvsConntrackSetLabels(OvsFlowKey *key,
                      POVS_CT_ENTRY entry,
                      MD_LABELS *labels,
                      BOOLEAN *labelChanged)
{
    POVS_CT_ENTRY parent = entry->parent;

    /* Inherit master's labels at labels initialization, if any. */
    if (!OvsConntrackIsLabelsNonZero(&entry->labels) &&
        parent && OvsConntrackIsLabelsNonZero(&parent->labels)) {
        RtlCopyMemory(&entry->labels, &parent->labels, OVS_CT_LABELS_LEN);
        *labelChanged = TRUE;
    }

    /* Update labels according to value of ct_label in ct commit */
    if (labels && OvsConntrackIsLabelsNonZero(&labels->mask)) {
        UINT8 i;
        UINT32 *dst = entry->labels.ct_labels_32;
        for (i = 0; i < OVS_CT_LABELS_LEN_32; i++) {
            dst[i] = (dst[i] & ~(labels->mask.ct_labels_32[i])) |
                     (labels->value.ct_labels_32[i] & labels->mask.ct_labels_32[i]);
        }

        *labelChanged = TRUE;
    }

    /* Update flow key's ct labels */
    NdisMoveMemory(&key->ct.labels, &entry->labels, OVS_CT_LABELS_LEN);
}

static void
OvsCtSetMarkLabel(OvsFlowKey *key,
                  POVS_CT_ENTRY entry,
                  MD_MARK *mark,
                  MD_LABELS *labels,
                  BOOLEAN *triggerUpdateEvent)
{
    OvsConntrackSetMark(key, entry, mark, triggerUpdateEvent);
    OvsConntrackSetLabels(key, entry, labels, triggerUpdateEvent);
}

/*
 *----------------------------------------------------------------------------
 * OvsCtUpdateTuple
 *     Assumes ct entry lock is acquired
 *----------------------------------------------------------------------------
 */
static __inline void
OvsCtUpdateTuple(OvsFlowKey *key, OVS_CT_KEY *ctKey)
{
    key->ct.tuple_ipv4.ipv4_src = ctKey->src.addr.ipv4_aligned;
    key->ct.tuple_ipv4.ipv4_dst = ctKey->dst.addr.ipv4_aligned;
    key->ct.tuple_ipv4.ipv4_proto = ctKey->nw_proto;

    /* Orig tuple Port is overloaded to take in ICMP-Type & Code */
    /* This mimics the behavior in lib/conntrack.c*/
    key->ct.tuple_ipv4.src_port = ctKey->nw_proto != IPPROTO_ICMP ?
                                    ctKey->src.port :
                                    htons(ctKey->src.icmp_type);
    key->ct.tuple_ipv4.dst_port = ctKey->nw_proto != IPPROTO_ICMP ?
                                    ctKey->dst.port :
                                    htons(ctKey->src.icmp_code);
}

static __inline NDIS_STATUS
OvsCtExecute_(OvsForwardingContext *fwdCtx,
              OvsFlowKey *key,
              OVS_PACKET_HDR_INFO *layers,
              BOOLEAN commit,
              BOOLEAN force,
              UINT16 zone,
              MD_MARK *mark,
              MD_LABELS *labels,
              PCHAR helper,
              PNAT_ACTION_INFO natInfo,
              BOOLEAN postUpdateEvent)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    BOOLEAN triggerUpdateEvent = FALSE;
    BOOLEAN entryCreated = FALSE;
    POVS_CT_ENTRY entry = NULL;
    POVS_CT_ENTRY parent = NULL;
    PNET_BUFFER_LIST curNbl = fwdCtx->curNbl;
    OvsConntrackKeyLookupCtx ctx = { 0 };
    LOCK_STATE_EX lockStateTable;
    UINT64 currentTime;
    NdisGetCurrentSystemTime((LARGE_INTEGER *) &currentTime);

    /* Retrieve the Conntrack Key related fields from packet */
    OvsCtSetupLookupCtx(key, zone, &ctx, curNbl, layers->l4Offset);

    /* Lookup Conntrack entries for a matching entry */
    entry = OvsCtLookup(&ctx);

    /* Delete entry in reverse direction if 'force' is specified */
    if (force && ctx.reply && entry) {
        UINT32 bucketIdx = ctx.hash & CT_HASH_TABLE_MASK;
        NdisAcquireRWLockWrite(ovsCtBucketLock[bucketIdx], &lockStateTable, 0);
        OvsCtEntryDelete(entry, TRUE);
        NdisReleaseRWLock(ovsCtBucketLock[bucketIdx], &lockStateTable);
        entry = NULL;
    }

    if (entry) {
        /* Increment stats for the entry if it wasn't tracked previously or
         * if they are on different zones
         */
        if ((entry->key.zone != key->ct.zone ||
               (!(key->ct.state & OVS_CS_F_TRACKED)))) {
            OvsCtIncrementCounters(entry, ctx.reply, curNbl);
        }
        /* Process the entry and update CT flags */
        entry = OvsProcessConntrackEntry(fwdCtx, layers, &ctx, key,
                                         zone, natInfo, commit, currentTime,
                                         &entryCreated);

    } else {
        if (commit && (ctTotalEntries >= CT_MAX_ENTRIES ||
            zoneInfo[ctx.key.zone].entries >= zoneInfo[ctx.key.zone].limit)) {
            /* Don't proceed with processing if the max limit has been hit.
             * This blocks only new entries from being created and doesn't
             * affect existing connections.
             */
            OVS_LOG_ERROR("Conntrack Limit hit: zone(%u), zoneLimit(%lu),"
                          "zoneEntries(%lu), ctTotalEntries(%lu)",
                           zone, zoneInfo[ctx.key.zone].limit,
                           zoneInfo[ctx.key.zone].entries, ctTotalEntries);
            return NDIS_STATUS_RESOURCES;
        }
        /* If no matching entry was found, create one and add New state */
        entry = OvsCtEntryCreate(fwdCtx, key->ipKey.nwProto,
                                 layers, &ctx,
                                 key, natInfo, commit, currentTime,
                                 &entryCreated);
    }

    if (entry == NULL) {
        return status;
    }

    /*
     * Note that natInfo is not the same as entry->natInfo here. natInfo
     * is decided by action in the openflow rule, entry->natInfo is decided
     * when the entry is created. In the reverse NAT case, natInfo is
     * NAT_ACTION_REVERSE, yet entry->natInfo is NAT_ACTION_SRC or
     * NAT_ACTION_DST without NAT_ACTION_REVERSE
     */
    KIRQL irql = KeGetCurrentIrql();
    OVS_ACQUIRE_SPIN_LOCK(&(entry->lock), irql);
    if (natInfo->natAction != NAT_ACTION_NONE) {
        OvsNatPacket(fwdCtx, entry, entry->natInfo.natAction,
                     key, ctx.reply);
    }

    OvsCtSetMarkLabel(key, entry, mark, labels, &triggerUpdateEvent);

    if (OvsDetectFtpPacket(key)) {
        /* FTP parser will always be loaded */
        status = OvsCtHandleFtp(curNbl, key, layers, currentTime, entry,
                                (ntohs(key->ipKey.l4.tpDst) == IPPORT_FTP));
        if (status != NDIS_STATUS_SUCCESS) {
            OVS_LOG_ERROR("Error while parsing the FTP packet");
        }
    }

    parent = entry->parent;
    /* The entry should have the same helper name with parent's */
    if (!entry->helper_name &&
        (helper || (parent && parent->helper_name))) {

        helper = helper ? helper : parent->helper_name;
        entry->helper_name = OvsAllocateMemoryWithTag(strlen(helper) + 1,
                                                      OVS_CT_POOL_TAG);
        if (!entry->helper_name) {
            OVS_LOG_ERROR("Error while allocating memory");
            OVS_RELEASE_SPIN_LOCK(&(entry->lock), irql);
            return NDIS_STATUS_RESOURCES;
        }
        memcpy(entry->helper_name, helper, strlen(helper) + 1);
    }

    /* Add original tuple information to flow Key */
    if (entry->key.dl_type == ntohs(ETH_TYPE_IPV4)) {
        if (parent != NULL) {
            OVS_ACQUIRE_SPIN_LOCK(&(parent->lock), irql);
            OvsCtUpdateTuple(key, &parent->key);
            OVS_RELEASE_SPIN_LOCK(&(parent->lock), irql);
        } else {
            OvsCtUpdateTuple(key, &entry->key);
        }
    }

    if (entryCreated) {
        OvsPostCtEventEntry(entry, OVS_EVENT_CT_NEW);
    } else if (postUpdateEvent && triggerUpdateEvent) {
        OvsPostCtEventEntry(entry, OVS_EVENT_CT_UPDATE);
    }

    OVS_RELEASE_SPIN_LOCK(&(entry->lock), irql);
    return status;
}

/*
 *---------------------------------------------------------------------------
 * OvsExecuteConntrackAction
 *     Executes Conntrack actions XXX - Add more
 *     For the Ipv4 fragments, consume the orginal fragment NBL
 *---------------------------------------------------------------------------
 */
NDIS_STATUS
OvsExecuteConntrackAction(OvsForwardingContext *fwdCtx,
                          OvsFlowKey *key,
                          const PNL_ATTR a)
{
    BOOLEAN commit = FALSE;
    BOOLEAN force = FALSE;
    BOOLEAN postUpdateEvent = FALSE;
    UINT16 zone = 0;
    UINT32 eventmask = 0;
    MD_MARK *mark = NULL;
    MD_LABELS *labels = NULL;
    PCHAR helper = NULL;
    NAT_ACTION_INFO natActionInfo;
    OVS_PACKET_HDR_INFO *layers = &fwdCtx->layers;
    NDIS_STATUS status;

    memset(&natActionInfo, 0, sizeof natActionInfo);
    status = OvsDetectCtPacket(fwdCtx, key);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    PNL_ATTR ctAttr = NULL;
    INT left;

    NL_NESTED_FOR_EACH (ctAttr, left, a) {
        switch(NlAttrType(ctAttr)) {
            case OVS_CT_ATTR_ZONE:
                zone = NlAttrGetU16(ctAttr);
                break;
            case OVS_CT_ATTR_COMMIT:
                commit = TRUE;
                break;
            case OVS_CT_ATTR_MARK:
                mark = NlAttrGet(ctAttr);
                break;
            case OVS_CT_ATTR_LABELS:
                labels = NlAttrGet(ctAttr);
                break;
            case OVS_CT_ATTR_HELPER:
                helper = NlAttrGetString(ctAttr);
                if (helper == NULL) {
                    return NDIS_STATUS_INVALID_PARAMETER;
                }
                if (strcmp("ftp", helper) != 0 && strcmp("tftp", helper) != 0) {
                    /* Only support FTP/TFTP */
                    return NDIS_STATUS_NOT_SUPPORTED;
                }
                break;
            case OVS_CT_ATTR_FORCE_COMMIT:
                force = TRUE;
                /* Force implicitly means commit */
                commit = TRUE;
                break;
            case OVS_CT_ATTR_EVENTMASK:
                eventmask = NlAttrGetU32(ctAttr);
                /* Only mark and label updates are supported. */
                if (eventmask & (1 << IPCT_MARK | 1 << IPCT_LABEL))
                    postUpdateEvent = TRUE;
                break;
            case OVS_CT_ATTR_NAT:
                natActionInfo.natAction = NAT_ACTION_NONE;
                /* Pares Nested NAT attributes. */
                PNL_ATTR natAttr;
                unsigned int natLeft;
                BOOLEAN hasMinIp = FALSE;
                BOOLEAN hasMinPort = FALSE;
                BOOLEAN hasMaxIp = FALSE;
                BOOLEAN hasMaxPort = FALSE;
                NL_NESTED_FOR_EACH_UNSAFE (natAttr, natLeft, ctAttr) {
                    enum ovs_nat_attr subtype = NlAttrType(natAttr);
                    switch(subtype) {
                    case OVS_NAT_ATTR_SRC:
                    case OVS_NAT_ATTR_DST:
                        natActionInfo.natAction |=
                            ((subtype == OVS_NAT_ATTR_SRC)
                                ? NAT_ACTION_SRC : NAT_ACTION_DST);
                        break;
                    case OVS_NAT_ATTR_IP_MIN:
                        memcpy(&natActionInfo.minAddr,
                                NlAttrData(natAttr), NlAttrGetSize(natAttr));
                        hasMinIp = TRUE;
                        break;
                    case OVS_NAT_ATTR_IP_MAX:
                        memcpy(&natActionInfo.maxAddr,
                                NlAttrData(natAttr), NlAttrGetSize(natAttr));
                        hasMaxIp = TRUE;
                        break;
                    case OVS_NAT_ATTR_PROTO_MIN:
                        natActionInfo.minPort = NlAttrGetU16(natAttr);
                        hasMinPort = TRUE;
                        break;
                    case OVS_NAT_ATTR_PROTO_MAX:
                        natActionInfo.maxPort = NlAttrGetU16(natAttr);
                        hasMaxPort = TRUE;
                        break;
                    case OVS_NAT_ATTR_PERSISTENT:
                    case OVS_NAT_ATTR_PROTO_HASH:
                    case OVS_NAT_ATTR_PROTO_RANDOM:
                        break;
                    }
                }
                if (natActionInfo.natAction == NAT_ACTION_NONE) {
                    natActionInfo.natAction = NAT_ACTION_REVERSE;
                }
                if (hasMinIp && !hasMaxIp) {
                    memcpy(&natActionInfo.maxAddr,
                            &natActionInfo.minAddr,
                            sizeof(natActionInfo.maxAddr));
                }
                if (hasMinPort && !hasMaxPort) {
                    natActionInfo.maxPort = natActionInfo.minPort;
                }
                if (hasMinPort || hasMaxPort) {
                    if (natActionInfo.natAction & NAT_ACTION_SRC) {
                        natActionInfo.natAction |= NAT_ACTION_SRC_PORT;
                    } else if (natActionInfo.natAction & NAT_ACTION_DST) {
                        natActionInfo.natAction |= NAT_ACTION_DST_PORT;
                    }
                }
                break;
            default:
                OVS_LOG_TRACE("Invalid netlink attr type: %u", NlAttrType(ctAttr));
                break;
        }
    }
    /* If newNbl is not allocated, use the current Nbl*/
    status = OvsCtExecute_(fwdCtx, key, layers,
                           commit, force, zone, mark, labels, helper, &natActionInfo,
                           postUpdateEvent);
    return status;
}

/*
 *----------------------------------------------------------------------------
 * OvsConntrackEntryCleaner
 *     Runs periodically and cleans up the connection tracker
 *----------------------------------------------------------------------------
 */
VOID
OvsConntrackEntryCleaner(PVOID data)
{

    POVS_CT_THREAD_CTX context = (POVS_CT_THREAD_CTX)data;
    PLIST_ENTRY link, next;
    POVS_CT_ENTRY entry;
    LOCK_STATE_EX lockState;
    BOOLEAN success = TRUE;

    while (success) {
        if (context->exit) {
            break;
        }

        /* Set the timeout for the thread and cleanup */
        INT64 threadSleepTimeout = -CT_CLEANUP_INTERVAL;

        if (ctTotalEntries) {
            for (UINT32 i = 0; i < CT_HASH_TABLE_SIZE; i++) {
                NdisAcquireRWLockWrite(ovsCtBucketLock[i], &lockState, 0);
                LIST_FORALL_SAFE(&ovsConntrackTable[i], link, next) {
                    entry = CONTAINING_RECORD(link, OVS_CT_ENTRY, link);
                    OvsCtEntryDelete(entry, FALSE);
                }
                NdisReleaseRWLock(ovsCtBucketLock[i], &lockState);
            }
        }
        KeWaitForSingleObject(&context->event, Executive, KernelMode,
                              FALSE, (LARGE_INTEGER *)&threadSleepTimeout);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/*
 *----------------------------------------------------------------------------
 * OvsCtFlush
 *     Flushes out all Conntrack Entries that match any of the arguments
 *----------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsCtFlush(UINT16 zone, struct ovs_key_ct_tuple_ipv4 *tuple)
{
    PLIST_ENTRY link, next;
    POVS_CT_ENTRY entry;
    LOCK_STATE_EX lockState;

    if (ctTotalEntries) {
        for (UINT32 i = 0; i < CT_HASH_TABLE_SIZE; i++) {
            LIST_FORALL_SAFE(&ovsConntrackTable[i], link, next) {
            NdisAcquireRWLockWrite(ovsCtBucketLock[i], &lockState, 0);
                entry = CONTAINING_RECORD(link, OVS_CT_ENTRY, link);
                if (tuple) {
                    if (tuple->ipv4_proto != IPPROTO_ICMP &&
                        tuple->ipv4_src == entry->key.src.addr.ipv4_aligned &&
                        tuple->ipv4_dst == entry->key.dst.addr.ipv4_aligned &&
                        tuple->ipv4_proto == entry->key.nw_proto &&
                        tuple->src_port == entry->key.src.port &&
                        tuple->dst_port == entry->key.dst.port &&
                        (zone ? entry->key.zone == zone: TRUE)) {
                        OvsCtEntryDelete(entry, TRUE);
                    } else if (tuple->ipv4_src == entry->key.src.addr.ipv4_aligned &&
                        tuple->ipv4_dst == entry->key.dst.addr.ipv4_aligned &&
                        tuple->ipv4_proto == entry->key.nw_proto &&
                        tuple->src_port == entry->key.src.icmp_type &&
                        tuple->dst_port == entry->key.src.icmp_code &&
                        (zone ? entry->key.zone == zone: TRUE)) {
                        OvsCtEntryDelete(entry, TRUE);
                    }
                } else if (!zone || zone == entry->key.zone) {
                    OvsCtEntryDelete(entry, TRUE);
                }
                NdisReleaseRWLock(ovsCtBucketLock[i], &lockState);
            }
        }
    }

    OvsNatFlush(zone);
    return NDIS_STATUS_SUCCESS;
}

NTSTATUS
OvsCtDeleteCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                      UINT32 *replyLen)
{
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
    PNL_MSG_HDR nlMsgHdr = &(msgIn->nlMsg);
    PNL_ATTR ctAttrs[__CTA_MAX];
    UINT32 attrOffset = NLMSG_HDRLEN + NF_GEN_MSG_HDRLEN + OVS_HDRLEN;
    NL_ERROR nlError = NL_ERROR_SUCCESS;
    NTSTATUS status;
    UINT16 zone = 0;
    struct ovs_key_ct_tuple_ipv4 *ct_tuple = NULL;
    NL_BUFFER nlBuf;
    UINT16 nlmsgType;
    PNL_MSG_HDR nlMsg;

    static const NL_POLICY ctAttrPolicy[] = {
        [CTA_TUPLE_ORIG] = {.type = NL_A_NESTED, .optional = TRUE},
        [CTA_ZONE] = {.type = NL_A_BE16, .optional = TRUE },
    };

    if ((NlAttrParse(nlMsgHdr, attrOffset, NlNfMsgAttrsLen(nlMsgHdr),
        ctAttrPolicy, ARRAY_SIZE(ctAttrPolicy),
        ctAttrs, ARRAY_SIZE(ctAttrs)))
        != TRUE) {
        OVS_LOG_ERROR("Ct attr parsing failed for msg: %p", nlMsgHdr);
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    if (ctAttrs[CTA_ZONE]) {
        zone = ntohs(NlAttrGetU16(ctAttrs[CTA_ZONE]));
    }

    if (ctAttrs[CTA_TUPLE_ORIG]) {
        ct_tuple = OvsAllocateMemoryWithTag(sizeof(struct ovs_key_ct_tuple_ipv4),
                                            OVS_CT_POOL_TAG);
        if (ct_tuple == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto done;
        }
        /* Parse ct tuple. */
        status = MapNlToCtTuple(msgIn, ctAttrs[CTA_TUPLE_ORIG], ct_tuple);
        if (status != STATUS_SUCCESS) {
            goto done;
        }
    }

    status = OvsCtFlush(zone, ct_tuple);
    if (status == STATUS_SUCCESS) {
        nlmsgType = (NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_DELETE);
        NlBufInit(&nlBuf,
                  usrParamsCtx->outputBuffer,
                  usrParamsCtx->outputLength);
        if (!NlFillOvsMsgForNfGenMsg(&nlBuf, nlmsgType, NLM_F_CREATE,
                                     msgIn->nlMsg.nlmsgSeq,
                                     msgIn->nlMsg.nlmsgPid,
                                     AF_UNSPEC,
                                     msgIn->nfGenMsg.version,
                                     0)) {
            status = STATUS_INVALID_PARAMETER;
        }
        nlMsg = (PNL_MSG_HDR)NlBufAt(&nlBuf, 0, 0);
        nlMsg->nlmsgLen = NlBufSize(&nlBuf);
        *replyLen = msgOut->nlMsg.nlmsgLen;
    }

done:
    if (ct_tuple) {
        OvsFreeMemoryWithTag(ct_tuple, OVS_CT_POOL_TAG);
    }

    nlError = NlMapStatusToNlErr(status);
    if (nlError != NL_ERROR_SUCCESS) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
                                       usrParamsCtx->outputBuffer;

        ASSERT(msgError);
        NlBuildErrorMsg(msgIn, msgError, nlError, replyLen);
        ASSERT(*replyLen != 0);
        status = STATUS_SUCCESS;
    }

    return status;
}

static __inline NDIS_STATUS
MapNlToCtTuple(POVS_MESSAGE msgIn, PNL_ATTR ctAttr,
                  struct ovs_key_ct_tuple_ipv4 *ct_tuple) {

    PNL_MSG_HDR nlMsgHdr = &(msgIn->nlMsg);
    PNL_ATTR ctTupleAttrs[__CTA_MAX];
    UINT32 attrOffset;
    static const NL_POLICY ctTuplePolicy[] = {
        [CTA_TUPLE_IP] = {.type = NL_A_NESTED, .optional = FALSE },
        [CTA_TUPLE_PROTO] = {.type = NL_A_NESTED, .optional = FALSE},
    };

    static const NL_POLICY ctTupleIpPolicy[] = {
        [CTA_IP_V4_SRC] = { .type = NL_A_BE32, .optional = TRUE },
        [CTA_IP_V4_DST] = { .type = NL_A_BE32, .optional = TRUE },
    };

    static const NL_POLICY ctTupleProtoPolicy[] = {
        [CTA_PROTO_NUM] = { .type = NL_A_U8, .optional = FALSE },
        [CTA_PROTO_SRC_PORT] = { .type = NL_A_BE16, .optional = TRUE },
        [CTA_PROTO_DST_PORT] = { .type = NL_A_BE16, .optional = TRUE },
        [CTA_PROTO_ICMP_TYPE] = { .type = NL_A_U8, .optional = TRUE },
        [CTA_PROTO_ICMP_CODE] = { .type = NL_A_U8, .optional = TRUE },
    };

    if (!ctAttr) {
        return STATUS_INVALID_PARAMETER;
    }

    attrOffset = (UINT32)((PCHAR) ctAttr - (PCHAR)nlMsgHdr);
    if ((NlAttrParseNested(nlMsgHdr, attrOffset, NlAttrLen(ctAttr),
        ctTuplePolicy, ARRAY_SIZE(ctTuplePolicy),
        ctTupleAttrs, ARRAY_SIZE(ctTupleAttrs)))
        != TRUE) {
        OVS_LOG_ERROR("CTA_TUPLE attr parsing failed for msg: %p", nlMsgHdr);
        return STATUS_INVALID_PARAMETER;
    }

    if (ctTupleAttrs[CTA_TUPLE_IP]) {
        PNL_ATTR ctTupleIpAttrs[__CTA_MAX];
        attrOffset = (UINT32)((PCHAR) ctTupleAttrs[CTA_TUPLE_IP] - (PCHAR)nlMsgHdr);
        if ((NlAttrParseNested(nlMsgHdr, attrOffset, NlAttrLen(ctTupleAttrs[CTA_TUPLE_IP]),
            ctTupleIpPolicy, ARRAY_SIZE(ctTupleIpPolicy),
            ctTupleIpAttrs, ARRAY_SIZE(ctTupleIpAttrs)))
            != TRUE) {
            OVS_LOG_ERROR("CTA_TUPLE_IP attr parsing failed for msg: %p", nlMsgHdr);
            return STATUS_INVALID_PARAMETER;
        }

        if (ctTupleIpAttrs[CTA_IP_V4_SRC] && ctTupleIpAttrs[CTA_IP_V4_DST]) {
            ct_tuple->ipv4_src = NlAttrGetU32(ctTupleIpAttrs[CTA_IP_V4_SRC]);
            ct_tuple->ipv4_dst = NlAttrGetU32(ctTupleIpAttrs[CTA_IP_V4_DST]);
        }
    }

    if (ctTupleAttrs[CTA_TUPLE_PROTO]) {
        PNL_ATTR ctTupleProtoAttrs[__CTA_MAX];
        attrOffset = (UINT32)((PCHAR) ctTupleAttrs[CTA_TUPLE_PROTO] - (PCHAR)nlMsgHdr);
        if ((NlAttrParseNested(nlMsgHdr, attrOffset, NlAttrLen(ctTupleAttrs[CTA_TUPLE_PROTO]),
            ctTupleProtoPolicy, ARRAY_SIZE(ctTupleProtoPolicy),
            ctTupleProtoAttrs, ARRAY_SIZE(ctTupleProtoAttrs)))
            != TRUE) {
            OVS_LOG_ERROR("CTA_TUPLE_PROTO attr parsing failed for msg: %p", nlMsgHdr);
            return STATUS_INVALID_PARAMETER;
        }

        if (ctTupleProtoAttrs[CTA_PROTO_NUM]) {
            ct_tuple->ipv4_proto =  NlAttrGetU8 (ctTupleProtoAttrs[CTA_PROTO_NUM]);
            if (ctTupleProtoAttrs[CTA_PROTO_SRC_PORT] && ctTupleProtoAttrs[CTA_PROTO_DST_PORT]) {
                ct_tuple->src_port = NlAttrGetU16(ctTupleProtoAttrs[CTA_PROTO_SRC_PORT]);
                ct_tuple->dst_port = NlAttrGetU16(ctTupleProtoAttrs[CTA_PROTO_DST_PORT]);
            } else if (ctTupleProtoAttrs[CTA_PROTO_ICMP_TYPE] &&
                        ctTupleProtoAttrs[CTA_PROTO_ICMP_CODE] ) {
                ct_tuple->src_port = NlAttrGetU8(ctTupleProtoAttrs[CTA_PROTO_ICMP_TYPE]);
                ct_tuple->dst_port = NlAttrGetU8(ctTupleProtoAttrs[CTA_PROTO_ICMP_CODE]);
            }

        }
    }

    return NDIS_STATUS_SUCCESS;
}

static __inline NDIS_STATUS
MapIpTupleToNl(PNL_BUFFER nlBuf, OVS_CT_KEY *key)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    UINT32 offset = 0;

    offset = NlMsgStartNested(nlBuf, CTA_TUPLE_IP);
    if (!offset) {
        return NDIS_STATUS_FAILURE;
    }

    if (key->dl_type == ntohs(ETH_TYPE_IPV4)) {
        if (!NlMsgPutTailU32(nlBuf, CTA_IP_V4_SRC, key->src.addr.ipv4)) {
            status = NDIS_STATUS_FAILURE;
            goto done;
        }
        if (!NlMsgPutTailU32(nlBuf, CTA_IP_V4_DST, key->dst.addr.ipv4)) {
            status = NDIS_STATUS_FAILURE;
            goto done;
        }
    } else if (key->dl_type == ntohs(ETH_TYPE_IPV6)) {
        if (!NlMsgPutTailUnspec(nlBuf, CTA_IP_V6_SRC,
                                (PCHAR)(&key->src.addr.ipv6),
                                sizeof(key->src.addr.ipv6))) {
            status = NDIS_STATUS_FAILURE;
            goto done;
        }
        if (!NlMsgPutTailUnspec(nlBuf, CTA_IP_V6_DST,
                                (PCHAR)(&key->dst.addr.ipv6),
                                sizeof(key->dst.addr.ipv6))) {
            status = NDIS_STATUS_FAILURE;
            goto done;
        }
    }

done:
    NlMsgEndNested(nlBuf, offset);
    return status;
}

static __inline NDIS_STATUS
MapProtoTupleToNl(PNL_BUFFER nlBuf, OVS_CT_KEY *key)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    UINT32 offset = 0;

    offset = NlMsgStartNested(nlBuf, CTA_TUPLE_PROTO);
    if (!offset) {
        return NDIS_STATUS_FAILURE;
    }

    if (!NlMsgPutTailU8(nlBuf, CTA_PROTO_NUM, key->nw_proto)) {
        status = NDIS_STATUS_FAILURE;
        goto done;
    }

    if (key->dl_type == ntohs(ETH_TYPE_IPV4)
        || key->dl_type == ntohs(ETH_TYPE_IPV6)) {
        /* ICMP and ICMPv6 Type, Code and ID are currently not tracked */
        if (key->nw_proto == IPPROTO_ICMP) {
            if (!NlMsgPutTailU16(nlBuf, CTA_PROTO_ICMP_ID,
                                 htons(key->src.icmp_id))) {
                status = NDIS_STATUS_FAILURE;
                goto done;
            }
            if (!NlMsgPutTailU8(nlBuf, CTA_PROTO_ICMP_TYPE,
                                key->src.icmp_type)) {
                status = NDIS_STATUS_FAILURE;
                goto done;
            }
            if (!NlMsgPutTailU8(nlBuf, CTA_PROTO_ICMP_CODE,
                                key->src.icmp_code)) {
                status = NDIS_STATUS_FAILURE;
                goto done;
            }
        } else if (key->nw_proto == IPPROTO_ICMPV6) {
            if (!NlMsgPutTailU16(nlBuf, CTA_PROTO_ICMPV6_ID, 0)) {
                status = NDIS_STATUS_FAILURE;
                goto done;
            }
            if (!NlMsgPutTailU8(nlBuf, CTA_PROTO_ICMPV6_TYPE, 0)) {
                status = NDIS_STATUS_FAILURE;
                goto done;
            }
            if (!NlMsgPutTailU8(nlBuf, CTA_PROTO_ICMPV6_CODE, 0)) {
                status = NDIS_STATUS_FAILURE;
                goto done;
            }
        } else if (key->nw_proto == IPPROTO_TCP
                   || key->nw_proto == IPPROTO_UDP) {
            if (!NlMsgPutTailU16(nlBuf, CTA_PROTO_SRC_PORT,
                                 key->src.port)) {
                status = NDIS_STATUS_FAILURE;
                goto done;
            }
            if (!NlMsgPutTailU16(nlBuf, CTA_PROTO_DST_PORT,
                                 key->dst.port)) {
                status = NDIS_STATUS_FAILURE;
                goto done;
            }
        }
    }

done:
    NlMsgEndNested(nlBuf, offset);
    return status;
}

static __inline NDIS_STATUS
MapCtKeyTupleToNl(PNL_BUFFER nlBuf,
                  UINT16 tupleType,
                  OVS_CT_KEY *key)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    UINT32 offset = 0;

    offset = NlMsgStartNested(nlBuf, tupleType);
    if (!offset) {
        return NDIS_STATUS_FAILURE;
    }

    status = MapIpTupleToNl(nlBuf, key);
    if (status != NDIS_STATUS_SUCCESS) {
        goto done;
    }

    status = MapProtoTupleToNl(nlBuf, key);
    if (status != NDIS_STATUS_SUCCESS) {
        goto done;
    }

done:
    NlMsgEndNested(nlBuf, offset);
    return status;
}

static __inline NDIS_STATUS
MapCtCounterToNl(PNL_BUFFER nlBuf,
                 UINT16 counterType,
                 OVS_CT_KEY *key)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    UINT32 offset = 0;

    offset = NlMsgStartNested(nlBuf, counterType);
    if (!offset) {
        return NDIS_STATUS_FAILURE;
    }

    if (!NlMsgPutTailU64(nlBuf, CTA_COUNTERS_PACKETS,
                         htonll(key->packetCount))) {
        status = NDIS_STATUS_FAILURE;
        goto done;
    }

    if (!NlMsgPutTailU64(nlBuf, CTA_COUNTERS_BYTES,
                         htonll(key->byteCount))) {
        status = NDIS_STATUS_FAILURE;
        goto done;
    }

done:
    NlMsgEndNested(nlBuf, offset);
    return status;
}

/* Userspace expects system time to be Unix timestamp in Nano Seconds */
static __inline unsigned
WindowsTickToUnixSeconds(long long windowsTicks)
{
    /*
     *  Windows epoch starts 1601-01-01T00:00:00Z. It's 11644473600 seconds
     *  before the UNIX/Linux epoch (1970-01-01T00:00:00Z). Windows ticks are
     *  in 100 nanoseconds
     */
    return (unsigned)((windowsTicks / WINDOWS_TICK
                        - SEC_TO_UNIX_EPOCH));
}

NTSTATUS
OvsCreateNlMsgFromCtEntry(POVS_CT_ENTRY entry,
                          PVOID outBuffer,
                          UINT32 outBufLen,
                          UINT8 eventType,
                          UINT32 nlmsgSeq,
                          UINT32 nlmsgPid,
                          UINT8 nfGenVersion,
                          UINT32 dpIfIndex)
{
    NL_BUFFER nlBuf;
    BOOLEAN ok;
    PNL_MSG_HDR nlMsg;
    UINT32 timeout;
    NDIS_STATUS status;
    UINT64 currentTime, expiration;
    UINT16 nlmsgType;
    UINT16 nlmsgFlags = NLM_F_CREATE;
    NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
    UINT8 nfgenFamily = 0;

    if (entry->key.dl_type == htons(ETH_TYPE_IPV4)) {
        nfgenFamily = AF_INET;
    } else if (entry->key.dl_type == htons(ETH_TYPE_IPV6)) {
        nfgenFamily = AF_INET6;
    }

    NlBufInit(&nlBuf, outBuffer, outBufLen);
    /* Mimic netfilter */
    if (eventType == OVS_EVENT_CT_NEW || eventType == OVS_EVENT_CT_UPDATE) {
        nlmsgType = (UINT16) (NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_NEW);
    } else if (eventType == OVS_EVENT_CT_DELETE) {
        nlmsgType = (UINT16) (NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_DELETE);
    } else {
        return STATUS_INVALID_PARAMETER;
    }

    if (eventType == OVS_EVENT_CT_UPDATE) {
        /* In netlink-conntrack.c IPCTNL_MSG_CT_NEW msg type is used to
         * differentiate between OVS_EVENT_CT_NEW and OVS_EVENT_CT_UPDATE
         * events based on nlmsgFlags, unset it to notify an update event.
         */
        nlmsgFlags = 0;
    }
    ok = NlFillOvsMsgForNfGenMsg(&nlBuf, nlmsgType, nlmsgFlags,
                                 nlmsgSeq, nlmsgPid, nfgenFamily,
                                 nfGenVersion, dpIfIndex);
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    status = MapCtKeyTupleToNl(&nlBuf, CTA_TUPLE_ORIG, &entry->key);
    if (status != NDIS_STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    status = MapCtKeyTupleToNl(&nlBuf, CTA_TUPLE_REPLY, &entry->rev_key);
    if (status != NDIS_STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    status = MapCtCounterToNl(&nlBuf, CTA_COUNTERS_ORIG, &entry->key);
    if (status != NDIS_STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    status = MapCtCounterToNl(&nlBuf, CTA_COUNTERS_REPLY, &entry->rev_key);
    if (status != NDIS_STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    if (entry->key.zone) {
        if (!NlMsgPutTailU16(&nlBuf, CTA_ZONE, htons(entry->key.zone))) {
            return STATUS_INVALID_BUFFER_SIZE;
        }
    }

    if (entry->mark) {
        if (!NlMsgPutTailU32(&nlBuf, CTA_MARK, htonl(entry->mark))) {
            return STATUS_INVALID_BUFFER_SIZE;
        }
    }

    if (entry->labels.ct_labels) {
        ok = NlMsgPutTailUnspec(&nlBuf, CTA_LABELS,
                                (PCHAR)(&entry->labels),
                                sizeof(entry->labels));
        if (!ok) {
            return STATUS_INVALID_BUFFER_SIZE;
        }
    }

    if (entry->expiration > currentTime) {
        expiration = entry->expiration - currentTime;
        timeout = (UINT32) (expiration / CT_INTERVAL_SEC);
        if (!NlMsgPutTailU32(&nlBuf, CTA_TIMEOUT, htonl(timeout))) {
            return STATUS_INVALID_BUFFER_SIZE;
        }
    }

    if (entry->key.nw_proto == IPPROTO_TCP) {
        /* Add ProtoInfo for TCP */
        UINT32 offset;
        offset = NlMsgStartNested(&nlBuf, CTA_PROTOINFO);
        if (!offset) {
            return NDIS_STATUS_FAILURE;
        }

        status = OvsCtMapTcpProtoInfoToNl(&nlBuf, entry);
        NlMsgEndNested(&nlBuf, offset);
        if (status != NDIS_STATUS_SUCCESS) {
            return STATUS_UNSUCCESSFUL;
        }
    }

    if (entry->helper_name) {
        UINT32 offset;
        offset = NlMsgStartNested(&nlBuf, CTA_HELP);
        if (!offset) {
            return NDIS_STATUS_FAILURE;
        }
        if (!NlMsgPutTailString(&nlBuf, CTA_HELP_NAME, entry->helper_name)) {
            return STATUS_INVALID_BUFFER_SIZE;
        }
        NlMsgEndNested(&nlBuf, offset);
    }

    if (entry->parent) {
        status = MapCtKeyTupleToNl(&nlBuf, CTA_TUPLE_MASTER,
                                   &((POVS_CT_ENTRY)entry->parent)->key);
        if (status != NDIS_STATUS_SUCCESS) {
           return STATUS_UNSUCCESSFUL;
        }
    }

    /* CTA_STATUS is required but not implemented. Default to 0 */
    if (!NlMsgPutTailU32(&nlBuf, CTA_STATUS, 0)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    /* Mimic netfilter - nf_conntrack_netlink.c:
     *
     * int ctnetlink_dump_id(struct sk_buff *skb, const struct nf_conn *ct) {
     *     NLA_PUT_BE32(skb, CTA_ID, htonl((unsigned long)ct));
     *     return 0;
     * }
     *
     */
    if(!NlMsgPutTailU32(&nlBuf, CTA_ID, htonl((UINT32) entry))) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (entry->timestampStart) {
        UINT32 offset;
        offset = NlMsgStartNested(&nlBuf, CTA_TIMESTAMP);
        if (!offset) {
            return NDIS_STATUS_FAILURE;
        }
        UINT64 start;
        start = WindowsTickToUnixSeconds(entry->timestampStart);
        start = start * SEC_TO_NANOSEC;
        if (!NlMsgPutTailU64(&nlBuf, CTA_TIMESTAMP_START, htonll(start))) {
            NlMsgEndNested(&nlBuf, offset);
            return STATUS_INVALID_BUFFER_SIZE;
        }

        NlMsgEndNested(&nlBuf, offset);
    }

    nlMsg = (PNL_MSG_HDR)NlBufAt(&nlBuf, 0, 0);
    nlMsg->nlmsgLen = NlBufSize(&nlBuf);
    return STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 *  OvsCtDumpCmdHandler --
 *    Handler for IPCTNL_MSG_CT_GET command.
 *
 *  XXX - Try to consolidate dump handler patterns around dumpState usage
 *        The following dumpHandler is similar to one vport.c uses
 *----------------------------------------------------------------------------
*/
NTSTATUS
OvsCtDumpCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                    UINT32 *replyLen)
{
    NTSTATUS rc;
    /* Setup Dump Start if it's OVS_WRITE_DEV_OP and return */
    if (usrParamsCtx->devOp == OVS_WRITE_DEV_OP) {
        *replyLen = 0;
        OvsSetupDumpStart(usrParamsCtx);
        return STATUS_SUCCESS;
    }

    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;
    POVS_MESSAGE msgIn;

    ASSERT(usrParamsCtx->devOp == OVS_READ_DEV_OP);
    if (instance->dumpState.ovsMsg == NULL) {
        ASSERT(FALSE);
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* Output buffer has been validated while validating read dev op. */
    ASSERT(usrParamsCtx->outputBuffer != NULL);
    msgIn = instance->dumpState.ovsMsg;
    UINT32 inBucket = instance->dumpState.index[0];
    UINT32 inIndex = instance->dumpState.index[1];
    UINT32 i = CT_HASH_TABLE_SIZE;
    UINT32 outIndex = 0;
    KIRQL irql = KeGetCurrentIrql();
    LOCK_STATE_EX lockStateTable;

    if (ctTotalEntries) {
        for (i = inBucket; i < CT_HASH_TABLE_SIZE; i++) {
            PLIST_ENTRY head, link;
            NdisAcquireRWLockRead(ovsCtBucketLock[i], &lockStateTable, 0);
            head = &ovsConntrackTable[i];
            POVS_CT_ENTRY entry = NULL;

            outIndex = 0;
            LIST_FORALL(head, link) {
                /*
                 * if one or more dumps were previously done on this same
                 * bucket, inIndex will be > 0, so we'll need to reply with
                 * the inIndex + 1 ct-entry from the bucket.
                 */
                if (outIndex >= inIndex) {
                    entry = CONTAINING_RECORD(link, OVS_CT_ENTRY, link);
                    OVS_ACQUIRE_SPIN_LOCK(&(entry->lock), irql);
                    rc = OvsCreateNlMsgFromCtEntry(entry,
                                                   usrParamsCtx->outputBuffer,
                                                   usrParamsCtx->outputLength,
                                                   OVS_EVENT_CT_NEW,
                                                   msgIn->nlMsg.nlmsgSeq,
                                                   msgIn->nlMsg.nlmsgPid,
                                                   msgIn->nfGenMsg.version,
                                                   0);
                    OVS_RELEASE_SPIN_LOCK(&(entry->lock), irql);
                    if (rc != NDIS_STATUS_SUCCESS) {
                        NdisReleaseRWLock(ovsCtBucketLock[i], &lockStateTable);
                        return STATUS_UNSUCCESSFUL;
                    }

                    ++outIndex;
                    break;
                }

                ++outIndex;
            }
            NdisReleaseRWLock(ovsCtBucketLock[i], &lockStateTable);
            if (entry) {
                break;
            }

            /*
             * if no ct-entry was found above, check the next bucket, beginning
             * with the first (i.e. index 0) elem from within that bucket
             */
            inIndex = 0;
        }
    }
    instance->dumpState.index[0] = i;
    instance->dumpState.index[1] = outIndex;
    /* if i < CT_HASH_TABLE_SIZE => entry was found */
    if (i < CT_HASH_TABLE_SIZE) {
        POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
        *replyLen = msgOut->nlMsg.nlmsgLen;
    } else {
        /* if i >= CT_HASH_TABLE_SIZE => entry was not found => dump done */
        *replyLen = 0;
        FreeUserDumpState(instance);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
OvsCreateNlMsgFromCtLimit(POVS_MESSAGE msgIn,
                          PVOID outBuffer,
                          UINT32 outBufLen,
                          PCHAR attr,
                          UINT32 numAttrs,
                          int dpIfIndex)
{
    NTSTATUS status = STATUS_SUCCESS;
    NL_BUFFER nlBuffer;
    PNL_MSG_HDR nlMsg;
    PGENL_MSG_HDR genlMsgHdr = &(msgIn->genlMsg);

    NlBufInit(&nlBuffer, outBuffer, outBufLen);

    if (!NlFillOvsMsg(&nlBuffer, msgIn->nlMsg.nlmsgType, NLM_F_MULTI,
                      msgIn->nlMsg.nlmsgSeq, msgIn->nlMsg.nlmsgPid,
                      msgIn->genlMsg.cmd, msgIn->genlMsg.version,
                      dpIfIndex)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (genlMsgHdr->cmd == OVS_CT_LIMIT_CMD_GET && numAttrs) {
        POVS_CT_ZONE_LIMIT zoneLimitAttr = (POVS_CT_ZONE_LIMIT) attr;
        UINT32 offset = NlMsgStartNested(&nlBuffer, OVS_CT_LIMIT_ATTR_ZONE_LIMIT);
        if (!offset) {
            /* Starting the nested attribute failed. */
            status = STATUS_INVALID_BUFFER_SIZE;
            goto done;
        }

        /* Insert OVS_CT_ZONE_LIMIT attributes.*/
        for (UINT32 i = 0; i < numAttrs; i++) {
            if (zoneLimitAttr) {
                zoneLimitAttr->limit = zoneInfo[zoneLimitAttr->zone_id].limit;
                zoneLimitAttr->count = zoneInfo[zoneLimitAttr->zone_id].entries;
                if (zoneLimitAttr->zone_id == -1) {
                    zoneLimitAttr->limit = defaultCtLimit;
                }
                NlMsgPutTail(&nlBuffer, (const PCHAR)zoneLimitAttr,
                             sizeof(OVS_CT_ZONE_LIMIT));
            } else {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            zoneLimitAttr = (POVS_CT_ZONE_LIMIT)((PCHAR) zoneLimitAttr +
                                sizeof(OVS_CT_ZONE_LIMIT));
        }
        NlMsgEndNested(&nlBuffer, offset);
    }

done:
    nlMsg = (PNL_MSG_HDR)NlBufAt(&nlBuffer, 0, 0);
    nlMsg->nlmsgLen = NlBufSize(&nlBuffer);

    return status;
}

NTSTATUS
OvsCtLimitHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                  UINT32 *replyLen)
{
    NTSTATUS status;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
    PNL_MSG_HDR nlMsgHdr = &(msgIn->nlMsg);
    PGENL_MSG_HDR genlMsgHdr = &(msgIn->genlMsg);
    POVS_HDR ovsHdr = &(msgIn->ovsHdr);
    PCHAR attr = NULL;
    UINT32 numAttrs = 0;
    UINT32 attrOffset = NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN;

    static const NL_POLICY ovsCtLimitPolicy[] = {
        [OVS_CT_LIMIT_ATTR_ZONE_LIMIT] = { .type = NL_A_NESTED, .optional = TRUE }
    };
    PNL_ATTR nlAttrs[ARRAY_SIZE(ovsCtLimitPolicy)];

    if ((NlAttrParse(nlMsgHdr, attrOffset, NlMsgAttrsLen(nlMsgHdr),
                     ovsCtLimitPolicy, ARRAY_SIZE(ovsCtLimitPolicy),
                     nlAttrs, ARRAY_SIZE(nlAttrs)))
                     != TRUE) {
        OVS_LOG_ERROR("Attr Parsing failed for msg: %p", nlMsgHdr);
        return STATUS_INVALID_PARAMETER;
    }

    if (nlAttrs[OVS_CT_LIMIT_ATTR_ZONE_LIMIT]) {
        numAttrs = NlAttrGetSize(nlAttrs[OVS_CT_LIMIT_ATTR_ZONE_LIMIT])/sizeof(OVS_CT_ZONE_LIMIT);
        attr = NlAttrGet(nlAttrs[OVS_CT_LIMIT_ATTR_ZONE_LIMIT]);
    }

    if (genlMsgHdr->cmd == OVS_CT_LIMIT_CMD_SET ||
        genlMsgHdr->cmd == OVS_CT_LIMIT_CMD_DEL) {
        POVS_CT_ZONE_LIMIT zoneLimitAttr = (POVS_CT_ZONE_LIMIT)attr;
        for (UINT32 i = 0; i < numAttrs; i++) {
            /* Parse zone limit attributes. */
            if (zoneLimitAttr) {
                if (genlMsgHdr->cmd == OVS_CT_LIMIT_CMD_DEL) {
                    zoneLimitAttr->limit = CT_MAX_ENTRIES;
                }
                OvsCtSetZoneLimit(zoneLimitAttr->zone_id, zoneLimitAttr->limit);
            } else {
                OVS_LOG_ERROR("Failed to get zone limit attribute at index(%u),"
                              " numAttrs(%u)", i, numAttrs);
                return STATUS_INVALID_PARAMETER;
            }
            zoneLimitAttr = (POVS_CT_ZONE_LIMIT)((PCHAR) zoneLimitAttr +
                                sizeof(OVS_CT_ZONE_LIMIT));
        }
    }

    /* Output buffer has been validated while validating transact dev op. */
    ASSERT(msgOut != NULL && usrParamsCtx->outputLength >= sizeof *msgOut);
    status = OvsCreateNlMsgFromCtLimit(msgIn, msgOut,
                                       usrParamsCtx->outputLength,
                                       attr, numAttrs, ovsHdr->dp_ifindex);
    *replyLen = msgOut->nlMsg.nlmsgLen;

    return status;
}

#pragma warning(pop)
