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

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_CONTRK

#include "Conntrack.h"
#include "Jhash.h"
#include "PacketParser.h"
#include "Debug.h"

typedef struct _OVS_CT_THREAD_CTX {
    KEVENT      event;
    PVOID       threadObject;
    UINT32      exit;
} OVS_CT_THREAD_CTX, *POVS_CT_THREAD_CTX;

KSTART_ROUTINE ovsConntrackEntryCleaner;
static PLIST_ENTRY ovsConntrackTable;
static OVS_CT_THREAD_CTX ctThreadCtx;
static PNDIS_RW_LOCK_EX ovsConntrackLockObj;

/*
 *----------------------------------------------------------------------------
 * OvsInitConntrack
 *     Initialize the components used by Connection Tracking
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsInitConntrack(POVS_SWITCH_CONTEXT context)
{
    NTSTATUS status;
    HANDLE threadHandle = NULL;

    /* Init the sync-lock */
    ovsConntrackLockObj = NdisAllocateRWLock(context->NdisFilterHandle);
    if (ovsConntrackLockObj == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Init the Hash Buffer */
    ovsConntrackTable = OvsAllocateMemoryWithTag(sizeof(LIST_ENTRY)
                                                 * CT_HASH_TABLE_SIZE,
                                                 OVS_CT_POOL_TAG);
    if (ovsConntrackTable == NULL) {
        NdisFreeRWLock(ovsConntrackLockObj);
        ovsConntrackLockObj = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (int i = 0; i < CT_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&ovsConntrackTable[i]);
    }

    /* Init CT Cleaner Thread */
    KeInitializeEvent(&ctThreadCtx.event, NotificationEvent, FALSE);
    status = PsCreateSystemThread(&threadHandle, SYNCHRONIZE, NULL, NULL,
                                  NULL, ovsConntrackEntryCleaner,
                                  &ctThreadCtx);

    if (status != STATUS_SUCCESS) {
        NdisFreeRWLock(ovsConntrackLockObj);
        ovsConntrackLockObj = NULL;

        OvsFreeMemoryWithTag(ovsConntrackTable, OVS_CT_POOL_TAG);
        ovsConntrackTable = NULL;

        return status;
    }

    ObReferenceObjectByHandle(threadHandle, SYNCHRONIZE, NULL, KernelMode,
                              &ctThreadCtx.threadObject, NULL);
    ZwClose(threadHandle);
    threadHandle = NULL;
    return STATUS_SUCCESS;
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
    LOCK_STATE_EX lockState;
    NdisAcquireRWLockWrite(ovsConntrackLockObj, &lockState, 0);
    ctThreadCtx.exit = 1;
    KeSetEvent(&ctThreadCtx.event, 0, FALSE);
    NdisReleaseRWLock(ovsConntrackLockObj, &lockState);

    KeWaitForSingleObject(ctThreadCtx.threadObject, Executive,
                          KernelMode, FALSE, NULL);
    ObDereferenceObject(ctThreadCtx.threadObject);

    if (ovsConntrackTable) {
        OvsFreeMemoryWithTag(ovsConntrackTable, OVS_CT_POOL_TAG);
        ovsConntrackTable = NULL;
    }

    NdisFreeRWLock(ovsConntrackLockObj);
    ovsConntrackLockObj = NULL;
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

static __inline POVS_CT_ENTRY
OvsCtEntryCreate(const TCPHdr *tcp,
                 PNET_BUFFER_LIST curNbl,
                 OvsConntrackKeyLookupCtx *ctx,
                 OvsFlowKey *key,
                 BOOLEAN commit,
                 UINT64 currentTime)
{
    POVS_CT_ENTRY entry = NULL;
    UINT32 state = 0;
    if (!OvsConntrackValidateTcpPacket(tcp)) {
        state |= OVS_CS_F_INVALID;
        OvsCtUpdateFlowKey(key, state, ctx->key.zone, 0, NULL);
        return entry;
    }

    state |= OVS_CS_F_NEW;
    if (commit) {
        entry = OvsConntrackCreateTcpEntry(tcp, curNbl, currentTime);
        NdisMoveMemory(&entry->key, &ctx->key, sizeof (OVS_CT_KEY));
        NdisMoveMemory(&entry->rev_key, &ctx->key, sizeof (OVS_CT_KEY));
        OvsCtKeyReverse(&entry->rev_key);
        InsertHeadList(&ovsConntrackTable[ctx->hash & CT_HASH_TABLE_MASK],
                       &entry->link);
    }

    OvsCtUpdateFlowKey(key, state, ctx->key.zone, 0, NULL);
    return entry;
}

static __inline VOID
OvsCtEntryDelete(POVS_CT_ENTRY entry)
{
    RemoveEntryList(&entry->link);
    OvsFreeMemoryWithTag(entry, OVS_CT_POOL_TAG);
}

static __inline BOOLEAN
OvsCtEntryExpired(POVS_CT_ENTRY entry)
{
    if (entry == NULL)
        return TRUE;

    UINT64 currentTime;
    NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
    return entry->expiration < currentTime;
}

static __inline NDIS_STATUS
OvsDetectCtPacket(OvsFlowKey *key)
{
    /* Currently we support only Unfragmented TCP packets */
    switch (ntohs(key->l2.dlType)) {
    case ETH_TYPE_IPV4:
        if (key->ipKey.nwFrag != OVS_FRAG_TYPE_NONE) {
            return NDIS_STATUS_NOT_SUPPORTED;
        }
        if (key->ipKey.nwProto != IPPROTO_TCP) {
            return NDIS_STATUS_NOT_SUPPORTED;
        }
        return NDIS_STATUS_SUCCESS;
    case ETH_TYPE_IPV6:
        return NDIS_STATUS_NOT_SUPPORTED;
    }

    return NDIS_STATUS_NOT_SUPPORTED;
}

static __inline BOOLEAN
OvsCtKeyAreSame(OVS_CT_KEY ctxKey, OVS_CT_KEY entryKey)
{
    return ((ctxKey.src.addr.ipv4 == entryKey.src.addr.ipv4) &&
        (ctxKey.src.addr.ipv4_aligned == entryKey.src.addr.ipv4_aligned) &&
        (ctxKey.src.port == entryKey.src.port) &&
        (ctxKey.dst.addr.ipv4 == entryKey.dst.addr.ipv4) &&
        (ctxKey.dst.addr.ipv4_aligned == entryKey.dst.addr.ipv4_aligned) &&
        (ctxKey.dst.port == entryKey.dst.port) &&
        (ctxKey.dl_type == entryKey.dl_type) &&
        (ctxKey.nw_proto == entryKey.nw_proto) &&
        (ctxKey.zone == entryKey.zone));
}

static __inline POVS_CT_ENTRY
OvsCtLookup(OvsConntrackKeyLookupCtx *ctx)
{
    PLIST_ENTRY link;
    POVS_CT_ENTRY entry;
    BOOLEAN reply = FALSE;
    POVS_CT_ENTRY found = NULL;

    LIST_FORALL(&ovsConntrackTable[ctx->hash & CT_HASH_TABLE_MASK], link) {
        entry = CONTAINING_RECORD(link, OVS_CT_ENTRY, link);

        if (OvsCtKeyAreSame(ctx->key,entry->key)) {
            found = entry;
            reply = FALSE;
            break;
        }

        if (OvsCtKeyAreSame(ctx->key,entry->rev_key)) {
            found = entry;
            reply = TRUE;
            break;
        }
    }

    if (found) {
        if (OvsCtEntryExpired(found)) {
            found = NULL;
        } else {
            ctx->reply = reply;
        }
    }

    ctx->entry = found;
    return found;
}

static __inline VOID
OvsCtSetupLookupCtx(OvsFlowKey *flowKey,
                    UINT16 zone,
                    OvsConntrackKeyLookupCtx *ctx)
{
    UINT32 hsrc, hdst,hash;

    ctx->key.zone = zone;
    ctx->key.dl_type = flowKey->l2.dlType;

    if (flowKey->l2.dlType == htons(ETH_TYPE_IPV4)) {
        ctx->key.src.addr.ipv4 = flowKey->ipKey.nwSrc;
        ctx->key.dst.addr.ipv4 = flowKey->ipKey.nwDst;
        ctx->key.nw_proto = flowKey->ipKey.nwProto;

        ctx->key.src.port = flowKey->ipKey.l4.tpSrc;
        ctx->key.dst.port = flowKey->ipKey.l4.tpDst;
    } else if (flowKey->l2.dlType == htons(ETH_TYPE_IPV6)) {
        ctx->key.src.addr.ipv6 = flowKey->ipv6Key.ipv6Src;
        ctx->key.dst.addr.ipv6 = flowKey->ipv6Key.ipv6Dst;
        ctx->key.nw_proto = flowKey->ipv6Key.nwProto;

        ctx->key.src.port = flowKey->ipv6Key.l4.tpSrc;
        ctx->key.dst.port = flowKey->ipv6Key.l4.tpDst;
    }

    /* Related bit is set for ICMP and FTP (Not supported)*/
    ctx->related = FALSE;

    hsrc = OvsJhashBytes((UINT32*) &ctx->key.src, sizeof(ctx->key.src), 0);
    hdst = OvsJhashBytes((UINT32*) &ctx->key.dst, sizeof(ctx->key.dst), 0);
    hash = hsrc ^ hdst; /* TO identify reverse traffic */
    ctx->hash = OvsJhashBytes((uint32_t *) &ctx->key.dst + 1,
                              ((uint32_t *) (&ctx->key + 1) -
                              (uint32_t *) (&ctx->key.dst + 1)),
                              hash);
}

/*
 *----------------------------------------------------------------------------
 * OvsProcessConntrackEntry
 *     Check the TCP flags and set the ct_state of the entry
 *----------------------------------------------------------------------------
 */
static __inline POVS_CT_ENTRY
OvsProcessConntrackEntry(PNET_BUFFER_LIST curNbl,
                         const TCPHdr *tcp,
                         OvsConntrackKeyLookupCtx *ctx,
                         OvsFlowKey *key,
                         UINT16 zone,
                         BOOLEAN commit,
                         UINT64 currentTime)
{
    POVS_CT_ENTRY entry = ctx->entry;
    UINT32 state = 0;

    /* If an entry was found, update the state based on TCP flags */
    if (ctx->related) {
        state |= OVS_CS_F_RELATED;
        if (ctx->reply) {
            state = OVS_CS_F_REPLY_DIR;
        }
    } else {
        CT_UPDATE_RES result;
        result = OvsConntrackUpdateTcpEntry(entry, tcp, curNbl,
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
            OvsCtEntryDelete(ctx->entry);
            ctx->entry = NULL;
            entry = OvsCtEntryCreate(tcp, curNbl, ctx, key,
                                     commit, currentTime);
            break;
        }
    }
    /* Copy mark and label from entry into flowKey. If actions specify
       different mark and label, update the flowKey. */
    OvsCtUpdateFlowKey(key, state, zone, entry->mark, &entry->labels);
    return entry;
}

static __inline VOID
OvsConntrackSetMark(OvsFlowKey *key,
                    POVS_CT_ENTRY entry,
                    UINT32 value,
                    UINT32 mask)
{
    UINT32 newMark;
    newMark = value | (entry->mark & ~(mask));
    if (entry->mark != newMark) {
        entry->mark = newMark;
        key->ct.mark = newMark;
    }
}

static __inline void
OvsConntrackSetLabels(OvsFlowKey *key,
                      POVS_CT_ENTRY entry,
                      struct ovs_key_ct_labels *val,
                      struct ovs_key_ct_labels *mask)
{
    ovs_u128 v, m, pktMdLabel;
    memcpy(&v, val, sizeof v);
    memcpy(&m, mask, sizeof m);

    pktMdLabel.u64.lo = v.u64.lo | (pktMdLabel.u64.lo & ~(m.u64.lo));
    pktMdLabel.u64.hi = v.u64.hi | (pktMdLabel.u64.hi & ~(m.u64.hi));

    NdisMoveMemory(&entry->labels, &pktMdLabel,
                   sizeof(struct ovs_key_ct_labels));
    NdisMoveMemory(&key->ct.labels, &pktMdLabel,
                   sizeof(struct ovs_key_ct_labels));
}

static __inline NDIS_STATUS
OvsCtExecute_(PNET_BUFFER_LIST curNbl,
              OvsFlowKey *key,
              OVS_PACKET_HDR_INFO *layers,
              BOOLEAN commit,
              UINT16 zone,
              MD_MARK *mark,
              MD_LABELS *labels)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    POVS_CT_ENTRY entry = NULL;
    OvsConntrackKeyLookupCtx ctx = { 0 };
    TCPHdr tcpStorage;
    UINT64 currentTime;
    LOCK_STATE_EX lockState;
    const TCPHdr *tcp;
    tcp = OvsGetTcp(curNbl, layers->l4Offset, &tcpStorage);
    NdisGetCurrentSystemTime((LARGE_INTEGER *) &currentTime);

    /* Retrieve the Conntrack Key related fields from packet */
    OvsCtSetupLookupCtx(key, zone, &ctx);

    NdisAcquireRWLockWrite(ovsConntrackLockObj, &lockState, 0);

    /* Lookup Conntrack entries for a matching entry */
    entry = OvsCtLookup(&ctx);

    if (!entry) {
        /* If no matching entry was found, create one and add New state */
        entry = OvsCtEntryCreate(tcp, curNbl, &ctx,
                                 key, commit, currentTime);
    } else {
        /* Process the entry and update CT flags */
        entry = OvsProcessConntrackEntry(curNbl, tcp, &ctx, key,
                                         zone, commit, currentTime);
    }

    if (entry && mark) {
        OvsConntrackSetMark(key, entry, mark->value, mark->mask);
    }

    if (entry && labels) {
        OvsConntrackSetLabels(key, entry, &labels->value, &labels->mask);
    }

    NdisReleaseRWLock(ovsConntrackLockObj, &lockState);

    return status;
}

/*
 *---------------------------------------------------------------------------
 * OvsExecuteConntrackAction
 *     Executes Conntrack actions XXX - Add more
 *---------------------------------------------------------------------------
 */
NDIS_STATUS
OvsExecuteConntrackAction(PNET_BUFFER_LIST curNbl,
                          OVS_PACKET_HDR_INFO *layers,
                          OvsFlowKey *key,
                          const PNL_ATTR a)
{
    PNL_ATTR ctAttr;
    BOOLEAN commit = FALSE;
    UINT16 zone = 0;
    MD_MARK *mark = NULL;
    MD_LABELS *labels = NULL;
    NDIS_STATUS status;

    status = OvsDetectCtPacket(key);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    ctAttr = NlAttrFindNested(a, OVS_CT_ATTR_ZONE);
    if (ctAttr) {
        zone = NlAttrGetU16(ctAttr);
    }
    ctAttr = NlAttrFindNested(a, OVS_CT_ATTR_COMMIT);
    if (ctAttr) {
        commit = TRUE;
    }
    ctAttr = NlAttrFindNested(a, OVS_CT_ATTR_MARK);
    if (ctAttr) {
        mark = NlAttrGet(ctAttr);
    }
    ctAttr = NlAttrFindNested(a, OVS_CT_ATTR_LABELS);
    if (ctAttr) {
        labels = NlAttrGet(ctAttr);
    }

    status = OvsCtExecute_(curNbl, key, layers,
                           commit, zone, mark, labels);
    return status;
}

/*
 *----------------------------------------------------------------------------
 * OvsConntrackEnrtyCleaner
 *     Runs periodically and cleans up the connection tracker
 *----------------------------------------------------------------------------
 */
VOID
ovsConntrackEntryCleaner(PVOID data)
{

    POVS_CT_THREAD_CTX context = (POVS_CT_THREAD_CTX)data;
    PLIST_ENTRY link, next;
    POVS_CT_ENTRY entry;
    BOOLEAN success = TRUE;

    while (success) {
        LOCK_STATE_EX lockState;
        NdisAcquireRWLockWrite(ovsConntrackLockObj, &lockState, 0);
        if (context->exit) {
            NdisReleaseRWLock(ovsConntrackLockObj, &lockState);
            break;
        }

        /* Set the timeout for the thread and cleanup */
        UINT64 currentTime, threadSleepTimeout;
        NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
        threadSleepTimeout = currentTime + CT_CLEANUP_INTERVAL;

        for (int i = 0; i < CT_HASH_TABLE_SIZE; i++) {
            LIST_FORALL_SAFE(&ovsConntrackTable[i], link, next) {
                entry = CONTAINING_RECORD(link, OVS_CT_ENTRY, link);
                if (entry->expiration < currentTime) {
                    OvsCtEntryDelete(entry);
                }
            }
        }

        NdisReleaseRWLock(ovsConntrackLockObj, &lockState);
        KeWaitForSingleObject(&context->event, Executive, KernelMode,
                              FALSE, (LARGE_INTEGER *)&threadSleepTimeout);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}
