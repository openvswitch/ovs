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

#include "Conntrack.h"
#include "Jhash.h"

static PLIST_ENTRY ovsCtRelatedTable; /* Holds related entries */
static UINT64 ctTotalRelatedEntries;
static OVS_CT_THREAD_CTX ctRelThreadCtx;
static PNDIS_RW_LOCK_EX ovsCtRelatedLockObj;
extern POVS_SWITCH_CONTEXT gOvsSwitchContext;
KSTART_ROUTINE OvsCtRelatedEntryCleaner;

static __inline UINT32
OvsExtractCtRelatedKeyHash(OVS_CT_KEY *key)
{
    UINT32 hsrc, hdst,hash;
    hsrc = OvsJhashBytes((UINT32*) &key->src, sizeof(key->src), 0);
    hdst = OvsJhashBytes((UINT32*) &key->dst, sizeof(key->dst), 0);
    hash = hsrc ^ hdst; /* TO identify reverse traffic */
    return hash;
}

static __inline BOOLEAN
OvsCtRelatedKeyAreSame(OVS_CT_KEY incomingKey, OVS_CT_KEY entryKey)
{
    /* FTP PASV - Client initiates the connection from unknown port */
    if ((incomingKey.dst.addr.ipv4 == entryKey.src.addr.ipv4) &&
        (incomingKey.dst.port == entryKey.src.port) &&
        (incomingKey.src.addr.ipv4 == entryKey.dst.addr.ipv4) &&
        (incomingKey.dl_type == entryKey.dl_type) &&
        (incomingKey.nw_proto == entryKey.nw_proto)) {
        return TRUE;
    }

    /* FTP ACTIVE - Server initiates the connection */
    if ((incomingKey.src.addr.ipv4 == entryKey.src.addr.ipv4) &&
        (incomingKey.src.port == entryKey.src.port) &&
        (incomingKey.dst.addr.ipv4 == entryKey.dst.addr.ipv4) &&
        (incomingKey.dst.port == entryKey.dst.port) &&
        (incomingKey.dl_type == entryKey.dl_type) &&
        (incomingKey.nw_proto == entryKey.nw_proto)) {
        return TRUE;
    }

    return FALSE;
}

/*
 *---------------------------------------------------------------------------
 * OvsCtRelatedLookup
 *     Checks the related connections table for an entry that matches the
 *     incoming connection. If there is a matching entry, then it returns
 *     the pointer to the original control connection.
 *
 *---------------------------------------------------------------------------
 */
POVS_CT_ENTRY
OvsCtRelatedLookup(OVS_CT_KEY key, UINT64 currentTime)
{
    PLIST_ENTRY link, next;
    POVS_CT_REL_ENTRY entry;
    LOCK_STATE_EX lockState;

    NdisAcquireRWLockRead(ovsCtRelatedLockObj, &lockState, 0);

    if (!ctTotalRelatedEntries) {
        NdisReleaseRWLock(ovsCtRelatedLockObj, &lockState);
        return NULL;
    }

    for (int i = 0; i < CT_HASH_TABLE_SIZE; i++) {
        /* XXX - Scan the table based on the hash instead */
        LIST_FORALL_SAFE(&ovsCtRelatedTable[i], link, next) {
            entry = CONTAINING_RECORD(link, OVS_CT_REL_ENTRY, link);
            if (entry->expiration > currentTime) {
                if (OvsCtRelatedKeyAreSame(key, entry->key)) {
                    NdisReleaseRWLock(ovsCtRelatedLockObj, &lockState);
                    return entry->parent;
                }
            }
        }
    }
    NdisReleaseRWLock(ovsCtRelatedLockObj, &lockState);
    return NULL;
}

static __inline VOID
OvsCtRelatedEntryDelete(POVS_CT_REL_ENTRY entry)
{
    RemoveEntryList(&entry->link);
    OvsFreeMemoryWithTag(entry, OVS_CT_POOL_TAG);
    ctTotalRelatedEntries--;
}

NDIS_STATUS
OvsCtRelatedEntryCreate(UINT8 ipProto,
                        UINT16 dl_type,
                        UINT32 serverIp,
                        UINT32 clientIp,
                        UINT16 serverPort,
                        UINT16 clientPort,
                        UINT64 currentTime,
                        POVS_CT_ENTRY parent)
{
    LOCK_STATE_EX lockState;
    POVS_CT_REL_ENTRY entry;
    entry = OvsAllocateMemoryWithTag(sizeof(OVS_CT_REL_ENTRY),
                                     OVS_CT_POOL_TAG);
    if (!entry) {
        return NDIS_STATUS_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(struct OVS_CT_REL_ENTRY));
    entry->expiration = currentTime + (CT_INTERVAL_SEC * 60);
    entry->key.src.addr.ipv4 = serverIp;
    entry->key.dst.addr.ipv4 = clientIp;
    entry->key.nw_proto = ipProto;
    entry->key.dl_type = dl_type;
    entry->key.src.port = serverPort;
    entry->key.dst.port = clientPort;
    entry->parent = parent;

    UINT32 hash = OvsExtractCtRelatedKeyHash(&entry->key);

    NdisAcquireRWLockWrite(ovsCtRelatedLockObj, &lockState, 0);
    InsertHeadList(&ovsCtRelatedTable[hash & CT_HASH_TABLE_MASK],
                   &entry->link);
    ctTotalRelatedEntries++;
    NdisReleaseRWLock(ovsCtRelatedLockObj, &lockState);

    return NDIS_STATUS_SUCCESS;
}

static __inline NDIS_STATUS
OvsCtRelatedFlush()
{
    PLIST_ENTRY link, next;
    POVS_CT_REL_ENTRY entry;

    LOCK_STATE_EX lockState;
    NdisAcquireRWLockWrite(ovsCtRelatedLockObj, &lockState, 0);

    if (ctTotalRelatedEntries) {
        for (int i = 0; i < CT_HASH_TABLE_SIZE; i++) {
            LIST_FORALL_SAFE(&ovsCtRelatedTable[i], link, next) {
                entry = CONTAINING_RECORD(link, OVS_CT_REL_ENTRY, link);
                OvsCtRelatedEntryDelete(entry);
            }
        }
    }

    NdisReleaseRWLock(ovsCtRelatedLockObj, &lockState);
    return NDIS_STATUS_SUCCESS;
}

/* XXX - Create a wrapper for managing Tables used by Connection Trackers */

/*
 *----------------------------------------------------------------------------
 * OvsCtRelatedEntryCleaner
 *     Runs periodically and cleans up the related connections tracker
 *----------------------------------------------------------------------------
 */
VOID
OvsCtRelatedEntryCleaner(PVOID data)
{
    POVS_CT_THREAD_CTX context = (POVS_CT_THREAD_CTX)data;
    PLIST_ENTRY link, next;
    POVS_CT_REL_ENTRY entry;
    BOOLEAN success = TRUE;

    while (success) {
        LOCK_STATE_EX lockState;
        NdisAcquireRWLockWrite(ovsCtRelatedLockObj, &lockState, 0);
        if (context->exit) {
            NdisReleaseRWLock(ovsCtRelatedLockObj, &lockState);
            break;
        }

        /* Set the timeout for the thread and cleanup */
        UINT64 currentTime, threadSleepTimeout;
        NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
        threadSleepTimeout = currentTime + CT_CLEANUP_INTERVAL;

        if (ctTotalRelatedEntries) {
            for (int i = 0; i < CT_HASH_TABLE_SIZE; i++) {
                LIST_FORALL_SAFE(&ovsCtRelatedTable[i], link, next) {
                    entry = CONTAINING_RECORD(link, OVS_CT_REL_ENTRY, link);
                    if (entry->expiration < currentTime) {
                        OvsCtRelatedEntryDelete(entry);
                    }
                }
            }
        }
        NdisReleaseRWLock(ovsCtRelatedLockObj, &lockState);
        KeWaitForSingleObject(&context->event, Executive, KernelMode,
                              FALSE, (LARGE_INTEGER *)&threadSleepTimeout);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/*
 *----------------------------------------------------------------------------
 * OvsInitCtRelated
 *     Initialize the components used by Related Connections Tracker
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsInitCtRelated(POVS_SWITCH_CONTEXT context)
{
    NTSTATUS status;
    HANDLE threadHandle = NULL;
    ctTotalRelatedEntries = 0;

    /* Init the sync-lock */
    ovsCtRelatedLockObj = NdisAllocateRWLock(context->NdisFilterHandle);
    if (ovsCtRelatedLockObj == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Init the Hash Buffer */
    ovsCtRelatedTable = OvsAllocateMemoryWithTag(sizeof(LIST_ENTRY)
                                                 * CT_HASH_TABLE_SIZE,
                                                 OVS_CT_POOL_TAG);
    if (ovsCtRelatedTable == NULL) {
        NdisFreeRWLock(ovsCtRelatedLockObj);
        ovsCtRelatedLockObj = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (int i = 0; i < CT_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&ovsCtRelatedTable[i]);
    }

    /* Init CT Cleaner Thread */
    KeInitializeEvent(&ctRelThreadCtx.event, NotificationEvent, FALSE);
    status = PsCreateSystemThread(&threadHandle, SYNCHRONIZE, NULL, NULL,
                                  NULL, OvsCtRelatedEntryCleaner,
                                  &ctRelThreadCtx);

    if (status != STATUS_SUCCESS) {
        NdisFreeRWLock(ovsCtRelatedLockObj);
        ovsCtRelatedLockObj = NULL;

        OvsFreeMemoryWithTag(ovsCtRelatedTable, OVS_CT_POOL_TAG);
        ovsCtRelatedTable = NULL;

        return status;
    }

    ObReferenceObjectByHandle(threadHandle, SYNCHRONIZE, NULL, KernelMode,
                              &ctRelThreadCtx.threadObject, NULL);
    ZwClose(threadHandle);
    threadHandle = NULL;
    return STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsCleanupCtRelated
 *     Cleanup memory and thread that were spawned for tracking related entry
 *----------------------------------------------------------------------------
 */
VOID
OvsCleanupCtRelated(VOID)
{
    LOCK_STATE_EX lockState;
    NdisAcquireRWLockWrite(ovsCtRelatedLockObj, &lockState, 0);
    ctRelThreadCtx.exit = 1;
    KeSetEvent(&ctRelThreadCtx.event, 0, FALSE);
    NdisReleaseRWLock(ovsCtRelatedLockObj, &lockState);

    KeWaitForSingleObject(ctRelThreadCtx.threadObject, Executive,
                          KernelMode, FALSE, NULL);
    ObDereferenceObject(ctRelThreadCtx.threadObject);

    if (ovsCtRelatedTable) {
        OvsCtRelatedFlush();
        OvsFreeMemoryWithTag(ovsCtRelatedTable, OVS_CT_POOL_TAG);
        ovsCtRelatedTable = NULL;
    }

    NdisFreeRWLock(ovsCtRelatedLockObj);
    ovsCtRelatedLockObj = NULL;
}
