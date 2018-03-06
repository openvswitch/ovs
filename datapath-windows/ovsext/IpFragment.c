/*
 * Copyright (c) 2017 VMware, Inc.
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
#include "Debug.h"
#include "IpFragment.h"
#include "Jhash.h"
#include "Offload.h"
#include "PacketParser.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_IPFRAG

#define MIN_FRAGMENT_SIZE 400
#define MAX_IPDATAGRAM_SIZE 65535
#define MAX_FRAGMENTS MAX_IPDATAGRAM_SIZE/MIN_FRAGMENT_SIZE + 1

/* Function declarations */
static KSTART_ROUTINE OvsIpFragmentEntryCleaner;
static VOID OvsIpFragmentEntryDelete(POVS_IPFRAG_ENTRY entry, BOOLEAN checkExpiry);

/* Global and static variables */
static OVS_IPFRAG_THREAD_CTX ipFragThreadCtx;
static PNDIS_RW_LOCK_EX ovsIpFragmentHashLockObj;
static UINT64 ipTotalEntries;
static PLIST_ENTRY OvsIpFragTable;

NDIS_STATUS
OvsInitIpFragment(POVS_SWITCH_CONTEXT context)
{

    NDIS_STATUS status;
    HANDLE threadHandle = NULL;

    /* Init the sync-lock */
    ovsIpFragmentHashLockObj = NdisAllocateRWLock(context->NdisFilterHandle);
    if (ovsIpFragmentHashLockObj == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Init the Hash Buffer */
    OvsIpFragTable = OvsAllocateMemoryWithTag(sizeof(LIST_ENTRY)
                                              * IP_FRAG_HASH_TABLE_SIZE,
                                              OVS_IPFRAG_POOL_TAG);
    if (OvsIpFragTable == NULL) {
        NdisFreeRWLock(ovsIpFragmentHashLockObj);
        ovsIpFragmentHashLockObj = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (int i = 0; i < IP_FRAG_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&OvsIpFragTable[i]);
    }

    /* Init Cleaner Thread */
    KeInitializeEvent(&ipFragThreadCtx.event, NotificationEvent, FALSE);
    status = PsCreateSystemThread(&threadHandle, SYNCHRONIZE, NULL, NULL,
                                  NULL, OvsIpFragmentEntryCleaner,
                                  &ipFragThreadCtx);

    if (status != STATUS_SUCCESS) {
        OvsFreeMemoryWithTag(OvsIpFragTable, OVS_IPFRAG_POOL_TAG);
        OvsIpFragTable = NULL;
        NdisFreeRWLock(ovsIpFragmentHashLockObj);
        ovsIpFragmentHashLockObj = NULL;
        return status;
    }

    ObReferenceObjectByHandle(threadHandle, SYNCHRONIZE, NULL, KernelMode,
                              &ipFragThreadCtx.threadObject, NULL);
    ZwClose(threadHandle);
    threadHandle = NULL;
    return STATUS_SUCCESS;
}

static __inline UINT32
OvsGetIPFragmentHash(POVS_IPFRAG_KEY fragKey)
{
    UINT32 arr[6];
    arr[0] = (UINT32)fragKey->protocol;
    arr[1] = (UINT32)fragKey->id;
    arr[2] = (UINT32)fragKey->sAddr;
    arr[3] = (UINT32)fragKey->dAddr;
    arr[4] = (UINT32)((fragKey->tunnelId & 0xFFFFFFFF00000000LL) >> 32);
    arr[5] = (UINT32)(fragKey->tunnelId & 0xFFFFFFFFLL);
    return OvsJhashWords(arr, 6, OVS_HASH_BASIS);
}

static __inline POVS_IPFRAG_ENTRY
OvsLookupIPFrag(POVS_IPFRAG_KEY fragKey, UINT32 hash)
{
    POVS_IPFRAG_ENTRY entry;
    PLIST_ENTRY link;
    LOCK_STATE_EX lockState;

    NdisAcquireRWLockRead(ovsIpFragmentHashLockObj, &lockState, 0);
    LIST_FORALL(&OvsIpFragTable[hash & IP_FRAG_HASH_TABLE_MASK], link) {
        entry = CONTAINING_RECORD(link, OVS_IPFRAG_ENTRY, link);
        NdisAcquireSpinLock(&(entry->lockObj));
        if (entry->fragKey.dAddr == fragKey->dAddr &&
            entry->fragKey.sAddr == fragKey->sAddr &&
            entry->fragKey.id == fragKey->id &&
            entry->fragKey.protocol == fragKey->protocol &&
            entry->fragKey.tunnelId == fragKey->tunnelId) {
            NdisReleaseSpinLock(&(entry->lockObj));
            NdisReleaseRWLock(ovsIpFragmentHashLockObj, &lockState);
            return entry;
        }
        NdisReleaseSpinLock(&(entry->lockObj));
    }
    NdisReleaseRWLock(ovsIpFragmentHashLockObj, &lockState);
    return NULL;
}

/*
 *----------------------------------------------------------------------------
 * OvsIpv4Reassemble
 *     Reassemble the ipv4 fragments and return newNbl on success.
 *     Should be called after acquiring the lockObj for the entry.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsIpv4Reassemble(POVS_SWITCH_CONTEXT switchContext,
                  PNET_BUFFER_LIST *curNbl,
                  OvsCompletionList *completionList,
                  NDIS_SWITCH_PORT_ID sourcePort,
                  POVS_IPFRAG_ENTRY entry,
                  PNET_BUFFER_LIST *newNbl)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_STRING filterReason;
    POVS_BUFFER_CONTEXT ctx;
    PNET_BUFFER curNb;
    EthHdr *eth;
    IPHdr *ipHdr, *newIpHdr;
    CHAR *ethBuf[sizeof(EthHdr)];
    CHAR *packetBuf;
    UINT16 ipHdrLen, packetHeader;
    POVS_FRAGMENT_LIST head = NULL;
    UINT32 packetLen;

    curNb = NET_BUFFER_LIST_FIRST_NB(*curNbl);
    ASSERT(NET_BUFFER_NEXT_NB(curNb) == NULL);

    eth = (EthHdr*)NdisGetDataBuffer(curNb, ETH_HEADER_LENGTH,
                                     (PVOID)&ethBuf, 1, 0);
    if (eth == NULL) {
        return NDIS_STATUS_INVALID_PACKET;
    }
    ipHdr = (IPHdr *)((PCHAR)eth + ETH_HEADER_LENGTH);
    if (ipHdr == NULL) {
        return NDIS_STATUS_INVALID_PACKET;
    }
    ipHdrLen = ipHdr->ihl * 4;
    if (ipHdrLen + entry->totalLen > MAX_IPDATAGRAM_SIZE) {
        return NDIS_STATUS_INVALID_LENGTH;
    }
    packetLen = ETH_HEADER_LENGTH + ipHdrLen + entry->totalLen;
    packetBuf = (CHAR*)OvsAllocateMemoryWithTag(packetLen,
                                                OVS_IPFRAG_POOL_TAG);
    if (packetBuf == NULL) {
        OVS_LOG_ERROR("Insufficient resources, failed to allocate packetBuf");
        return NDIS_STATUS_RESOURCES;
    }

    /* copy Ethernet header */
    NdisMoveMemory(packetBuf, eth, ETH_HEADER_LENGTH);
    /* copy ipv4 header to packet buff */
    NdisMoveMemory(packetBuf + ETH_HEADER_LENGTH, ipHdr, ipHdrLen);

    /* update new ip header */
    newIpHdr = (IPHdr *)(packetBuf + ETH_HEADER_LENGTH);
    newIpHdr->frag_off = 0;
    newIpHdr->tot_len = htons(packetLen - ETH_HEADER_LENGTH);
    newIpHdr->check = 0;
    newIpHdr->check = IPChecksum((UINT8 *)packetBuf + ETH_HEADER_LENGTH,
                                 ipHdrLen, 0);
    packetHeader = ETH_HEADER_LENGTH + ipHdrLen;
    head = entry->head;
    while (head) {
        if ((UINT32)(packetHeader + head->offset) > packetLen) {
            status = NDIS_STATUS_INVALID_DATA;
            goto cleanup;
        }
        NdisMoveMemory(packetBuf + packetHeader + head->offset,
                       head->pbuff, head->len);
        head = head->next;
    }
    /* Create new nbl from the flat buffer */
    *newNbl = OvsAllocateNBLFromBuffer(switchContext, packetBuf, packetLen);
    if (*newNbl == NULL) {
        OVS_LOG_ERROR("Insufficient resources, failed to allocate newNbl");
        status = NDIS_STATUS_RESOURCES;
        goto cleanup;
    }

    /* Complete the fragment NBL */
    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(*curNbl);
    if (ctx->flags & OVS_BUFFER_NEED_COMPLETE) {
        RtlInitUnicodeString(&filterReason, L"Complete last fragment");
        OvsAddPktCompletionList(completionList, TRUE, sourcePort, *curNbl, 1,
                                &filterReason);
    } else {
        OvsCompleteNBL(switchContext, *curNbl, TRUE);
    }
    /* Store mru in the ovs buffer context. */
    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(*newNbl);
    ctx->mru = entry->mru;
    *curNbl = *newNbl;
cleanup:
    OvsFreeMemoryWithTag(packetBuf, OVS_IPFRAG_POOL_TAG);
    entry->markedForDelete = TRUE;
    return status;
}
/*
 *----------------------------------------------------------------------------
 * OvsProcessIpv4Fragment
 *     Reassemble the fragments once all the fragments are recieved and
 *     return NDIS_STATUS_PENDING for the pending fragments
 *     XXX - Instead of copying NBls, Keep the NBLs in limbo state.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsProcessIpv4Fragment(POVS_SWITCH_CONTEXT switchContext,
                       PNET_BUFFER_LIST *curNbl,
                       OvsCompletionList *completionList,
                       NDIS_SWITCH_PORT_ID sourcePort,
                       ovs_be64 tunnelId,
                       PNET_BUFFER_LIST *newNbl)
{
    NDIS_STATUS status = NDIS_STATUS_PENDING;
    PNET_BUFFER curNb;
    CHAR *ethBuf[sizeof(EthHdr)];
    UINT16 offset, flags;
    UINT16 payloadLen, ipHdrLen;
    UINT32 hash;
    UINT64 currentTime;
    EthHdr *eth;
    IPHdr *ipHdr;
    OVS_IPFRAG_KEY fragKey;
    POVS_IPFRAG_ENTRY entry;
    POVS_FRAGMENT_LIST fragStorage;
    LOCK_STATE_EX htLockState;

    curNb = NET_BUFFER_LIST_FIRST_NB(*curNbl);
    ASSERT(NET_BUFFER_NEXT_NB(curNb) == NULL);

    eth = (EthHdr*)NdisGetDataBuffer(curNb, ETH_HEADER_LENGTH,
                                     (PVOID)&ethBuf, 1, 0);
    if (eth == NULL) {
        return NDIS_STATUS_INVALID_PACKET;
    }

    ipHdr = (IPHdr *)((PCHAR)eth + ETH_HEADER_LENGTH);
    if (ipHdr == NULL) {
        return NDIS_STATUS_INVALID_PACKET;
    }
    ipHdrLen = ipHdr->ihl * 4;
    payloadLen = ntohs(ipHdr->tot_len) - ipHdrLen;
    offset = ntohs(ipHdr->frag_off) & IP_OFFSET;
    offset <<= 3;
    flags = ntohs(ipHdr->frag_off) & IP_MF;

    /*Copy fragment specific fields. */
    fragKey.protocol = ipHdr->protocol;
    fragKey.id = ipHdr->id;
    fragKey.sAddr = ipHdr->saddr;
    fragKey.dAddr = ipHdr->daddr;
    fragKey.tunnelId = tunnelId;
    /* Padding. */
    NdisZeroMemory(&fragKey.pad_1, 3);
    fragKey.pad_2 = 0;

    fragStorage = (POVS_FRAGMENT_LIST )
        OvsAllocateMemoryWithTag(sizeof(OVS_FRAGMENT_LIST),
                                 OVS_IPFRAG_POOL_TAG);
    if (fragStorage == NULL) {
        OVS_LOG_ERROR("Insufficient resources, fail to allocate fragStorage");
        return NDIS_STATUS_RESOURCES;
    }

    fragStorage->pbuff = (CHAR *)OvsAllocateMemoryWithTag(payloadLen,
                                                          OVS_IPFRAG_POOL_TAG);
    if (fragStorage->pbuff == NULL) {
        OVS_LOG_ERROR("Insufficient resources, fail to allocate pbuff");
        OvsFreeMemoryWithTag(fragStorage, OVS_IPFRAG_POOL_TAG);
        return NDIS_STATUS_RESOURCES;
    }

    /* Copy payload from nbl to fragment storage. */
    if (OvsGetPacketBytes(*curNbl, payloadLen, ETH_HEADER_LENGTH + ipHdrLen,
                          fragStorage->pbuff) == NULL) {
        status = NDIS_STATUS_RESOURCES;
        goto payload_copy_error;
    }
    fragStorage->len = payloadLen;
    fragStorage->offset = offset;
    fragStorage->next = NULL;
    hash = OvsGetIPFragmentHash(&fragKey);
    entry = OvsLookupIPFrag(&fragKey, hash);
    if (entry == NULL) {
        entry = (POVS_IPFRAG_ENTRY)
            OvsAllocateMemoryWithTag(sizeof(OVS_IPFRAG_ENTRY),
                                     OVS_IPFRAG_POOL_TAG);
        if (entry == NULL) {
            status = NDIS_STATUS_RESOURCES;
            goto payload_copy_error;
        }
        /* Copy the fragmeny key. */
        NdisZeroMemory(entry, sizeof(OVS_IPFRAG_ENTRY));
        NdisMoveMemory(&(entry->fragKey), &fragKey,
                       sizeof(OVS_IPFRAG_KEY));
        /* Init MRU. */
        entry->mru = ETH_HEADER_LENGTH + ipHdrLen + payloadLen;
        entry->recvdLen += fragStorage->len;
        entry->head = entry->tail = fragStorage;
        entry->numFragments = 1;
        if (!flags) {
            entry->totalLen = offset + payloadLen;
        }
        NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
        entry->expiration = currentTime + IPFRAG_ENTRY_TIMEOUT;

        /* Init the sync-lock. */
        NdisAllocateSpinLock(&(entry->lockObj));
        NdisAcquireRWLockWrite(ovsIpFragmentHashLockObj, &htLockState, 0);
        InsertHeadList(&OvsIpFragTable[hash & IP_FRAG_HASH_TABLE_MASK],
                       &entry->link);

        ipTotalEntries++;
        NdisReleaseRWLock(ovsIpFragmentHashLockObj, &htLockState);
        return NDIS_STATUS_PENDING;
    } else {
        /* Acquire the entry lock. */
        NdisAcquireSpinLock(&(entry->lockObj));
        NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
        if (currentTime > entry->expiration || entry->numFragments == MAX_FRAGMENTS) {
            /* Mark the entry for delete. */
            entry->markedForDelete = TRUE;
            goto fragment_error;
        }
        POVS_FRAGMENT_LIST next = entry->head;
        POVS_FRAGMENT_LIST prev = entry->tail;
        if (prev != NULL && prev->offset < offset) {
            next = NULL;
            goto found;
        }
        prev = NULL;
        for (next = entry->head; next != NULL; next = next->next) {
            if (next->offset > fragStorage->offset) {
                break;
            }
            prev = next;
        }
found:
        /*Check for overlap. */
        if (prev) {
            /* i bytes overlap. */
            int i = (prev->offset + prev->len) - fragStorage->offset;
            if (i > 0) {
                goto fragment_error;
            }
        }
        if (next) {
            /* i bytes overlap. */
            int i = (fragStorage->offset + fragStorage->len) - next->offset;
            if (i > 0) {
                goto fragment_error;
            }
        }

        if (entry->recvdLen + fragStorage->len > entry->recvdLen) {
            entry->recvdLen += fragStorage->len;
        } else {
            /* Overflow, ignore the fragment.*/
            goto fragment_error;
        }

        /*Insert. */
        if (prev) {
            prev->next = fragStorage;
            fragStorage->next = next;
        } else {
            fragStorage->next = next;
            entry->head = fragStorage;
        }
        if (!next) {
            entry->tail = fragStorage;
        }

        /*Update Maximum recieved Unit */
        entry->mru = entry->mru > (ETH_HEADER_LENGTH + ipHdrLen + payloadLen) ?
            entry->mru : (ETH_HEADER_LENGTH + ipHdrLen + payloadLen);
        entry->numFragments++;
        if (!flags) {
            entry->totalLen = offset + payloadLen;
        }
        if (entry->recvdLen == entry->totalLen) {
            status = OvsIpv4Reassemble(switchContext, curNbl, completionList,
                                       sourcePort, entry, newNbl);
        }
        NdisReleaseSpinLock(&(entry->lockObj));
        return status;
    }
fragment_error:
    status = NDIS_STATUS_INVALID_PACKET;
    /* Release the entry lock. */
    NdisReleaseSpinLock(&(entry->lockObj));
payload_copy_error:
    OvsFreeMemoryWithTag(fragStorage->pbuff, OVS_IPFRAG_POOL_TAG);
    OvsFreeMemoryWithTag(fragStorage, OVS_IPFRAG_POOL_TAG);
    return status;
}


/*
 *----------------------------------------------------------------------------
 * OvsIpFragmentEntryCleaner
 *     Runs periodically and cleans up the Ip Fragment table
 *     Interval is selected as twice the entry timeout
 *----------------------------------------------------------------------------
 */
static VOID
OvsIpFragmentEntryCleaner(PVOID data)
{

    POVS_IPFRAG_THREAD_CTX context = (POVS_IPFRAG_THREAD_CTX)data;
    PLIST_ENTRY link, next;
    POVS_IPFRAG_ENTRY entry;
    LOCK_STATE_EX lockState;
    BOOLEAN success = TRUE;

    while (success) {
        if (ovsIpFragmentHashLockObj == NULL) {
            /* Lock has been freed by 'OvsCleanupIpFragment()' */
            break;
        }
        NdisAcquireRWLockWrite(ovsIpFragmentHashLockObj, &lockState, 0);
        if (context->exit) {
            NdisReleaseRWLock(ovsIpFragmentHashLockObj, &lockState);
            break;
        }

        /* Set the timeout for the thread and cleanup. */
        UINT64 currentTime, threadSleepTimeout;
        NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
        threadSleepTimeout = currentTime + IPFRAG_CLEANUP_INTERVAL;
        for (int i = 0; i < IP_FRAG_HASH_TABLE_SIZE && ipTotalEntries; i++) {
            LIST_FORALL_SAFE(&OvsIpFragTable[i], link, next) {
                entry = CONTAINING_RECORD(link, OVS_IPFRAG_ENTRY, link);
                OvsIpFragmentEntryDelete(entry, TRUE);
            }
        }

        NdisReleaseRWLock(ovsIpFragmentHashLockObj, &lockState);
        KeWaitForSingleObject(&context->event, Executive, KernelMode,
                              FALSE, (LARGE_INTEGER *)&threadSleepTimeout);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID
OvsIpFragmentEntryDelete(POVS_IPFRAG_ENTRY entry, BOOLEAN checkExpiry)
{
    NdisAcquireSpinLock(&(entry->lockObj));
    if (!entry->markedForDelete && checkExpiry) {
        UINT64 currentTime;
        NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
        if (entry->expiration > currentTime) {
            NdisReleaseSpinLock(&(entry->lockObj));
            return;
        }
    }

    POVS_FRAGMENT_LIST head = entry->head;
    POVS_FRAGMENT_LIST temp = NULL;
    while (head) {
        temp = head;
        head = head->next;
        OvsFreeMemoryWithTag(temp->pbuff, OVS_IPFRAG_POOL_TAG);
        OvsFreeMemoryWithTag(temp, OVS_IPFRAG_POOL_TAG);
    }
    RemoveEntryList(&entry->link);
    ipTotalEntries--;
    NdisReleaseSpinLock(&(entry->lockObj));
    NdisFreeSpinLock(&(entry->lockObj));
    OvsFreeMemoryWithTag(entry, OVS_IPFRAG_POOL_TAG);
}

VOID
OvsCleanupIpFragment(VOID)
{
    PLIST_ENTRY link, next;
    POVS_IPFRAG_ENTRY entry;
    LOCK_STATE_EX lockState;

    ipFragThreadCtx.exit = 1;
    KeSetEvent(&ipFragThreadCtx.event, 0, FALSE);
    KeWaitForSingleObject(ipFragThreadCtx.threadObject, Executive,
                          KernelMode, FALSE, NULL);
    ObDereferenceObject(ipFragThreadCtx.threadObject);
    NdisAcquireRWLockWrite(ovsIpFragmentHashLockObj, &lockState, 0);
    if (OvsIpFragTable) {
        for (int i = 0; i < IP_FRAG_HASH_TABLE_SIZE && ipTotalEntries; i++) {
            LIST_FORALL_SAFE(&OvsIpFragTable[i], link, next) {
                entry = CONTAINING_RECORD(link, OVS_IPFRAG_ENTRY, link);
                OvsIpFragmentEntryDelete(entry, FALSE);
            }
        }
        OvsFreeMemoryWithTag(OvsIpFragTable, OVS_IPFRAG_POOL_TAG);
        OvsIpFragTable = NULL;
    }
    NdisReleaseRWLock(ovsIpFragmentHashLockObj, &lockState);
    NdisFreeRWLock(ovsIpFragmentHashLockObj);
    ovsIpFragmentHashLockObj = NULL;
 }
