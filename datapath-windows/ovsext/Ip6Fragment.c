/*
 * Copyright (c) 2022 VMware, Inc.
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
#include "Ip6Fragment.h"
#include "Util.h"
#include "Jhash.h"
#include "NetProto.h"
#include "PacketParser.h"

static OVS_IP6FRAG_THREAD_CTX ip6FragThreadCtx;
static PNDIS_RW_LOCK_EX ovsIp6FragmentHashLockObj;
static UINT64 ip6TotalEntries;
static PLIST_ENTRY OvsIp6FragTable;

#define MIN_FRAGMENT_SIZE 400
#define MAX_IPDATAGRAM_SIZE 65535
#define MAX_FRAGMENTS MAX_IPDATAGRAM_SIZE/MIN_FRAGMENT_SIZE + 1

static __inline UINT32
OvsGetIP6FragmentHash(POVS_IP6FRAG_KEY fragKey)
{
    UINT32 arr[11];
    arr[0] = (UINT32)fragKey->id;
    arr[1] = (UINT32)(((UINT32*)(&(fragKey->sAddr)))[0]);
    arr[2] = (UINT32)(((UINT32*)(&(fragKey->sAddr)))[1]);
    arr[3] = (UINT32)(((UINT32*)(&(fragKey->sAddr)))[2]);
    arr[4] = (UINT32)(((UINT32*)(&(fragKey->sAddr)))[3]);
    arr[5] = (UINT32)(((UINT32*)(&(fragKey->dAddr)))[0]);
    arr[6] = (UINT32)(((UINT32*)(&(fragKey->dAddr)))[1]);
    arr[7] = (UINT32)(((UINT32*)(&(fragKey->dAddr)))[2]);
    arr[8] = (UINT32)(((UINT32*)(&(fragKey->dAddr)))[3]);
    arr[9] = (UINT32)((fragKey->tunnelId & 0xFFFFFFFF00000000LL) >> 32);
    arr[10] = (UINT32)(fragKey->tunnelId & 0xFFFFFFFFLL);
    return OvsJhashWords(arr, 11, OVS_HASH_BASIS);
}

static VOID
OvsIp6FragmentEntryDelete(POVS_IP6FRAG_ENTRY entry, BOOLEAN checkExpiry)
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

    POVS_FRAGMENT6_LIST head = entry->head;
    POVS_FRAGMENT6_LIST temp = NULL;
    while (head) {
        temp = head;
        head = head->next;
        OvsFreeMemoryWithTag(temp->pbuff, OVS_IP6FRAG_POOL_TAG);
        OvsFreeMemoryWithTag(temp, OVS_IP6FRAG_POOL_TAG);
    }
    RemoveEntryList(&entry->link);
    ip6TotalEntries--;
    NdisReleaseSpinLock(&(entry->lockObj));
    NdisFreeSpinLock(&(entry->lockObj));
    if (entry->beforeFragHdrLen > 0) {
        OvsFreeMemoryWithTag(entry->beforeFragHdrBuf, OVS_IP6FRAG_POOL_TAG);
    }

    if (entry->fragHdrLen > 0) {
        OvsFreeMemoryWithTag(entry->fragHdrBuf, OVS_IP6FRAG_POOL_TAG);
    }

    if (entry->behindFragHdrLen > 0) {
        OvsFreeMemoryWithTag(entry->behindFragHdrBuf, OVS_IP6FRAG_POOL_TAG);
    }

    OvsFreeMemoryWithTag(entry, OVS_IP6FRAG_POOL_TAG);
}

static VOID
OvsIp6FragmentEntryCleaner(PVOID data)
{
    POVS_IP6FRAG_THREAD_CTX context = (POVS_IP6FRAG_THREAD_CTX)data;
    PLIST_ENTRY link, next;
    POVS_IP6FRAG_ENTRY entry;
    LOCK_STATE_EX lockState;
    BOOLEAN success = TRUE;

    while (success) {
        if (ovsIp6FragmentHashLockObj == NULL) {
            /* Lock has been freed by 'OvsCleanupIpFragment()' */
            break;
        }
        NdisAcquireRWLockWrite(ovsIp6FragmentHashLockObj, &lockState, 0);
        if (context->exit) {
            NdisReleaseRWLock(ovsIp6FragmentHashLockObj, &lockState);
            break;
        }

        /* Set the timeout for the thread and cleanup. */
        UINT64 currentTime, threadSleepTimeout;
        NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
        threadSleepTimeout = currentTime + IP6FRAG_CLEANUP_INTERVAL;
        for (int i = 0; i < IP6_FRAG_HASH_TABLE_SIZE && ip6TotalEntries; i++) {
            LIST_FORALL_SAFE(&OvsIp6FragTable[i], link, next) {
                entry = CONTAINING_RECORD(link, OVS_IP6FRAG_ENTRY, link);
                OvsIp6FragmentEntryDelete(entry, TRUE);
            }
        }

        NdisReleaseRWLock(ovsIp6FragmentHashLockObj, &lockState);
        KeWaitForSingleObject(&context->event, Executive, KernelMode,
                              FALSE, (LARGE_INTEGER *)&threadSleepTimeout);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NDIS_STATUS OvsInitIp6Fragment(POVS_SWITCH_CONTEXT context)
{
    NDIS_STATUS status;
    HANDLE threadHandle = NULL;

    OVS_LOG_INFO("Init ipv6 fragment.");
    ovsIp6FragmentHashLockObj = NdisAllocateRWLock(context->NdisFilterHandle);
    if (ovsIp6FragmentHashLockObj == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Init the Hash Buffer */
    OvsIp6FragTable = OvsAllocateMemoryWithTag(sizeof(LIST_ENTRY)
                                              * IP6_FRAG_HASH_TABLE_SIZE,
                                              OVS_IP6FRAG_POOL_TAG);
    if (OvsIp6FragTable == NULL) {
        NdisFreeRWLock(ovsIp6FragmentHashLockObj);
        ovsIp6FragmentHashLockObj = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }


    for (int i = 0; i < IP6_FRAG_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&OvsIp6FragTable[i]);
    }

    /* Init Cleaner Thread */
    KeInitializeEvent(&ip6FragThreadCtx.event, NotificationEvent, FALSE);
    status = PsCreateSystemThread(&threadHandle, SYNCHRONIZE, NULL, NULL,
                                  NULL, OvsIp6FragmentEntryCleaner,
                                  &ip6FragThreadCtx);

    if (status != STATUS_SUCCESS) {
        OvsFreeMemoryWithTag(OvsIp6FragTable, OVS_IPFRAG_POOL_TAG);
        OvsIp6FragTable = NULL;
        NdisFreeRWLock(ovsIp6FragmentHashLockObj);
        ovsIp6FragmentHashLockObj = NULL;
        return status;
    }

    ObReferenceObjectByHandle(threadHandle, SYNCHRONIZE, NULL, KernelMode,
                              &ip6FragThreadCtx.threadObject, NULL);
    ZwClose(threadHandle);
    threadHandle = NULL;
    return STATUS_SUCCESS;
}

static __inline POVS_IP6FRAG_ENTRY
OvsLookupIP6Frag(POVS_IP6FRAG_KEY fragKey, UINT32 hash)
{
    POVS_IP6FRAG_ENTRY entry;
    PLIST_ENTRY link;
    LOCK_STATE_EX lockState;

    NdisAcquireRWLockRead(ovsIp6FragmentHashLockObj, &lockState, 0);
    LIST_FORALL(&OvsIp6FragTable[hash & IP6_FRAG_HASH_TABLE_MASK], link) {
        entry = CONTAINING_RECORD(link, OVS_IP6FRAG_ENTRY, link);
        NdisAcquireSpinLock(&(entry->lockObj));
        if (RtlCompareMemory(&entry->fragKey.dAddr, &fragKey->dAddr,
                             sizeof(fragKey->dAddr)) == sizeof(fragKey->dAddr) &&
            RtlCompareMemory(&entry->fragKey.sAddr, &fragKey->sAddr,
                             sizeof(fragKey->sAddr)) == sizeof(fragKey->sAddr) &&
            entry->fragKey.id == fragKey->id &&
            entry->fragKey.tunnelId == fragKey->tunnelId) {
            NdisReleaseSpinLock(&(entry->lockObj));
            NdisReleaseRWLock(ovsIp6FragmentHashLockObj, &lockState);
            return entry;
        }
        NdisReleaseSpinLock(&(entry->lockObj));
    }
    NdisReleaseRWLock(ovsIp6FragmentHashLockObj, &lockState);
    return NULL;
}

VOID OvsCleanupIp6Fragment(VOID)
{
    PLIST_ENTRY link, next;
    POVS_IP6FRAG_ENTRY entry;
    LOCK_STATE_EX lockState;

    ip6FragThreadCtx.exit = 1;
    KeSetEvent(&ip6FragThreadCtx.event, 0, FALSE);
    KeWaitForSingleObject(ip6FragThreadCtx.threadObject, Executive,
                          KernelMode, FALSE, NULL);
    ObDereferenceObject(ip6FragThreadCtx.threadObject);
    NdisAcquireRWLockWrite(ovsIp6FragmentHashLockObj, &lockState, 0);
    if (OvsIp6FragTable) {
        for (int i = 0; i < IP6_FRAG_HASH_TABLE_SIZE && ip6TotalEntries; i++) {
            LIST_FORALL_SAFE(&OvsIp6FragTable[i], link, next) {
                entry = CONTAINING_RECORD(link, OVS_IP6FRAG_ENTRY, link);
                OvsIp6FragmentEntryDelete(entry, FALSE);
            }
        }
        OvsFreeMemoryWithTag(OvsIp6FragTable, OVS_IP6FRAG_POOL_TAG);
        OvsIp6FragTable = NULL;
    }
    NdisReleaseRWLock(ovsIp6FragmentHashLockObj, &lockState);
    NdisFreeRWLock(ovsIp6FragmentHashLockObj);
    ovsIp6FragmentHashLockObj = NULL;
}

PCHAR
OvsBuildNewIpv6Hdr(EthHdr *eth, POVS_IP6FRAG_ENTRY entry,
                   POVS_PACKET_HDR_INFO layers,
                   UINT32 *pktLen)
{
    IPv6Hdr *ipHdr = NULL;
    IPv6Hdr *newIpHdr = NULL;
    PCHAR ipv6StdPtr = NULL;
    PCHAR packetBuf = NULL;
    UINT32 packetLen = 0;

    ipHdr = (IPv6Hdr *)((PCHAR)eth + layers->l3Offset);
    if (layers->l4Offset + entry->totalLen > MAX_IPDATAGRAM_SIZE) {
        return NULL;
    }

    packetLen = (layers->l3Offset + sizeof(IPv6Hdr) +
                 entry->beforeFragHdrLen + entry->behindFragHdrLen + entry->totalLen);
    packetBuf = (CHAR*)OvsAllocateMemoryWithTag(packetLen, OVS_IP6FRAG_POOL_TAG);
    if (packetBuf == NULL) {
        return NULL;
    }
    *pktLen = packetLen;

    NdisMoveMemory(packetBuf, eth, layers->l3Offset + sizeof(IPv6Hdr));
    IPv6ExtHdr *extHdr = (IPv6ExtHdr *)((PCHAR)packetBuf + layers->l3Offset +
                                        sizeof(IPv6Hdr));
    ipv6StdPtr = (PCHAR)extHdr;
    newIpHdr = (IPv6Hdr *)(packetBuf + layers->l3Offset);
    newIpHdr->payload_len = htons(entry->beforeFragHdrLen +
                                  entry->behindFragHdrLen + entry->totalLen);

    /* Copy extension header to new packet buf. */
    if (entry->beforeFragHdrLen > 0) {
        NdisMoveMemory(ipv6StdPtr, entry->beforeFragHdrBuf,
                       entry->beforeFragHdrLen);
    }

    if (entry->behindFragHdrLen > 0) {
        NdisMoveMemory((ipv6StdPtr + entry->beforeFragHdrLen),
                       entry->behindFragHdrBuf,
                       entry->behindFragHdrLen);
    }

    /* Fix next header. */
    if (entry->beforeFragHdrLen > 0) {
        extHdr = (IPv6ExtHdr *)((PCHAR)extHdr + entry->priorFragEleOffset);
        extHdr->nextHeader =  ((IPv6FragHdr *)(entry->fragHdrBuf))->nextHeader;
    }

    if (entry->beforeFragHdrLen == 0) {
        if (entry->behindFragHdrLen == 0) {
            newIpHdr->nexthdr = entry->fragKey.protocol;
        } else {
            newIpHdr->nexthdr = ((IPv6FragHdr *)(entry->fragHdrBuf))->nextHeader;
        }
    }

    return packetBuf;
}


NDIS_STATUS
OvsIpv6Reassemble(POVS_SWITCH_CONTEXT switchContext,
                  PNET_BUFFER_LIST *curNbl,
                  OvsCompletionList *completionList,
                  NDIS_SWITCH_PORT_ID sourcePort,
                  POVS_IP6FRAG_ENTRY entry,
                  POVS_PACKET_HDR_INFO layers)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    NDIS_STRING filterReason;
    POVS_BUFFER_CONTEXT ctx;
    PNET_BUFFER curNb;
    EthHdr *eth;
    CHAR *packetBuf;
    POVS_FRAGMENT6_LIST head = NULL;
    PNET_BUFFER_LIST newNbl = NULL;
    UINT16 packetHeaderLen;
    UINT32 packetLen;

    curNb = NET_BUFFER_LIST_FIRST_NB(*curNbl);
    ASSERT(NET_BUFFER_NEXT_NB(curNb) == NULL);

    OVS_LOG_INFO("Process ipv6 reassemble, entry total length is %d.",
                 entry->totalLen);
    eth = (EthHdr*)NdisGetDataBuffer(curNb, layers->l4Offset,
                                     NULL, 1, 0);
    if (!eth) {
        return NDIS_STATUS_INVALID_PACKET;
    }

    packetBuf = OvsBuildNewIpv6Hdr(eth, entry, layers, &packetLen);
    if (!packetBuf) {
        return NDIS_STATUS_INVALID_PACKET;
    }

    head = entry->head;
    packetHeaderLen = (layers->l3Offset + sizeof(IPv6Hdr) +
                       entry->beforeFragHdrLen + entry->behindFragHdrLen);
    while (head) {
        if ((UINT32)(packetHeaderLen + (head->offset * 8) + head->len) > packetLen) {
            status = NDIS_STATUS_INVALID_DATA;
            goto cleanup;
        }
        NdisMoveMemory(packetBuf + packetHeaderLen + (head->offset * 8),
                       head->pbuff, head->len);
        head = head->next;
    }
    /* Create new nbl from the flat buffer */
    newNbl = OvsAllocateNBLFromBuffer(switchContext, packetBuf, packetLen);
    if (newNbl == NULL) {
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
    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(newNbl);
    ctx->mru = entry->mru;
    *curNbl = newNbl;
cleanup:
    OvsFreeMemoryWithTag(packetBuf, OVS_IP6FRAG_POOL_TAG);
    entry->markedForDelete = TRUE;
    return status;
}

NDIS_STATUS
OvsProcessIpv6Fragment(POVS_SWITCH_CONTEXT switchContext,
                       PNET_BUFFER_LIST *curNbl,
                       OvsCompletionList *completionList,
                       NDIS_SWITCH_PORT_ID sourcePort,
                       POVS_PACKET_HDR_INFO layers, ovs_be64 tunnelId,
                       OvsFlowKey *key)
{
    NDIS_STATUS status = NDIS_STATUS_PENDING;
    PNET_BUFFER curNb;
    UINT32 hash;
    UINT64 currentTime;
    EthHdr *eth;
    IPv6Hdr *ip6Hdr = NULL;
    OVS_IP6FRAG_KEY frag6Key;
    POVS_IP6FRAG_ENTRY entry;
    POVS_FRAGMENT6_LIST fragStorage;
    LOCK_STATE_EX htLockState;
    IP6_PktExtHeader_Meta pktMeta = {0};

    curNb = NET_BUFFER_LIST_FIRST_NB(*curNbl);
    ASSERT(NET_BUFFER_NEXT_NB(curNb) == NULL);

    OVS_LOG_INFO("Process ipv6 fragment.");
    eth = (EthHdr*)NdisGetDataBuffer(curNb, layers->l4Offset,
                                     NULL, 1, 0);
    if (eth == NULL) {
        return NDIS_STATUS_INVALID_PACKET;
    }

    ip6Hdr = (IPv6Hdr *)((PCHAR)eth + layers->l3Offset);
    status = OvsGetPacketMeta(&pktMeta, eth, key, layers);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    fragStorage = (POVS_FRAGMENT6_LIST)
            OvsAllocateMemoryWithTag(sizeof(OVS_FRAGMENT6_LIST),
                                     OVS_IP6FRAG_POOL_TAG);
    if (fragStorage == NULL) {
        OVS_LOG_ERROR("Insufficient resources, fail to allocate fragStorage");
        return NDIS_STATUS_RESOURCES;
    }

    fragStorage->len = pktMeta.dataPayloadLen;
    fragStorage->offset = pktMeta.fragOffset;
    fragStorage->next = NULL;
    fragStorage->pbuff = (CHAR *)OvsAllocateMemoryWithTag(fragStorage->len,
                                                          OVS_IP6FRAG_POOL_TAG);
    if (fragStorage->pbuff == NULL) {
        OVS_LOG_ERROR("Insufficient resources, fail to allocate pbuff");
        OvsFreeMemoryWithTag(fragStorage, OVS_IP6FRAG_POOL_TAG);
        return NDIS_STATUS_RESOURCES;
    }

    if (OvsGetPacketBytes(*curNbl, pktMeta.dataPayloadLen,
                          layers->l4Offset,
                          fragStorage->pbuff) == NULL) {
        status = NDIS_STATUS_RESOURCES;
        OVS_LOG_ERROR("Get packet bytes fail, pkt len is %d, offset is %d.",
                      pktMeta.dataPayloadLen, layers->l4Offset);
        goto payload_copy_error;
    }

    frag6Key.sAddr = ip6Hdr->saddr;
    frag6Key.dAddr = ip6Hdr->daddr;
    frag6Key.tunnelId = tunnelId;
    frag6Key.id = pktMeta.ident;

    hash = OvsGetIP6FragmentHash(&frag6Key);
    entry = OvsLookupIP6Frag(&frag6Key, hash);
    if (entry == NULL) {
        entry = (POVS_IP6FRAG_ENTRY)
                OvsAllocateMemoryWithTag(sizeof(OVS_IP6FRAG_ENTRY),
                                         OVS_IP6FRAG_POOL_TAG);
        if (entry == NULL) {
            status = NDIS_STATUS_RESOURCES;
            goto payload_copy_error;
        }
        /* Copy the fragmeny key. */
        NdisZeroMemory(entry, sizeof(OVS_IP6FRAG_ENTRY));
        NdisMoveMemory(&(entry->fragKey), &frag6Key, sizeof(OVS_IP6FRAG_KEY));
        /* Init MRU. */
        entry->mru = pktMeta.pktMru;
        entry->recvdLen = fragStorage->len;
        entry->head = entry->tail = fragStorage;
        entry->numFragments = 1;

        if (!pktMeta.fragOffset) {
            /* First packet, fragment offset is 0 */
            OVS_LOG_INFO("before fragment extension header len:%d "
                         "fragment extension header len:%d "
                         "behind fragment extension header len :%d "
                         "last element before fragment offset %d",
                         pktMeta.beforeFragExtHdrLen,
                         pktMeta.fragExtHdrLen,
                         pktMeta.behindFragExtHdrLen,
                         pktMeta.priorFragEleOffset);
           /* We could get all ext header info from first fragment packet. */
           status = OvsStorageIpv6ExtHeader(entry, pktMeta.beforeFragExtHdrLen,
                                            pktMeta.fragExtHdrLen,
                                            pktMeta.behindFragExtHdrLen,
                                            pktMeta.priorFragEleOffset,
                                            (PCHAR) eth, layers);
           if (status != NDIS_STATUS_SUCCESS) {
               OVS_LOG_INFO("StorageIpv6 header fails, parse failed.");
               OvsFreeMemoryWithTag(entry, OVS_IP6FRAG_POOL_TAG);
               goto payload_copy_error;
           }

           entry->fragKey.protocol = pktMeta.protocol;
           OVS_LOG_INFO("First packet, protocol is %d.",
                        entry->fragKey.protocol);
        }

        if (!pktMeta.flags) {
            /* It's the last fragment, it demonstrates the packet was arrived
             * out of order, we calculate the complte packet total length. */
            entry->totalLen = pktMeta.fragOffset * 8 +  pktMeta.dataPayloadLen;
        }

        NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
        entry->expiration = currentTime + IP6FRAG_ENTRY_TIMEOUT;

        /* Init the sync-lock. */
        NdisAllocateSpinLock(&(entry->lockObj));
        NdisAcquireRWLockWrite(ovsIp6FragmentHashLockObj, &htLockState, 0);
        InsertHeadList(&OvsIp6FragTable[hash & IP6_FRAG_HASH_TABLE_MASK],
                       &entry->link);

        ip6TotalEntries++;
        NdisReleaseRWLock(ovsIp6FragmentHashLockObj, &htLockState);
        return NDIS_STATUS_PENDING;
    } else {
        /* Acquire the entry lock. */
        NdisAcquireSpinLock(&(entry->lockObj));
        NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
        if (currentTime > entry->expiration ||
            (entry->numFragments == MAX_FRAGMENTS)) {
            /* Mark the entry for delete. */
            OVS_LOG_ERROR("Will delete the fragment numbers.");
            entry->markedForDelete = TRUE;
            goto fragment_error;
        }

        if (!pktMeta.fragOffset) {
            status = OvsStorageIpv6ExtHeader(entry, pktMeta.behindFragExtHdrLen,
                                             pktMeta.fragExtHdrLen,
                                             pktMeta.behindFragExtHdrLen,
                                             pktMeta.priorFragEleOffset,
                                             (PCHAR) eth,
                                             layers);
            if (status != NDIS_STATUS_SUCCESS) {
                OVS_LOG_ERROR("IPv6 Extension header not valid.");
                goto fragment_error;
            }

            entry->fragKey.protocol = pktMeta.protocol;
        }

        if (!pktMeta.flags) {
            entry->totalLen = pktMeta.fragOffset * 8 +  pktMeta.dataPayloadLen;
        }

        /* Find the element offset just large than fragment and insert the
         * fragment before it. */
        POVS_FRAGMENT6_LIST next = entry->head;
        POVS_FRAGMENT6_LIST prev = entry->tail;
        if (prev != NULL && prev->offset < pktMeta.fragOffset) {
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
            int i = ((prev->offset * 8) + prev->len) - (fragStorage->offset * 8);
            if (i > 0) {
                OVS_LOG_ERROR("IPv6 fragment error, prev offset %d, pre len "
                              "%d, frag offset %d",
                              prev->offset, prev->len, fragStorage->offset);
                goto fragment_error;
            }
        }
        if (next) {
            /* i bytes overlap. */
            int i = ((fragStorage->offset * 8) + fragStorage->len) -
                    (next->offset * 8);
            if (i > 0) {
                OVS_LOG_ERROR("IPv6 fragment error, frag offset %d, frag "
                              "len %d, next offset %d.",
                              fragStorage->offset, fragStorage->len,
                              next->offset);
                goto fragment_error;
            }
        }

        if (entry->recvdLen + fragStorage->len > entry->recvdLen) {
            entry->recvdLen += fragStorage->len;
        } else {
            /* Overflow, ignore the fragment.*/
            OVS_LOG_ERROR("IPv6 fragment error, entry recv len %d, frag "
                          "len %d.", entry->recvdLen, fragStorage->len);
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

        /*Update Maximum Receive Unit */
        entry->mru = entry->mru > pktMeta.pktMru ? entry->mru : pktMeta.pktMru;
        entry->numFragments++;

        OVS_LOG_INFO("Max mru is %d, entry total length %d, entry recv length %d, "
                     "extension header length is %d", entry->mru,
                     entry->totalLen, entry->recvdLen,
                     entry->behindFragHdrLen);
        if (entry->recvdLen == (entry->totalLen - entry->behindFragHdrLen)) {
            /* when exist ipv6 extension field behind ipv6 fragment field,
             * the ipv6 extension field will be regard as "data", the totalLen
             * represent the "fragment data length" + "ipv6 extension length
             * behind fragment". However, the recvdLen only represents the
             * data length, thus when we judge is or not receive a complete
             * packet, we should use
             * (entry->totalLen - entry->behindFragHdrLen) == entry->recvdLen */
            status = OvsIpv6Reassemble(switchContext, curNbl, completionList,
                                       sourcePort, entry, layers);
        }
        NdisReleaseSpinLock(&(entry->lockObj));
        return status;
    }

fragment_error:
    status = NDIS_STATUS_INVALID_PACKET;
    /* Release the entry lock. */
    NdisReleaseSpinLock(&(entry->lockObj));

payload_copy_error:
    OVS_LOG_ERROR("Payload error, exits.");
    OvsFreeMemoryWithTag(fragStorage->pbuff, OVS_IP6FRAG_POOL_TAG);
    OvsFreeMemoryWithTag(fragStorage, OVS_IP6FRAG_POOL_TAG);
    return status;
}

NDIS_STATUS
OvsGetPacketMeta(PIP6_PktExtHeader_Meta pktMeta, EthHdr *eth,
                 OvsFlowKey *key, POVS_PACKET_HDR_INFO layers)
{
    IPv6Hdr *ip6Hdr = NULL;
    IPv6ExtHdr *extHdr = NULL;
    UINT8 nextHdr;

    ip6Hdr = (IPv6Hdr *)((PCHAR)eth + layers->l3Offset);
    if (!ip6Hdr) {
        return NDIS_STATUS_INVALID_PACKET;
    }

    nextHdr = ip6Hdr->nexthdr;
    pktMeta->firstHdr = nextHdr;

    if ((nextHdr == SOCKET_IPPROTO_HOPOPTS) ||
        (nextHdr == SOCKET_IPPROTO_ROUTING) ||
        (nextHdr == SOCKET_IPPROTO_DSTOPTS) ||
        (nextHdr == SOCKET_IPPROTO_FRAGMENT)) {
        extHdr = (IPv6ExtHdr *)((PCHAR)ip6Hdr + sizeof(IPv6Hdr));
        pktMeta->firstHdrPtr = extHdr;
    } else {
        return NDIS_STATUS_INVALID_PACKET;
    }

    for (;;) {
        if ((nextHdr != SOCKET_IPPROTO_HOPOPTS)
            && (nextHdr != SOCKET_IPPROTO_ROUTING)
            && (nextHdr != SOCKET_IPPROTO_DSTOPTS)
            && (nextHdr != SOCKET_IPPROTO_AH)
            && (nextHdr != SOCKET_IPPROTO_FRAGMENT)) {
            /*
             * It's either a terminal header (e.g., TCP, UDP, Icmpv6) or one we
             * don't understand.  In either case, we're done with the
             * packet, so use it to fill in 'nw_proto'.
             */
            pktMeta->protocol = nextHdr;
            break;
        }

        if (nextHdr == SOCKET_IPPROTO_HOPOPTS ||
            nextHdr == SOCKET_IPPROTO_ROUTING ||
            nextHdr == SOCKET_IPPROTO_DSTOPTS ||
            nextHdr == SOCKET_IPPROTO_AH) {
            UINT8 len  = extHdr->hdrExtLen;
            nextHdr = extHdr->nextHeader;
            if (nextHdr == SOCKET_IPPROTO_FRAGMENT) {
                pktMeta->beforeFragElePtr = (PCHAR)(extHdr);
            }

            if (nextHdr == SOCKET_IPPROTO_AH) {
                extHdr = (IPv6ExtHdr *)((PCHAR)extHdr + (len  + 2) * 4);
                pktMeta->extHdrTotalLen += ((len + 2) * 4);
            } else {
                extHdr = (IPv6ExtHdr *)((PCHAR)extHdr + (len + 1) * 8);
                pktMeta->extHdrTotalLen += ((len + 1) * 8);
            }
        } else if (nextHdr == SOCKET_IPPROTO_FRAGMENT) {
            IPv6FragHdr *fragHdr = (IPv6FragHdr *)extHdr;
            pktMeta->ident = fragHdr->ident;
            pktMeta->beforeFragExtHdrLen = pktMeta->extHdrTotalLen;
            pktMeta->fragExtHdrLen = sizeof(IPv6FragHdr);
            pktMeta->extHdrTotalLen += sizeof(IPv6FragHdr);
            pktMeta->fragOffset = (ntohs(fragHdr->offlg)
                    & IP6F_OFF_HOST_ORDER_MASK) >> 3;
            pktMeta->flags = ntohs(fragHdr->offlg) & 0x01;
            nextHdr = extHdr->nextHeader;
            extHdr = (IPv6ExtHdr *)((PCHAR)extHdr + sizeof(IPv6FragHdr));
            if (key->ipv6Key.nwFrag == OVS_FRAG_TYPE_LATER) {
                pktMeta->protocol = SOCKET_IPPROTO_FRAGMENT;
                break;
            }
        }
    }

    pktMeta->dataPayloadLen = (ntohs(ip6Hdr->payload_len) -
                               pktMeta->extHdrTotalLen);
    OVS_LOG_INFO("playload len %d, extotalLen %d, datapyaload len %d.",
                 ntohs(ip6Hdr->payload_len),
                 pktMeta->extHdrTotalLen,
                 pktMeta->dataPayloadLen);
    pktMeta->behindFragExtHdrLen = (pktMeta->extHdrTotalLen -
                                    pktMeta->beforeFragExtHdrLen -
                                    pktMeta->fragExtHdrLen);
    pktMeta->pktMru = (layers->l3Offset + sizeof(IPv6Hdr) +
                      ntohs(ip6Hdr->payload_len));
    if (pktMeta->beforeFragElePtr) {
        pktMeta->priorFragEleOffset =  (UINT16)((PCHAR)pktMeta->beforeFragElePtr -
                                                (PCHAR)pktMeta->firstHdrPtr);
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 *-----------------------------------------------------------------------------
 * OvsStorageIpv6ExtHeader --
 *      In some scenario, we need to storage the ipv6 option header, this
 *      function is used to do it, we could divide ipv6 option field into
 *      three parts, including "option field before fragment
 *      field", "fragment field", "option field behind fragment field". The
 *      reason store extension header is that it's convenient to copy the
 *      specified to the fragment header.
 *-----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsStorageIpv6ExtHeader(POVS_IP6FRAG_ENTRY entry,
                        UINT16 beforeFragHdrLen,
                        UINT16 fragHdrLen,
                        UINT16 behindFragHdrLen,
                        UINT16 priorFragEleOffset,
                        CHAR *pktBuf,
                        POVS_PACKET_HDR_INFO layers)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    if (beforeFragHdrLen) {
        entry->beforeFragHdrBuf =
                OvsAllocateMemoryWithTag(beforeFragHdrLen,
                                         OVS_IP6FRAG_POOL_TAG);
        if (entry->beforeFragHdrBuf == NULL) {
            goto beforeFragHdrError;
        }
        entry->beforeFragHdrLen = beforeFragHdrLen;
        entry->priorFragEleOffset = priorFragEleOffset;
    }

    if (fragHdrLen) {
        entry->fragHdrBuf = OvsAllocateMemoryWithTag(fragHdrLen,
                                                     OVS_IP6FRAG_POOL_TAG);
        if (entry->fragHdrBuf == NULL) {
            goto fragHdrError;
        }
        entry->fragHdrLen = fragHdrLen;
    }

    if (behindFragHdrLen) {
        entry->behindFragHdrBuf =
                OvsAllocateMemoryWithTag(behindFragHdrLen,
                                         OVS_IP6FRAG_POOL_TAG);
        if (entry->behindFragHdrBuf == NULL) {
            goto behindFragHdrError;
        }
        entry->behindFragHdrLen = behindFragHdrLen;
    }

    if (entry->beforeFragHdrLen) {
        NdisMoveMemory(entry->beforeFragHdrBuf,
                       pktBuf + layers->l3Offset + sizeof(IPv6Hdr),
                       entry->beforeFragHdrLen);
    }

    if (entry->fragHdrLen) {
        NdisMoveMemory(entry->fragHdrBuf,
                       (pktBuf + layers->l3Offset +
                        sizeof(IPv6Hdr) + beforeFragHdrLen),
                       entry->fragHdrLen);
    }

    if (entry->behindFragHdrLen) {
        NdisMoveMemory(entry->behindFragHdrBuf,
                       (pktBuf + layers->l3Offset + sizeof(IPv6Hdr)
                        + beforeFragHdrLen + fragHdrLen),
                       entry->behindFragHdrLen);
    }

    return status;

behindFragHdrError:
fragHdrError:
    if (entry->fragHdrBuf) {
        OvsFreeMemoryWithTag(entry->fragHdrBuf, OVS_IP6FRAG_POOL_TAG);
    }
beforeFragHdrError:
    if (entry->beforeFragHdrBuf) {
        OvsFreeMemoryWithTag(entry->beforeFragHdrBuf, OVS_IP6FRAG_POOL_TAG);
    }
    status = NDIS_STATUS_RESOURCES;
    OVS_LOG_ERROR("Storage header fails due to header.");
    return status;
}
