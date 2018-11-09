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

#ifndef __IPFRAGMENT_H_
#define __IPFRAGMENT_H_ 1
#include "PacketIO.h"

typedef struct _OVS_FRAGMENT_LIST {
    CHAR *pbuff;
    UINT16 len;
    UINT16 offset;
    struct _OVS_FRAGMENT_LIST *next;
} OVS_FRAGMENT_LIST, *POVS_FRAGMENT_LIST;

typedef struct _OVS_IPFRAG_KEY {
    UINT8 protocol;
    UINT8 pad_1[3];             /* Align the structure to address boundaries.*/
    UINT16 id;
    UINT16 pad_2;               /* Align the structure to address boundaries.*/
    UINT32 sAddr;
    UINT32 dAddr;
    ovs_be64 tunnelId;
} OVS_IPFRAG_KEY, *POVS_IPFRAG_KEY;

typedef struct _OVS_IPFRAG_ENTRY {
    NDIS_SPIN_LOCK lockObj;       /* To access the entry. */
    BOOLEAN markedForDelete;
    UINT8 numFragments;
    UINT16 totalLen;
    UINT16 recvdLen;
    UINT16 mru;
    UINT64 expiration;
    OVS_IPFRAG_KEY fragKey;
    POVS_FRAGMENT_LIST head;
    POVS_FRAGMENT_LIST tail;
    LIST_ENTRY link;
} OVS_IPFRAG_ENTRY, *POVS_IPFRAG_ENTRY;

typedef struct _OVS_IPFRAG_THREAD_CTX {
    KEVENT event;
    PVOID threadObject;
    UINT32 exit;
} OVS_IPFRAG_THREAD_CTX, *POVS_IPFRAG_THREAD_CTX;

#define IP_FRAG_HASH_TABLE_SIZE ((UINT32)1 << 10)
#define IP_FRAG_HASH_TABLE_MASK (IP_FRAG_HASH_TABLE_SIZE - 1)
/*30s -Sufficient time to receive all fragments.*/
#define IPFRAG_ENTRY_TIMEOUT 300000000LL
#define IPFRAG_CLEANUP_INTERVAL IPFRAG_ENTRY_TIMEOUT * 2 /*1m.*/
PNET_BUFFER_LIST OvsIpv4FragmentNBL(PVOID ovsContext,
                                    PNET_BUFFER_LIST nbl,
                                    UINT16 mru);

NDIS_STATUS OvsProcessIpv4Fragment(POVS_SWITCH_CONTEXT switchContext,
                                   PNET_BUFFER_LIST *curNbl,
                                   OvsCompletionList *completionList,
                                   NDIS_SWITCH_PORT_ID sourcePort,
                                   POVS_PACKET_HDR_INFO layers,
                                   ovs_be64 tunnelId);
NDIS_STATUS OvsInitIpFragment(POVS_SWITCH_CONTEXT context);
VOID OvsCleanupIpFragment(VOID);
#endif /* __IPFRAGMENT_H_ */
