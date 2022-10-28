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

#ifndef __IP6FRAGMENT_H_
#define __IP6FRAGMENT_H_ 1
#include "PacketIO.h"

typedef struct _OVS_FRAGMENT6_LIST {
    CHAR *pbuff;
    UINT16 len; /* Fragment data length. */
    UINT16 offset; /* Fragment data offset. */
    struct _OVS_FRAGMENT6_LIST *next;
} OVS_FRAGMENT6_LIST, *POVS_FRAGMENT6_LIST;

typedef struct _OVS_IP6FRAG_KEY {
    UINT8 protocol;
    UINT8 pad_1[3];             /* Align the structure to address boundaries.*/
    UINT32 id;
    struct in6_addr sAddr;
    struct in6_addr dAddr;
    ovs_be64 tunnelId;
} OVS_IP6FRAG_KEY, *POVS_IP6FRAG_KEY;

typedef struct _OVS_IP6FRAG_ENTRY {
    NDIS_SPIN_LOCK lockObj;       /* To access the entry. */
    BOOLEAN markedForDelete;
    UINT8 numFragments;
    UINT16 totalLen; /* The packet data total length(not
                      * include ipv6 header and opt header length) before
                      * fragment */
    UINT16 recvdLen; /* Total data length packet contains has received */
    UINT16 mru; /* Max receive unit(it's the whole ethernet frame
                 * packet length), it will be used in sent out before forward */
    UINT64 expiration;
    /* refer https://www.rfc-editor.org/rfc/rfc8200.html */
    PCHAR beforeFragHdrBuf;/* ipv6 extension header buf before fragment field */
    UINT16 beforeFragHdrLen;
    UINT16 priorFragEleOffset;/* The last element before fragment field offset */
    PCHAR fragHdrBuf;
    UINT16 fragHdrLen;
    PCHAR behindFragHdrBuf;/* ipv6 extension header buf behind fragment field */
    UINT16 behindFragHdrLen;
    OVS_IP6FRAG_KEY fragKey;
    POVS_FRAGMENT6_LIST head;
    POVS_FRAGMENT6_LIST tail;
    LIST_ENTRY link;
} OVS_IP6FRAG_ENTRY, *POVS_IP6FRAG_ENTRY;

typedef struct _IP6_PktExtHeader_Meta {
    UINT8 firstHdr;
    UINT8 protocol;
    UINT16 beforeFragExtHdrLen;
    UINT16 fragExtHdrLen;
    UINT16 behindFragExtHdrLen;
    UINT16 extHdrTotalLen;
    UINT16 dataPayloadLen;/* Ipv6 data length, not include extension header */
    UINT16 fragOffset;
    UINT16 priorFragEleOffset;
    UINT16 flags;
    UINT16 pktMru;
    UINT32 ident;
    PCHAR beforeFragElePtr;
    IPv6ExtHdr *firstHdrPtr;
} IP6_PktExtHeader_Meta, *PIP6_PktExtHeader_Meta;

typedef struct _OVS_IP6FRAG_THREAD_CTX {
    KEVENT event;
    PVOID threadObject;
    UINT32 exit;
} OVS_IP6FRAG_THREAD_CTX, *POVS_IP6FRAG_THREAD_CTX;

#define IP6_FRAG_HASH_TABLE_SIZE ((UINT32)1 << 10)
#define IP6_FRAG_HASH_TABLE_MASK (IP6_FRAG_HASH_TABLE_SIZE - 1)

#define IP6FRAG_ENTRY_TIMEOUT 300000000LL
#define IP6FRAG_CLEANUP_INTERVAL IP6FRAG_ENTRY_TIMEOUT * 2 /*1m.*/

NDIS_STATUS OvsProcessIpv6Fragment(POVS_SWITCH_CONTEXT switchContext,
                       PNET_BUFFER_LIST *curNbl,
                       OvsCompletionList *completionList,
                       NDIS_SWITCH_PORT_ID sourcePort,
                       POVS_PACKET_HDR_INFO layers,
                       ovs_be64 tunnelId, OvsFlowKey *key);
NDIS_STATUS OvsStorageIpv6ExtHeader(POVS_IP6FRAG_ENTRY entry,
                                    UINT16 beforeFragHdrLen,
                                    UINT16 fragHdrLen,
                                    UINT16 behindFragHdrLen,
                                    UINT16 priorFragEleOffset,
                                    CHAR *pktBuf,
                                    POVS_PACKET_HDR_INFO layers);
NDIS_STATUS OvsInitIp6Fragment(POVS_SWITCH_CONTEXT context);
VOID OvsCleanupIp6Fragment(VOID);
NDIS_STATUS OvsGetPacketMeta(PIP6_PktExtHeader_Meta pktMeta, EthHdr *eth,
                             OvsFlowKey *key, POVS_PACKET_HDR_INFO layers);
PCHAR OvsBuildNewIpv6Hdr(EthHdr *eth, POVS_IP6FRAG_ENTRY entry,
                         POVS_PACKET_HDR_INFO layers, UINT32 *pktLen);

#endif //_IP6FRAGMENT_H_
