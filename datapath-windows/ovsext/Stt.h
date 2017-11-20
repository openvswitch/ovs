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

#ifndef __OVS_STT_H_
#define __OVS_STT_H_ 1

#include "IpHelper.h"

typedef union _OVS_FWD_INFO *POVS_FWD_INFO;

#define STT_TCP_PORT 7471
#define STT_TCP_PORT_NBO 0x2f1d

#define MAX_IP_TOTAL_LEN 65535

// STT defines.
#define STT_SEQ_LEN_SHIFT 16
#define STT_SEQ_OFFSET_MASK ((1 << STT_SEQ_LEN_SHIFT) - 1)
#define STT_FRAME_LEN(seq) ((seq) >> STT_SEQ_LEN_SHIFT)
#define STT_SEGMENT_OFF(seq) ((seq) & STT_SEQ_OFFSET_MASK)

#define STT_CSUM_VERIFIED   (1 << 0)
#define STT_CSUM_PARTIAL    (1 << 1)
#define STT_PROTO_IPV4      (1 << 2)
#define STT_PROTO_TCP       (1 << 3)
#define STT_PROTO_TYPES     (STT_PROTO_IPV4 | STT_PROTO_TCP)

#define STT_HASH_TABLE_SIZE ((UINT32)1 << 10)
#define STT_HASH_TABLE_MASK (STT_HASH_TABLE_SIZE - 1)
#define STT_ENTRY_TIMEOUT 300000000   // 30s
#define STT_CLEANUP_INTERVAL 300000000 // 30s

#define STT_ETH_PAD 2
typedef struct SttHdr {
    UINT8    version;
    UINT8    flags;
    UINT8    l4Offset;
    UINT8    reserved;
    UINT16   mss;
    UINT16   vlanTCI;
    UINT64   key;
} SttHdr, *PSttHdr;

#define STT_HDR_LEN (sizeof(SttHdr) + STT_ETH_PAD)

typedef struct _OVS_STT_VPORT {
    UINT16 dstPort;
    UINT64 ackNo;
    UINT64 ipId;
} OVS_STT_VPORT, *POVS_STT_VPORT;

typedef struct _OVS_STT_PKT_KEY {
    UINT32 sAddr;
    UINT32 dAddr;
    UINT32 ackSeq;
} OVS_STT_PKT_KEY, *POVS_STT_PKT_KEY;

typedef struct _OVS_STT_PKT_ENTRY {
    OVS_STT_PKT_KEY     ovsPktKey;
    UINT64              timeout;
    UINT32              recvdLen;
    UINT32              allocatedLen;
    UINT8               ecn;
    SttHdr              sttHdr;
    PCHAR               packetBuf;
    LIST_ENTRY          link;
} OVS_STT_PKT_ENTRY, *POVS_STT_PKT_ENTRY;

typedef struct _OVS_STT_THREAD_CTX {
    KEVENT      event;
    PVOID       threadObject;
    UINT32      exit;
} OVS_STT_THREAD_CTX, *POVS_STT_THREAD_CTX;

NTSTATUS OvsInitSttTunnel(POVS_VPORT_ENTRY vport,
                          UINT16 udpDestPort);

VOID OvsCleanupSttTunnel(POVS_VPORT_ENTRY vport);

NDIS_STATUS OvsEncapStt(POVS_VPORT_ENTRY vport,
                        PNET_BUFFER_LIST curNbl,
                        OvsIPv4TunnelKey *tunKey,
                        POVS_SWITCH_CONTEXT switchContext,
                        POVS_PACKET_HDR_INFO layers,
                        PNET_BUFFER_LIST *newNbl,
                        POVS_FWD_INFO switchFwdInfo);


NDIS_STATUS OvsDecapStt(POVS_SWITCH_CONTEXT switchContext,
                        PNET_BUFFER_LIST curNbl,
                        OvsIPv4TunnelKey *tunKey,
                        PNET_BUFFER_LIST *newNbl);

NTSTATUS OvsInitSttDefragmentation();

VOID OvsCleanupSttDefragmentation(VOID);

static __inline UINT32
OvsGetSttTunHdrSize(VOID)
{
    return sizeof (EthHdr) + sizeof(IPHdr) + sizeof(TCPHdr) +
                  STT_HDR_LEN;
}

static __inline UINT32
OvsGetSttTunHdrSizeFromLayers(POVS_PACKET_HDR_INFO layers)
{
    return layers->l7Offset + STT_HDR_LEN;
}

#endif /*__OVS_STT_H_ */
