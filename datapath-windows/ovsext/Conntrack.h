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

#ifndef __OVS_CONNTRACK_H_
#define __OVS_CONNTRACK_H_ 1

#include "precomp.h"
#include "Actions.h"
#include "Debug.h"
#include "Flow.h"
#include "Actions.h"
#include <stddef.h>

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_CONTRK

struct ct_addr {
    union {
        ovs_be32 ipv4;
        struct in6_addr ipv6;
        uint32_t ipv4_aligned;
        struct in6_addr ipv6_aligned;
    };
};

struct ct_endpoint {
    struct ct_addr addr;
    union {
        struct {
            ovs_be16 port;
            uint16 pad_port;
        };
        struct {
            ovs_be16 icmp_id;
            uint8_t icmp_type;
            uint8_t icmp_code;
        };
    };
};

typedef enum CT_UPDATE_RES {
    CT_UPDATE_INVALID,
    CT_UPDATE_VALID,
    CT_UPDATE_NEW,
} CT_UPDATE_RES;

/* Metadata mark for masked write to conntrack mark */
typedef struct MD_MARK {
    UINT32 value;
    UINT32 mask;
} MD_MARK;

/* Metadata label for masked write to conntrack label. */
typedef struct MD_LABELS {
    struct ovs_key_ct_labels value;
    struct ovs_key_ct_labels mask;
} MD_LABELS;

typedef enum _NAT_ACTION {
    NAT_ACTION_NONE = 0,
    NAT_ACTION_REVERSE = 1 << 0,
    NAT_ACTION_SRC = 1 << 1,
    NAT_ACTION_SRC_PORT = 1 << 2,
    NAT_ACTION_DST = 1 << 3,
    NAT_ACTION_DST_PORT = 1 << 4,
} NAT_ACTION;

typedef struct _OVS_CT_KEY {
    struct ct_endpoint src;
    struct ct_endpoint dst;
    UINT16 dl_type;
    UINT8 nw_proto;
    UINT16 zone;
    UINT64 packetCount;
    UINT64 byteCount;
} OVS_CT_KEY, *POVS_CT_KEY;

typedef struct _NAT_ACTION_INFO {
    struct ct_addr minAddr;
    struct ct_addr maxAddr;
    uint16_t minPort;
    uint16_t maxPort;
    uint16_t natAction;
} NAT_ACTION_INFO, *PNAT_ACTION_INFO;

typedef struct OVS_CT_ENTRY {
    OVS_CT_KEY  key;
    OVS_CT_KEY  rev_key;
    UINT64      expiration;
    LIST_ENTRY  link;
    UINT32      mark;
    UINT64      timestampStart;
    struct ovs_key_ct_labels labels;
    NAT_ACTION_INFO natInfo;
    PVOID       parent; /* Points to main connection */
} OVS_CT_ENTRY, *POVS_CT_ENTRY;

typedef struct OVS_CT_REL_ENTRY {
    OVS_CT_KEY      key;
    POVS_CT_ENTRY   parent;
    UINT64          expiration;
    LIST_ENTRY      link;
} OVS_CT_REL_ENTRY, *POVS_CT_REL_ENTRY;

typedef struct _OVS_CT_THREAD_CTX {
    KEVENT      event;
    PVOID       threadObject;
    UINT32      exit;
} OVS_CT_THREAD_CTX, *POVS_CT_THREAD_CTX;

typedef struct OvsConntrackKeyLookupCtx {
    OVS_CT_KEY      key;
    POVS_CT_ENTRY   entry;
    UINT32          hash;
    BOOLEAN         reply;
    BOOLEAN         related;
} OvsConntrackKeyLookupCtx;

#define CT_MAX_ENTRIES 1 << 21
#define CT_HASH_TABLE_SIZE ((UINT32)1 << 10)
#define CT_HASH_TABLE_MASK (CT_HASH_TABLE_SIZE - 1)
#define CT_INTERVAL_SEC 10000000LL //1s
#define CT_ENTRY_TIMEOUT (2 * 60 * CT_INTERVAL_SEC)   // 2m
#define CT_CLEANUP_INTERVAL (2 * 60 * CT_INTERVAL_SEC) // 2m


/* Given POINTER, the address of the given MEMBER in a STRUCT object, returns
   the STRUCT object. */
#define CONTAINER_OF(POINTER, STRUCT, MEMBER)                           \
        ((STRUCT *) (void *) ((char *) (POINTER) - \
         offsetof (STRUCT, MEMBER)))

static __inline void
OvsConntrackUpdateExpiration(OVS_CT_ENTRY *ctEntry,
                             long long now,
                             long long interval)
{
    ctEntry->expiration = now + interval;
}

static __inline UINT32
OvsGetTcpPayloadLength(PNET_BUFFER_LIST nbl)
{
    IPHdr *ipHdr;
    char *ipBuf[sizeof(IPHdr)];
    PNET_BUFFER curNb;
    curNb = NET_BUFFER_LIST_FIRST_NB(nbl);
    UINT32 hdrLen = sizeof(EthHdr);
    NdisAdvanceNetBufferDataStart(curNb, hdrLen, FALSE, NULL);
    ipHdr = NdisGetDataBuffer(curNb, sizeof *ipHdr, (PVOID) &ipBuf,
                              1 /*no align*/, 0);
    if (ipHdr == NULL) {
        NdisRetreatNetBufferDataStart(curNb, hdrLen, 0, NULL);
        return 0;
    }

    TCPHdr *tcp = (TCPHdr *)((PCHAR)ipHdr + ipHdr->ihl * 4);
    NdisRetreatNetBufferDataStart(curNb, hdrLen, 0, NULL);

    return (ntohs(ipHdr->tot_len) - (ipHdr->ihl * 4) - (TCP_HDR_LEN(tcp)));
}

VOID OvsCleanupConntrack(VOID);
NTSTATUS OvsInitConntrack(POVS_SWITCH_CONTEXT context);

NDIS_STATUS OvsExecuteConntrackAction(OvsForwardingContext *fwdCtx,
                                      OvsFlowKey *key,
                                      const PNL_ATTR a);
BOOLEAN OvsConntrackValidateTcpPacket(const TCPHdr *tcp);
BOOLEAN OvsConntrackValidateIcmpPacket(const ICMPHdr *icmp);
OVS_CT_ENTRY * OvsConntrackCreateTcpEntry(const TCPHdr *tcp,
                                          PNET_BUFFER_LIST nbl,
                                          UINT64 now);
NDIS_STATUS OvsCtMapTcpProtoInfoToNl(PNL_BUFFER nlBuf,
                                     OVS_CT_ENTRY *conn_);
OVS_CT_ENTRY * OvsConntrackCreateOtherEntry(UINT64 now);
OVS_CT_ENTRY * OvsConntrackCreateIcmpEntry(UINT64 now);
enum CT_UPDATE_RES OvsConntrackUpdateTcpEntry(OVS_CT_ENTRY* conn_,
                                              const TCPHdr *tcp,
                                              PNET_BUFFER_LIST nbl,
                                              BOOLEAN reply,
                                              UINT64 now);
enum CT_UPDATE_RES OvsConntrackUpdateOtherEntry(OVS_CT_ENTRY *conn_,
                                                BOOLEAN reply,
                                                UINT64 now);
enum CT_UPDATE_RES OvsConntrackUpdateIcmpEntry(OVS_CT_ENTRY* conn_,
                                               BOOLEAN reply,
                                               UINT64 now);
NTSTATUS OvsCreateNlMsgFromCtEntry(POVS_CT_ENTRY entry,
                                   PVOID outBuffer,
                                   UINT32 outBufLen,
                                   UINT8 eventType,
                                   UINT32 nlmsgSeq,
                                   UINT32 nlmsgPid,
                                   UINT8 nfGenVersion,
                                   UINT32 dpIfIndex);

/* Tracking related connections */
NTSTATUS OvsInitCtRelated(POVS_SWITCH_CONTEXT context);
VOID OvsCleanupCtRelated(VOID);
NDIS_STATUS OvsCtRelatedEntryCreate(UINT8 ipProto,
                                    UINT16 dl_type,
                                    UINT32 serverIp,
                                    UINT32 clientIp,
                                    UINT16 serverPort,
                                    UINT16 clientPort,
                                    UINT64 currentTime,
                                    POVS_CT_ENTRY parent);
POVS_CT_ENTRY OvsCtRelatedLookup(OVS_CT_KEY key, UINT64 currentTime);

NDIS_STATUS OvsCtHandleFtp(PNET_BUFFER_LIST curNbl,
                           OvsFlowKey *key,
                           OVS_PACKET_HDR_INFO *layers,
                           UINT64 currentTime,
                           POVS_CT_ENTRY entry,
                           BOOLEAN request);

UINT32 OvsHashCtKey(const OVS_CT_KEY *key);
BOOLEAN OvsCtKeyAreSame(OVS_CT_KEY ctxKey, OVS_CT_KEY entryKey);
POVS_CT_ENTRY OvsCtLookup(OvsConntrackKeyLookupCtx *ctx);


#endif /* __OVS_CONNTRACK_H_ */
