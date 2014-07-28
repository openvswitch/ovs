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

#ifndef __OVS_FLOW_H_
#define __OVS_FLOW_H_ 1

#include "precomp.h"
#include "OvsSwitch.h"
#include "OvsUser.h"
#include "OvsNetProto.h"

typedef struct _OvsFlow {
    LIST_ENTRY ListEntry;            // In Datapath's flowTable.
    OvsFlowKey key;
    UINT64 hash;
    UINT32 actionsLen;
    UINT8 tcpFlags;
    UINT64 used;
    UINT64 packetCount;
    UINT64 byteCount;
    UINT32 userActionsLen;   // used for flow query
    UINT32 actionBufferLen;  // used for flow reuse
    struct nlattr actions[1];
} OvsFlow;


typedef struct _OvsLayers {
    UINT32 l3Ofs;             // IPv4, IPv6, ARP, or other L3 header.
    UINT32 l4Ofs;             // TCP, UDP, ICMP, ICMPv6, or other L4 header.
    UINT32 l7Ofs;             // L4 protocol's payload.
} OvsLayers;

extern UINT64 ovsUserTimestampDelta;
extern UINT64 ovsTimeIncrementPerTick;

NDIS_STATUS OvsDeleteFlowTable(OVS_DATAPATH *datapath);
NDIS_STATUS OvsAllocateFlowTable(OVS_DATAPATH *datapath,
                                 POVS_SWITCH_CONTEXT switchContext);

NDIS_STATUS OvsExtractFlow(const NET_BUFFER_LIST *pkt, UINT32 inPort,
                           OvsFlowKey *flow, POVS_PACKET_HDR_INFO layers,
                           OvsIPv4TunnelKey *tunKey);
OvsFlow *OvsLookupFlow(OVS_DATAPATH *datapath, const OvsFlowKey *key,
                       UINT64 *hash, BOOLEAN hashValid);
UINT64 OvsHashFlow(const OvsFlowKey *key);
VOID OvsFlowUsed(OvsFlow *flow, const NET_BUFFER_LIST *pkt,
                 const POVS_PACKET_HDR_INFO layers);

NTSTATUS OvsDumpFlowIoctl(PVOID inputBuffer, UINT32 inputLength,
                          PVOID outputBuffer, UINT32 outputLength,
                          UINT32 *replyLen);
NTSTATUS OvsPutFlowIoctl(PVOID inputBuffer, UINT32 inputLength,
                         PVOID outputBuffer, UINT32 outputLength,
                         UINT32 *replyLen);
NTSTATUS OvsGetFlowIoctl(PVOID inputBuffer, UINT32 inputLength,
                         PVOID outputBuffer, UINT32 outputLength,
                         UINT32 *replyLen);
NTSTATUS OvsFlushFlowIoctl(PVOID inputBuffer, UINT32 inputLength);

/* Flags for tunneling */
#define OVS_TNL_F_DONT_FRAGMENT         (1 << 0)
#define OVS_TNL_F_CSUM                  (1 << 1)
#define OVS_TNL_F_KEY                   (1 << 2)

#endif /* __OVS_FLOW_H_ */
