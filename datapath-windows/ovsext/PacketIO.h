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

#ifndef __PACKETIO_H_
#define __PACKETIO_H_ 1

typedef union _OVS_PACKET_HDR_INFO OVS_PACKET_HDR_INFO;

/*
 * Data structures and utility functions to help manage a list of packets to be
 * completed (dropped).
 */
typedef struct OvsCompletionList {
    PNET_BUFFER_LIST dropNbl;
    PNET_BUFFER_LIST *dropNblNext;
    POVS_SWITCH_CONTEXT switchContext;
    ULONG sendCompleteFlags;
} OvsCompletionList;

VOID OvsInitCompletionList(OvsCompletionList *completionList,
                           POVS_SWITCH_CONTEXT switchContext,
                           ULONG sendCompleteFlags);
VOID OvsAddPktCompletionList(OvsCompletionList *completionList,
                             BOOLEAN incoming,
                             NDIS_SWITCH_PORT_ID sourcePort,
                             PNET_BUFFER_LIST netBufferList,
                             UINT32 netBufferListCount,
                             PNDIS_STRING filterReason);


/*
 * Functions related to packet processing.
 */
VOID OvsSendNBLIngress(POVS_SWITCH_CONTEXT switchContext,
                       PNET_BUFFER_LIST netBufferLists,
                       ULONG sendFlags);

NDIS_STATUS OvsActionsExecute(POVS_SWITCH_CONTEXT switchContext,
                            OvsCompletionList *completionList,
                            PNET_BUFFER_LIST curNbl, UINT32 srcVportNo,
                            ULONG sendFlags, OvsFlowKey *key, UINT64 *hash,
                            OVS_PACKET_HDR_INFO *layers,
                            const PNL_ATTR actions, int actionsLen);

VOID OvsLookupFlowOutput(POVS_SWITCH_CONTEXT switchContext,
                         VOID *compList, PNET_BUFFER_LIST curNbl);

#endif /* __PACKETIO_H_ */
