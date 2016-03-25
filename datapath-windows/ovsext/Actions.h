/*
 * Copyright (c) 2016 Cloudbase Solutions Srl
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

#ifndef __ACTIONS_H_
#define __ACTIONS_H_ 1

#include "Switch.h"
#include "PacketIO.h"

NDIS_STATUS
OvsActionsExecute(POVS_SWITCH_CONTEXT switchContext,
                  OvsCompletionList *completionList,
                  PNET_BUFFER_LIST curNbl,
                  UINT32 srcVportNo,
                  ULONG sendFlags,
                  OvsFlowKey *key,
                  UINT64 *hash,
                  OVS_PACKET_HDR_INFO *layers,
                  const PNL_ATTR actions,
                  int actionsLen);

NDIS_STATUS
OvsDoExecuteActions(POVS_SWITCH_CONTEXT switchContext,
                    OvsCompletionList *completionList,
                    PNET_BUFFER_LIST curNbl,
                    UINT32 srcVportNo,
                    ULONG sendFlags,
                    OvsFlowKey *key,
                    UINT64 *hash,
                    OVS_PACKET_HDR_INFO *layers,
                    const PNL_ATTR actions,
                    int actionsLen);

NDIS_STATUS
OvsDoRecirc(POVS_SWITCH_CONTEXT switchContext,
            OvsCompletionList *completionList,
            PNET_BUFFER_LIST curNbl,
            OvsFlowKey *key,
            UINT32 srcPortNo,
            OVS_PACKET_HDR_INFO *layers);

#endif /* __ACTIONS_H_ */
