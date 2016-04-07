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

#ifndef __RECIRC_H_
#define __RECIRC_H_ 1

#include "Actions.h"

#define DEFERRED_ACTION_QUEUE_SIZE          10
#define DEFERRED_ACTION_EXEC_LEVEL           4

typedef struct _OVS_DEFERRED_ACTION {
    PNET_BUFFER_LIST    nbl;
    PNL_ATTR            actions;
    OvsFlowKey          key;
} OVS_DEFERRED_ACTION, *POVS_DEFERRED_ACTION;

/*
 * --------------------------------------------------------------------------
 * OvsProcessDeferredActions --
 *     This function processes all deferred actions contained in the queue
 *     corresponding to the current CPU.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsProcessDeferredActions(POVS_SWITCH_CONTEXT switchContext,
                          OvsCompletionList *completionList,
                          UINT32 portNo,
                          ULONG sendFlags,
                          OVS_PACKET_HDR_INFO *layers);

/*
 * --------------------------------------------------------------------------
 * OvsAddDeferredActions --
 *     This function adds the deferred action to the current CPU queue and
 *     returns the new queue entry if the queue is not already full.
 * --------------------------------------------------------------------------
 */
POVS_DEFERRED_ACTION
OvsAddDeferredActions(PNET_BUFFER_LIST packet,
                      OvsFlowKey *key,
                      const PNL_ATTR actions);

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsInit --
 *     The function allocates all necessary deferred actions resources.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsDeferredActionsInit();

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsCleanup --
 *     The function frees all deferred actions resources.
 * --------------------------------------------------------------------------
 */
VOID
OvsDeferredActionsCleanup();

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsLevelGet --
 *     The function returns the deferred action execution level corresponding
 *     to the current processor.
 * --------------------------------------------------------------------------
 */
UINT32
OvsDeferredActionsLevelGet();

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsLevelInc --
 *     The function increments the deferred action execution level
 *     corresponding to the current processor.
 * --------------------------------------------------------------------------
 */
VOID
OvsDeferredActionsLevelInc();

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsLevelDec --
 *     The function decrements the deferred action execution level
 *     corresponding to the current processor.
 * --------------------------------------------------------------------------
*/
VOID
OvsDeferredActionsLevelDec();

#endif /* __RECIRC_H_ */
