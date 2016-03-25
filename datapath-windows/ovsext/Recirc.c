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

#include "Recirc.h"
#include "Flow.h"
#include "Jhash.h"

static POVS_DEFERRED_ACTION_QUEUE ovsDeferredActionQueue = NULL;
static UINT32* ovsDeferredActionLevel = NULL;

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsQueueAlloc --
 *     The function allocates per-cpu deferred actions queue.
 * --------------------------------------------------------------------------
 */
BOOLEAN
OvsDeferredActionsQueueAlloc()
{
    ovsDeferredActionQueue =
        OvsAllocateMemoryPerCpu(sizeof(*ovsDeferredActionQueue),
                                OVS_RECIRC_POOL_TAG);
    if (!ovsDeferredActionQueue) {
        return FALSE;
    }
    return TRUE;
}

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsQueueFree --
 *     The function frees per-cpu deferred actions queue.
 * --------------------------------------------------------------------------
 */
VOID
OvsDeferredActionsQueueFree()
{
    OvsFreeMemoryWithTag(ovsDeferredActionQueue,
                         OVS_RECIRC_POOL_TAG);
    ovsDeferredActionQueue = NULL;
}

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsLevelAlloc --
 *     The function allocates per-cpu deferred actions execution level.
 * --------------------------------------------------------------------------
 */
BOOLEAN
OvsDeferredActionsLevelAlloc()
{
    ovsDeferredActionLevel =
        OvsAllocateMemoryPerCpu(sizeof(*ovsDeferredActionLevel),
                                OVS_RECIRC_POOL_TAG);
    if (!ovsDeferredActionLevel) {
        return FALSE;
    }
    return TRUE;
}

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsLevelFree --
 *     The function frees per-cpu deferred actions execution level.
 * --------------------------------------------------------------------------
 */
VOID
OvsDeferredActionsLevelFree()
{
    OvsFreeMemoryWithTag(ovsDeferredActionLevel,
                         OVS_RECIRC_POOL_TAG);
    ovsDeferredActionLevel = NULL;
}

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsQueueGet --
 *     The function returns the deferred action queue corresponding to the
 *     current processor.
 * --------------------------------------------------------------------------
 */
POVS_DEFERRED_ACTION_QUEUE
OvsDeferredActionsQueueGet()
{
    POVS_DEFERRED_ACTION_QUEUE queue = NULL;
    ULONG index = 0;
    KIRQL oldIrql = KeGetCurrentIrql();

    if (oldIrql < DISPATCH_LEVEL) {
        KeRaiseIrqlToDpcLevel();
    }

    index = KeGetCurrentProcessorNumberEx(NULL);
    queue = &ovsDeferredActionQueue[index];

    if (oldIrql < DISPATCH_LEVEL) {
        KeLowerIrql(oldIrql);
    }

    return queue;
}

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsLevelGet --
 *     The function returns the deferred action execution level corresponding
 *     to the current processor.
 * --------------------------------------------------------------------------
 */
UINT32
OvsDeferredActionsLevelGet()
{
    UINT32 *level = NULL;
    ULONG index = 0;
    KIRQL oldIrql = KeGetCurrentIrql();

    if (oldIrql < DISPATCH_LEVEL) {
        KeRaiseIrqlToDpcLevel();
    }

    index = KeGetCurrentProcessorNumberEx(NULL);
    level = &ovsDeferredActionLevel[index];

    if (oldIrql < DISPATCH_LEVEL) {
        KeLowerIrql(oldIrql);
    }

    return *level;
}

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsLevelInc --
 *     The function increments the deferred action execution level
 *     corresponding to the current processor.
 * --------------------------------------------------------------------------
 */
VOID
OvsDeferredActionsLevelInc()
{
    UINT32 *level = NULL;
    ULONG index = 0;
    KIRQL oldIrql = KeGetCurrentIrql();

    if (oldIrql < DISPATCH_LEVEL) {
        KeRaiseIrqlToDpcLevel();
    }

    index = KeGetCurrentProcessorNumberEx(NULL);
    level = &ovsDeferredActionLevel[index];
    (*level)++;

    if (oldIrql < DISPATCH_LEVEL) {
        KeLowerIrql(oldIrql);
    }
}

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsLevelDec --
 *     The function decrements the deferred action execution level
 *     corresponding to the current processor.
 * --------------------------------------------------------------------------
 */
VOID
OvsDeferredActionsLevelDec()
{
    UINT32 *level = NULL;
    ULONG index = 0;
    KIRQL oldIrql = KeGetCurrentIrql();

    if (oldIrql < DISPATCH_LEVEL) {
        KeRaiseIrqlToDpcLevel();
    }

    index = KeGetCurrentProcessorNumberEx(NULL);
    level = &ovsDeferredActionLevel[index];
    (*level)--;

    if (oldIrql < DISPATCH_LEVEL) {
        KeLowerIrql(oldIrql);
    }
}

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsQueueInit --
 *     The function resets the queue to be ready for the next packet.
 * --------------------------------------------------------------------------
 */
static
VOID
OvsDeferredActionsQueueInit(POVS_DEFERRED_ACTION_QUEUE queue)
{
    queue->head = 0;
    queue->tail = 0;
}

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsQueueIsEmpty --
 *     The function verifies if the queue is empty.
 * --------------------------------------------------------------------------
 */
static
BOOLEAN
OvsDeferredActionsQueueIsEmpty(const POVS_DEFERRED_ACTION_QUEUE queue)
{
    return (queue->head == queue->tail);
}

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsQueuePop --
 *     The function pops the next queue element.
 * --------------------------------------------------------------------------
 */
static
POVS_DEFERRED_ACTION
OvsDeferredActionsQueuePop(POVS_DEFERRED_ACTION_QUEUE queue)
{
    POVS_DEFERRED_ACTION deferredAction = NULL;
    KIRQL oldIrql = KeGetCurrentIrql();

    if (oldIrql < DISPATCH_LEVEL) {
        KeRaiseIrqlToDpcLevel();
    }

    if (OvsDeferredActionsQueueIsEmpty(queue)) {
        /* Reset the queue for the next packet. */
        OvsDeferredActionsQueueInit(queue);
    } else {
        deferredAction = &queue->queue[queue->tail++];
    }

    if (oldIrql < DISPATCH_LEVEL) {
        KeLowerIrql(oldIrql);
    }

    return deferredAction;
}

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsQueuePush --
 *     The function pushes the current element in the deferred actions queue.
 * --------------------------------------------------------------------------
 */
static
POVS_DEFERRED_ACTION
OvsDeferredActionsQueuePush(POVS_DEFERRED_ACTION_QUEUE queue)
{
    POVS_DEFERRED_ACTION deferredAction = NULL;
    KIRQL oldIrql = KeGetCurrentIrql();

    if (oldIrql < DISPATCH_LEVEL) {
        KeRaiseIrqlToDpcLevel();
    }

    if (queue->head < DEFERRED_ACTION_QUEUE_SIZE) {
        deferredAction = &queue->queue[queue->head++];
    }

    if (oldIrql < DISPATCH_LEVEL) {
        KeLowerIrql(oldIrql);
    }

    return deferredAction;
}

/*
 * --------------------------------------------------------------------------
 * OvsAddDeferredActions --
 *     This function adds the deferred action to the current CPU queue and
 *     returns the new queue entry if the queue is not already full.
 * --------------------------------------------------------------------------
 */
POVS_DEFERRED_ACTION
OvsAddDeferredActions(PNET_BUFFER_LIST nbl,
                      OvsFlowKey *key,
                      const PNL_ATTR actions)
{
    POVS_DEFERRED_ACTION_QUEUE queue = OvsDeferredActionsQueueGet();
    POVS_DEFERRED_ACTION deferredAction = NULL;

    deferredAction = OvsDeferredActionsQueuePush(queue);
    if (deferredAction) {
        deferredAction->nbl = nbl;
        deferredAction->actions = actions;
        deferredAction->key = *key;
    }

    return deferredAction;
}

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
                          OVS_PACKET_HDR_INFO *layers)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    POVS_DEFERRED_ACTION_QUEUE queue = OvsDeferredActionsQueueGet();
    POVS_DEFERRED_ACTION deferredAction = NULL;

    /* Process all deferred actions. */
    while ((deferredAction = OvsDeferredActionsQueuePop(queue)) != NULL) {
        if (deferredAction->actions) {
            status = OvsDoExecuteActions(switchContext,
                                         completionList,
                                         deferredAction->nbl,
                                         portNo,
                                         sendFlags,
                                         &deferredAction->key, NULL,
                                         layers, deferredAction->actions,
                                         NlAttrGetSize(deferredAction->actions));
        } else {
            status = OvsDoRecirc(switchContext,
                                 completionList,
                                 deferredAction->nbl,
                                 &deferredAction->key,
                                 portNo,
                                 layers);
        }
    }

    return status;
}
