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

/*
 * --------------------------------------------------------------------------
 * '_OVS_DEFERRED_ACTION_QUEUE' structure is responsible for keeping track of
 * all deferred actions. The maximum number of deferred actions should not
 * exceed 'DEFERRED_ACTION_QUEUE_SIZE'.
 * --------------------------------------------------------------------------
 */
typedef struct _OVS_DEFERRED_ACTION_QUEUE {
    UINT32  head;
    UINT32  tail;
    OVS_DEFERRED_ACTION deferredActions[DEFERRED_ACTION_QUEUE_SIZE];
} OVS_DEFERRED_ACTION_QUEUE, *POVS_DEFERRED_ACTION_QUEUE;

typedef struct _OVS_DEFERRED_ACTION_DATA {
    OVS_DEFERRED_ACTION_QUEUE   queue;
    UINT32                      level;
} OVS_DEFERRED_ACTION_DATA, *POVS_DEFERRED_ACTION_DATA;

static POVS_DEFERRED_ACTION_DATA deferredData = NULL;

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsInit --
 *     The function allocates all necessary deferred actions resources.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsDeferredActionsInit()
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG count = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);

    deferredData = OvsAllocateMemoryPerCpu(sizeof(*deferredData),
                                           count,
                                           OVS_RECIRC_POOL_TAG);
    if (!deferredData) {
        status = NDIS_STATUS_RESOURCES;
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsDeferredActionsCleanup --
 *     The function frees all deferred actions resources.
 * --------------------------------------------------------------------------
 */
VOID
OvsDeferredActionsCleanup()
{
    if (deferredData) {
        OvsFreeMemoryWithTag(deferredData, OVS_RECIRC_POOL_TAG);
        deferredData = NULL;
    }
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
    queue = &deferredData[index].queue;

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
    UINT32 level = 0;
    ULONG index = 0;
    KIRQL oldIrql = KeGetCurrentIrql();

    if (oldIrql < DISPATCH_LEVEL) {
        KeRaiseIrqlToDpcLevel();
    }

    index = KeGetCurrentProcessorNumberEx(NULL);
    level = deferredData[index].level;

    if (oldIrql < DISPATCH_LEVEL) {
        KeLowerIrql(oldIrql);
    }

    return level;
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
    ULONG index = 0;
    KIRQL oldIrql = KeGetCurrentIrql();

    if (oldIrql < DISPATCH_LEVEL) {
        KeRaiseIrqlToDpcLevel();
    }

    index = KeGetCurrentProcessorNumberEx(NULL);
    deferredData[index].level++;

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
    ULONG index = 0;
    KIRQL oldIrql = KeGetCurrentIrql();

    if (oldIrql < DISPATCH_LEVEL) {
        KeRaiseIrqlToDpcLevel();
    }

    index = KeGetCurrentProcessorNumberEx(NULL);
    deferredData[index].level--;

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
        deferredAction = &queue->deferredActions[queue->tail++];
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
        deferredAction = &queue->deferredActions[queue->head++];
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
