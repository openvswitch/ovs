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

#include "precomp.h"

#include "OvsIoctl.h"
#include "OvsSwitch.h"
#include "OvsVport.h"
#include "OvsEvent.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_EVENT
#include "OvsDebug.h"

LIST_ENTRY ovsEventQueue;
UINT32 ovsNumEventQueue;
UINT32 ovsNumPollAll;

extern PNDIS_SPIN_LOCK gOvsCtrlLock;

NTSTATUS
OvsInitEventQueue()
{
    InitializeListHead(&ovsEventQueue);
    return STATUS_SUCCESS;
}

VOID
OvsCleanupEventQueue()
{
    ASSERT(IsListEmpty(&ovsEventQueue));
    ASSERT(ovsNumEventQueue == 0);
}

static __inline VOID
OvsAcquireEventQueueLock()
{
    NdisAcquireSpinLock(gOvsCtrlLock);
}

static __inline VOID
OvsReleaseEventQueueLock()
{
   NdisReleaseSpinLock(gOvsCtrlLock);
}

/*
 * --------------------------------------------------------------------------
 * Cleanup the event queue of the OpenInstance.
 * --------------------------------------------------------------------------
 */
VOID
OvsCleanupEvent(POVS_OPEN_INSTANCE instance)
{
    POVS_EVENT_QUEUE queue;
    PIRP irp = NULL;
    queue = (POVS_EVENT_QUEUE)instance->eventQueue;
    if (queue) {
        POVS_EVENT_QUEUE_ELEM elem;
        PLIST_ENTRY link, next;

        OvsAcquireEventQueueLock();
        RemoveEntryList(&queue->queueLink);
        ovsNumEventQueue--;
        if (queue->pendingIrp) {
            PDRIVER_CANCEL cancelRoutine;
            irp = queue->pendingIrp;
            cancelRoutine = IoSetCancelRoutine(irp, NULL);
            queue->pendingIrp = NULL;
            if (cancelRoutine == NULL) {
                irp = NULL;
            }
        }
        instance->eventQueue = NULL;
        OvsReleaseEventQueueLock();
        if (irp) {
            OvsCompleteIrpRequest(irp, 0, STATUS_SUCCESS);
        }

        LIST_FORALL_SAFE(&queue->elemList, link, next) {
            elem = CONTAINING_RECORD(link, OVS_EVENT_QUEUE_ELEM, link);
            OvsFreeMemory(elem);
        }
        OvsFreeMemory(queue);
    }
}

/*
 * --------------------------------------------------------------------------
 * When event is generated, we need to post the event to all
 * the event queues. If there is pending Irp waiting for event
 * complete the Irp to wakeup the user thread.
 *
 * Side effects: User thread may be woken up.
 * --------------------------------------------------------------------------
 */
VOID
OvsPostEvent(UINT32 portNo,
             UINT32 status)
{
    POVS_EVENT_QUEUE_ELEM elem;
    POVS_EVENT_QUEUE queue;
    PLIST_ENTRY link;
    BOOLEAN triggerPollAll = FALSE;
    LIST_ENTRY list;
    PLIST_ENTRY entry;
    PIRP irp;

    InitializeListHead(&list);

    OVS_LOG_TRACE("Enter: portNo: %#x, status: %#x", portNo, status);

    OvsAcquireEventQueueLock();

    LIST_FORALL(&ovsEventQueue, link) {
        queue = CONTAINING_RECORD(link, OVS_EVENT_QUEUE, queueLink);
        if ((status & queue->mask) == 0 ||
            queue->pollAll) {
            continue;
        }
        if (queue->numElems > (OVS_MAX_VPORT_ARRAY_SIZE >> 1) ||
            portNo == OVS_DEFAULT_PORT_NO) {
            queue->pollAll = TRUE;
        } else {
            elem = (POVS_EVENT_QUEUE_ELEM)OvsAllocateMemory(sizeof(*elem));
            if (elem == NULL) {
                queue->pollAll = TRUE;
            } else {
                elem->portNo = portNo;
                elem->status = (status & queue->mask);
                InsertTailList(&queue->elemList, &elem->link);
                queue->numElems++;
                OVS_LOG_INFO("Queue: %p, numElems: %d",
                             queue, queue->numElems);
            }
        }
        if (queue->pollAll) {
            PLIST_ENTRY curr, next;
            triggerPollAll = TRUE;
            ovsNumPollAll++;
            LIST_FORALL_SAFE(&queue->elemList, curr, next) {
                RemoveEntryList(curr);
                elem = CONTAINING_RECORD(curr, OVS_EVENT_QUEUE_ELEM, link);
                OvsFreeMemory(elem);
            }
            queue->numElems = 0;
        }
        if (queue->pendingIrp != NULL) {
            PDRIVER_CANCEL cancelRoutine;
            irp = queue->pendingIrp;
            queue->pendingIrp = NULL;
            cancelRoutine = IoSetCancelRoutine(irp, NULL);
            if (cancelRoutine) {
                InsertTailList(&list, &irp->Tail.Overlay.ListEntry);
            }
        }
    }
    OvsReleaseEventQueueLock();
    while (!IsListEmpty(&list)) {
        entry = RemoveHeadList(&list);
        irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        OVS_LOG_INFO("Wakeup thread with IRP: %p", irp);
        OvsCompleteIrpRequest(irp, 0, STATUS_SUCCESS);
    }
    OVS_LOG_TRACE("Exit: triggered pollAll: %s",
                  (triggerPollAll ? "TRUE" : "FALSE"));
}


/*
 * --------------------------------------------------------------------------
 * Subscribe for event notification.
 *
 * Results:
 *     STATUS_SUCCESS for valid request and enough resource.
 *     STATUS_NO_RESOURCES for queue allocation failure
 *     STATUS_INVALID_PARAMETER for invalid request
 *
 * Side effects:
 *     Event queue is created for the current open instance.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsSubscribeEventIoctl(PFILE_OBJECT fileObject,
                       PVOID inputBuffer,
                       UINT32 inputLength)
{
    POVS_EVENT_SUBSCRIBE request = (POVS_EVENT_SUBSCRIBE)inputBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    POVS_OPEN_INSTANCE instance;
    POVS_EVENT_QUEUE queue = NULL;

    OVS_LOG_TRACE("Enter: fileObject: %p, inputLength: %d", fileObject,
                  inputLength);

    if (inputLength < sizeof (OVS_EVENT_SUBSCRIBE) ||
        (request->mask & OVS_EVENT_MASK_ALL) == 0) {
        OVS_LOG_TRACE("Exit: subscribe failed with invalid request.");
        return STATUS_INVALID_PARAMETER;
    }

    OvsAcquireEventQueueLock();

    instance = OvsGetOpenInstance(fileObject, request->dpNo);

    if (instance == NULL) {
        status = STATUS_INVALID_PARAMETER;
        OVS_LOG_WARN("can not find open instance");
        goto done_event_subscribe;
    }

    /*
     * XXX for now, we don't allow change mask.
     */
    queue = (POVS_EVENT_QUEUE)instance->eventQueue;
    if (request->subscribe && queue) {
        if (queue->mask != request->mask) {
            status = STATUS_INVALID_PARAMETER;
            OVS_LOG_WARN("Can not chnage mask when the queue is subscribed");
        }
        status = STATUS_SUCCESS;
        goto done_event_subscribe;
    } else if (!request->subscribe && queue == NULL) {
        status = STATUS_SUCCESS;
        goto done_event_subscribe;
    }

    if (request->subscribe) {
        queue = (POVS_EVENT_QUEUE)OvsAllocateMemory(sizeof (OVS_EVENT_QUEUE));
        if (queue == NULL) {
            status = STATUS_NO_MEMORY;
            OVS_LOG_WARN("Fail to allocate event queue");
            goto done_event_subscribe;
        }
        InitializeListHead(&queue->elemList);
        queue->mask = request->mask;
        queue->pendingIrp = NULL;
        queue->numElems = 0;
        queue->pollAll = TRUE; /* always poll all in the begining */
        InsertHeadList(&ovsEventQueue, &queue->queueLink);
        ovsNumEventQueue++;
        instance->eventQueue = queue;
        queue->instance = instance;
    } else {
        queue = (POVS_EVENT_QUEUE)instance->eventQueue;
        RemoveEntryList(&queue->queueLink);
        ovsNumEventQueue--;
        instance->eventQueue = NULL;
    }
done_event_subscribe:
    if (!request->subscribe && queue) {
        POVS_EVENT_QUEUE_ELEM elem;
        PLIST_ENTRY link, next;
        PIRP irp = NULL;
        if (queue->pendingIrp) {
            PDRIVER_CANCEL cancelRoutine;
            irp = queue->pendingIrp;
            queue->pendingIrp = NULL;
            cancelRoutine = IoSetCancelRoutine(irp, NULL);
            if (cancelRoutine == NULL) {
                irp = NULL;
            }
        }
        OvsReleaseEventQueueLock();
        if (irp) {
            OvsCompleteIrpRequest(queue->pendingIrp, 0, STATUS_SUCCESS);
        }
        LIST_FORALL_SAFE(&queue->elemList, link, next) {
            elem = CONTAINING_RECORD(link, OVS_EVENT_QUEUE_ELEM, link);
            OvsFreeMemory(elem);
        }
        OvsFreeMemory(queue);
    } else {
        OvsReleaseEventQueueLock();
    }
    OVS_LOG_TRACE("Exit: subscribe event with status: %#x.", status);
    return status;
}

/*
 * --------------------------------------------------------------------------
 * Poll event queued in the event queue. always synchronous.
 *
 * Results:
 *     STATUS_SUCCESS for valid request
 *     STATUS_BUFFER_TOO_SMALL if outputBuffer is too small.
 *     STATUS_INVALID_PARAMETER for invalid request
 *
 * Side effects:
 *     Event  will be removed from event queue.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsPollEventIoctl(PFILE_OBJECT fileObject,
                  PVOID inputBuffer,
                  UINT32 inputLength,
                  PVOID outputBuffer,
                  UINT32 outputLength,
                  UINT32 *replyLen)
{
    POVS_EVENT_POLL poll;
    POVS_EVENT_STATUS eventStatus;
    POVS_EVENT_ENTRY entry;
    POVS_EVENT_QUEUE queue;
    POVS_EVENT_QUEUE_ELEM elem;
    POVS_OPEN_INSTANCE instance;
    UINT32 numEntry, i;

    OVS_LOG_TRACE("Enter: inputLength:%d, outputLength: %d",
                  inputLength, outputLength);

    ASSERT(replyLen);
    if (inputLength < sizeof (OVS_EVENT_POLL)) {
        OVS_LOG_TRACE("Exit: input buffer too small");
        return STATUS_INVALID_PARAMETER;
    }
    *replyLen = sizeof (OVS_EVENT_STATUS) + sizeof (OVS_EVENT_ENTRY);
    if (outputLength < *replyLen) {
        OVS_LOG_TRACE("Exit: output buffer too small");
        return STATUS_BUFFER_TOO_SMALL;
    }
    poll = (POVS_EVENT_POLL)inputBuffer;

    OvsAcquireEventQueueLock();
    instance = OvsGetOpenInstance(fileObject, poll->dpNo);
    if (instance == NULL) {
        OvsReleaseEventQueueLock();
        *replyLen = 0;
        OVS_LOG_TRACE("Exit: can not find Open instance");
        return STATUS_INVALID_PARAMETER;
    }

    eventStatus = (POVS_EVENT_STATUS)outputBuffer;
    numEntry =
        (outputLength - sizeof (OVS_EVENT_STATUS)) / sizeof (OVS_EVENT_ENTRY);
    queue = (POVS_EVENT_QUEUE)instance->eventQueue;
    if (queue->pollAll) {
        eventStatus->numberEntries = 1;
        numEntry = 1;
        entry =  &eventStatus->eventEntries[0];
        entry->portNo = OVS_DEFAULT_PORT_NO;
        entry->status = OVS_DEFAULT_EVENT_STATUS;
        queue->pollAll = FALSE;
        goto event_poll_done;
    }
    numEntry = MIN(numEntry, queue->numElems);
    eventStatus->numberEntries = numEntry;

    for (i = 0; i < numEntry; i++) {
        elem = (POVS_EVENT_QUEUE_ELEM)RemoveHeadList(&queue->elemList);
        entry = &eventStatus->eventEntries[i];
        entry->portNo = elem->portNo;
        entry->status = elem->status;
        OvsFreeMemory(elem);
        queue->numElems--;
    }
event_poll_done:
    OvsReleaseEventQueueLock();
    *replyLen = sizeof (OVS_EVENT_STATUS) +
                        numEntry * sizeof (OVS_EVENT_ENTRY);
    OVS_LOG_TRACE("Exit: numEventPolled: %d", numEntry);
    return STATUS_SUCCESS;
}


/*
 * --------------------------------------------------------------------------
 * Cancel wait IRP for event
 *
 * Please note, when this routine is called, it is always guaranteed that
 * IRP is valid.
 *
 * Side effects: Pending IRP is completed.
 * --------------------------------------------------------------------------
 */
VOID
OvsCancelIrp(PDEVICE_OBJECT deviceObject,
             PIRP irp)
{
    PIO_STACK_LOCATION irpSp;
    PFILE_OBJECT fileObject;
    POVS_EVENT_QUEUE queue;
    POVS_OPEN_INSTANCE instance;

    UNREFERENCED_PARAMETER(deviceObject);

    IoReleaseCancelSpinLock(irp->CancelIrql);

    irpSp = IoGetCurrentIrpStackLocation(irp);
    fileObject = irpSp->FileObject;

    if (fileObject == NULL) {
        goto done;
    }
    OvsAcquireEventQueueLock();
    instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    if (instance == NULL || instance->eventQueue == NULL) {
        OvsReleaseEventQueueLock();
        goto done;
    }
    queue = instance->eventQueue;
    if (queue->pendingIrp == irp) {
        queue->pendingIrp = NULL;
    }
    OvsReleaseEventQueueLock();
done:
    OvsCompleteIrpRequest(irp, 0, STATUS_CANCELLED);
}

/*
 * --------------------------------------------------------------------------
 * Wait for event.
 *
 * Results:
 *     STATUS_SUCCESS for valid request
 *     STATUS_DEVICE_BUSY if already in waiting state.
 *     STATUS_INVALID_PARAMETER for invalid request
 *     STATUS_PENDING wait for event
 *
 * Side effects:
 *     May return pending to IO manager.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsWaitEventIoctl(PIRP irp,
                  PFILE_OBJECT fileObject,
                  PVOID inputBuffer,
                  UINT32 inputLength)
{
    NTSTATUS status;
    POVS_EVENT_POLL poll;
    POVS_EVENT_QUEUE queue;
    POVS_OPEN_INSTANCE instance;
    BOOLEAN cancelled = FALSE;
    OVS_LOG_TRACE("Enter: inputLength: %u", inputLength);

    if (inputLength < sizeof (OVS_EVENT_POLL)) {
        OVS_LOG_TRACE("Exit: Invalid input buffer length.");
        return STATUS_INVALID_PARAMETER;
    }
    poll = (POVS_EVENT_POLL)inputBuffer;

    OvsAcquireEventQueueLock();

    instance = OvsGetOpenInstance(fileObject, poll->dpNo);
    if (instance == NULL) {
        OvsReleaseEventQueueLock();
        OVS_LOG_TRACE("Exit: Can not find open instance, dpNo: %d", poll->dpNo);
        return STATUS_INVALID_PARAMETER;
    }

    queue = (POVS_EVENT_QUEUE)instance->eventQueue;
    if (queue->pendingIrp) {
        OvsReleaseEventQueueLock();
        OVS_LOG_TRACE("Exit: Event queue already in pending state");
        return STATUS_DEVICE_BUSY;
    }

    status = (queue->numElems != 0 || queue->pollAll) ?
                        STATUS_SUCCESS : STATUS_PENDING;
    if (status == STATUS_PENDING) {
        PDRIVER_CANCEL cancelRoutine;
        IoMarkIrpPending(irp);
        IoSetCancelRoutine(irp, OvsCancelIrp);
        if (irp->Cancel) {
            cancelRoutine = IoSetCancelRoutine(irp, NULL);
            if (cancelRoutine) {
                cancelled = TRUE;
            }
        } else {
            queue->pendingIrp = irp;
        }
    }
    OvsReleaseEventQueueLock();
    if (cancelled) {
        OvsCompleteIrpRequest(irp, 0, STATUS_CANCELLED);
        OVS_LOG_INFO("Event IRP cancelled: %p", irp);
    }
    OVS_LOG_TRACE("Exit: return status: %#x", status);
    return status;
}
