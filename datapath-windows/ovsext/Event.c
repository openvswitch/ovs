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

#include "Datapath.h"
#include "Vport.h"
#include "Event.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_EVENT
#include "Debug.h"

LIST_ENTRY ovsEventQueueArr[OVS_MCAST_EVENT_TYPES_MAX];
static NDIS_SPIN_LOCK eventQueueLockArr[OVS_MCAST_EVENT_TYPES_MAX];
UINT32 ovsNumEventQueueArr[OVS_MCAST_EVENT_TYPES_MAX];
DRIVER_CANCEL OvsCancelIrp;

NTSTATUS
OvsInitEventQueue()
{
    for (int i = 0; i < OVS_MCAST_EVENT_TYPES_MAX; i++) {
        InitializeListHead(&ovsEventQueueArr[i]);
        NdisAllocateSpinLock(&eventQueueLockArr[i]);
    }
    return STATUS_SUCCESS;
}

VOID
OvsCleanupEventQueue()
{
    for (int i = 0; i < OVS_MCAST_EVENT_TYPES_MAX; i++) {
        ASSERT(IsListEmpty(&ovsEventQueueArr[i]));
        ASSERT(ovsNumEventQueueArr[i] == 0);
        NdisFreeSpinLock(&eventQueueLockArr[i]);
    }
}

_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_saves_global_(OldIrql, eventQueueLockArr[eventId])
_Acquires_lock_(eventQueueLockArr[eventId])
static __inline VOID
OvsAcquireEventQueueLock(int eventId)
{
    NdisAcquireSpinLock(&eventQueueLockArr[eventId]);
}

_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_restores_global_(OldIrql, eventQueueLockArr[eventId])
_Requires_lock_held_(eventQueueLockArr[eventId])
_Releases_lock_(eventQueueLockArr[eventId])
static __inline VOID
OvsReleaseEventQueueLock(int eventId)
{
   NdisReleaseSpinLock(&eventQueueLockArr[eventId]);
}

NDIS_STATUS
OvsGetMcastEventId(UINT32 protocol, UINT32 mcastMask, UINT32 *eventId)
{
    switch (protocol) {
    case NETLINK_GENERIC:
        *eventId = OVS_MCAST_VPORT_EVENT;
        return NDIS_STATUS_SUCCESS;
    case NETLINK_NETFILTER:
        if ((mcastMask & OVS_EVENT_CT_NEW)
            || (mcastMask & OVS_EVENT_CT_DELETE)
            || (mcastMask & OVS_EVENT_CT_UPDATE)) {
            *eventId =  OVS_MCAST_CT_EVENT;
            return NDIS_STATUS_SUCCESS;
        }
        break;
    default:
        goto error;
    }

error:
    return NDIS_STATUS_INVALID_PARAMETER;
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
    UINT32 eventId;
    queue = (POVS_EVENT_QUEUE)instance->eventQueue;
    if (queue) {
        POVS_EVENT_QUEUE_ELEM elem;
        PLIST_ENTRY link, next;

        /* Handle the error */
        OvsGetMcastEventId(instance->protocol, instance->mcastMask, &eventId);
        OvsAcquireEventQueueLock(eventId);
        RemoveEntryList(&queue->queueLink);
        ovsNumEventQueueArr[eventId]--;
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
        OvsReleaseEventQueueLock(eventId);
        if (irp) {
            OvsCompleteIrpRequest(irp, 0, STATUS_SUCCESS);
        }

        LIST_FORALL_SAFE(&queue->elemList, link, next) {
            elem = CONTAINING_RECORD(link, OVS_EVENT_QUEUE_ELEM, link);
            OvsFreeMemoryWithTag(elem, OVS_EVENT_POOL_TAG);
        }
        OvsFreeMemoryWithTag(queue, OVS_EVENT_POOL_TAG);
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
OvsPostVportEvent(POVS_VPORT_EVENT_ENTRY event)
{
    POVS_EVENT_QUEUE_ELEM elem;
    POVS_EVENT_QUEUE queue;
    PLIST_ENTRY link;
    LIST_ENTRY list;
    PLIST_ENTRY entry;
    PIRP irp;

    InitializeListHead(&list);

    OVS_LOG_TRACE("Enter: portNo: %#x, status: %#x", event->portNo,
                  event->type);

    OvsAcquireEventQueueLock(OVS_MCAST_VPORT_EVENT);

    LIST_FORALL(&ovsEventQueueArr[OVS_MCAST_VPORT_EVENT], link) {
        queue = CONTAINING_RECORD(link, OVS_EVENT_QUEUE, queueLink);
        if ((event->type & queue->mask) == 0) {
            continue;
        }
        event->type &= queue->mask;

        elem = (POVS_EVENT_QUEUE_ELEM)OvsAllocateMemoryWithTag(
            sizeof(*elem), OVS_EVENT_POOL_TAG);

        if (elem == NULL) {
            OVS_LOG_WARN("Fail to allocate memory for event");
            OvsReleaseEventQueueLock(OVS_MCAST_VPORT_EVENT);
            return;
        }

        RtlCopyMemory(&elem->vportEvent, event, sizeof elem->vportEvent);
        InsertTailList(&queue->elemList, &elem->link);
        queue->numElems++;
        OVS_LOG_INFO("Queue: %p, numElems: %d",
                        queue, queue->numElems);

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
    OvsReleaseEventQueueLock(OVS_MCAST_VPORT_EVENT);
    while (!IsListEmpty(&list)) {
        entry = RemoveHeadList(&list);
        irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        OVS_LOG_INFO("Wakeup thread with IRP: %p", irp);
        OvsCompleteIrpRequest(irp, 0, STATUS_SUCCESS);
    }
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
    UINT32 eventId;

    OVS_LOG_TRACE("Enter: fileObject: %p, inputLength: %d", fileObject,
                  inputLength);

    if (request->protocol == NETLINK_GENERIC) {
        if (inputLength < sizeof (OVS_EVENT_SUBSCRIBE) ||
            (request->mask & OVS_EVENT_MASK_ALL) == 0) {
            OVS_LOG_TRACE("Exit: subscribe failed with invalid request.");
            return STATUS_INVALID_PARAMETER;
        }
    }

    status = OvsGetMcastEventId(request->protocol, request->mask, &eventId);
    if (status != NDIS_STATUS_SUCCESS) {
        return STATUS_INVALID_PARAMETER;
    }

    OvsAcquireEventQueueLock(eventId);

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
        if (request->protocol == NETLINK_GENERIC
            && queue->mask != request->mask) {
            status = STATUS_INVALID_PARAMETER;
            OVS_LOG_WARN("Can not change mask when the queue is subscribed");
            goto done_event_subscribe;
        }
        if (request->protocol == NETLINK_NETFILTER) {
            if (queue->mask == request->mask) {
                /* Resubscribing to subscribed event */
                status = STATUS_SUCCESS;
                goto done_event_subscribe;
            } else {
                /* Update the instance and queue mask to reflect this */
                queue->mask |= request->mask;
                instance->mcastMask |= request->mask;
            }
            status = STATUS_SUCCESS;
            goto done_event_subscribe;
        }
    } else if (!request->subscribe && queue == NULL) {
        status = STATUS_SUCCESS;
        goto done_event_subscribe;
    }

    if (request->subscribe) {
        queue = (POVS_EVENT_QUEUE)OvsAllocateMemoryWithTag(
            sizeof(OVS_EVENT_QUEUE), OVS_EVENT_POOL_TAG);
        if (queue == NULL) {
            status = STATUS_NO_MEMORY;
            OVS_LOG_WARN("Fail to allocate event queue");
            goto done_event_subscribe;
        }
        InitializeListHead(&queue->elemList);
        queue->mask = request->mask;
        queue->mcastEventId = eventId;
        queue->pendingIrp = NULL;
        queue->numElems = 0;
        InsertHeadList(&ovsEventQueueArr[eventId], &queue->queueLink);
        ovsNumEventQueueArr[eventId]++;
        instance->eventQueue = queue;
        instance->mcastMask = request->mask;
        queue->instance = instance;
    } else {
        queue = (POVS_EVENT_QUEUE)instance->eventQueue;
        queue->mask &= ~(request->mask);
        instance->mcastMask &= ~(request->mask);
        if (!queue->mask) {
            /* No other mcast group exists */
            RemoveEntryList(&queue->queueLink);
            ovsNumEventQueueArr[eventId]--;
            instance->eventQueue = NULL;
            instance->mcastMask = 0;
        }
    }
done_event_subscribe:
    if (!request->subscribe && queue && !queue->mask) {
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
        OvsReleaseEventQueueLock(eventId);
        if (irp) {
            OvsCompleteIrpRequest(queue->pendingIrp, 0, STATUS_SUCCESS);
        }
        LIST_FORALL_SAFE(&queue->elemList, link, next) {
            elem = CONTAINING_RECORD(link, OVS_EVENT_QUEUE_ELEM, link);
            OvsFreeMemoryWithTag(elem, OVS_EVENT_POOL_TAG);
        }
        OvsFreeMemoryWithTag(queue, OVS_EVENT_POOL_TAG);
    } else {
        OvsReleaseEventQueueLock(eventId);
    }
    OVS_LOG_TRACE("Exit: subscribe event with status: %#x.", status);
    return status;
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
    UINT32 eventId;
    NDIS_STATUS status;

    UNREFERENCED_PARAMETER(deviceObject);

    IoReleaseCancelSpinLock(irp->CancelIrql);

    irpSp = IoGetCurrentIrpStackLocation(irp);
    fileObject = irpSp->FileObject;

    if (fileObject == NULL) {
        goto done;
    }

    instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    if (instance == NULL) {
        goto done;
    }

    status = OvsGetMcastEventId(instance->protocol,
                                instance->mcastMask,
                                &eventId);
    if (status != NDIS_STATUS_SUCCESS) {
        goto done;
    }

    OvsAcquireEventQueueLock(eventId);
    if (instance->eventQueue == NULL) {
        OvsReleaseEventQueueLock(eventId);
        goto done;
    }

    queue = instance->eventQueue;
    if (queue->pendingIrp == irp) {
        queue->pendingIrp = NULL;
    }
    OvsReleaseEventQueueLock(eventId);
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
    NTSTATUS status = STATUS_SUCCESS;
    POVS_EVENT_POLL poll;
    POVS_EVENT_QUEUE queue;
    POVS_OPEN_INSTANCE instance;
    BOOLEAN cancelled = FALSE;
    PDRIVER_CANCEL cancelRoutine;
    UINT32 eventId;

    OVS_LOG_TRACE("Enter: inputLength: %u", inputLength);

    if (inputLength < sizeof (OVS_EVENT_POLL)) {
        OVS_LOG_TRACE("Exit: Invalid input buffer length.");
        return STATUS_INVALID_PARAMETER;
    }
    poll = (POVS_EVENT_POLL)inputBuffer;

    instance = OvsGetOpenInstance(fileObject, poll->dpNo);
    if (instance == NULL) {
        OVS_LOG_TRACE("Exit: Can not find open instance, dpNo: %d",
                      poll->dpNo);
        return STATUS_INVALID_PARAMETER;
    }

    status = OvsGetMcastEventId(instance->protocol,
                                instance->mcastMask,
                                &eventId);
    if (status != NDIS_STATUS_SUCCESS) {
        return STATUS_INVALID_PARAMETER;
    }
    OvsAcquireEventQueueLock(eventId);

    queue = (POVS_EVENT_QUEUE)instance->eventQueue;
    if (queue == NULL) {
        OVS_LOG_TRACE("Exit: Event queue does not exist");
        status = STATUS_INVALID_PARAMETER;
        goto unlock;
    }
    if (queue->pendingIrp) {
        OVS_LOG_TRACE("Exit: Event queue already in pending state");
        status = STATUS_DEVICE_BUSY;
        goto unlock;
    }

    IoMarkIrpPending(irp);
    IoSetCancelRoutine(irp, OvsCancelIrp);
    if (irp->Cancel) {
        cancelRoutine = IoSetCancelRoutine(irp, NULL);
        if (cancelRoutine) {
            cancelled = TRUE;
        }
    } else {
        queue->pendingIrp = irp;
        status = STATUS_PENDING;
    }

unlock:
    OvsReleaseEventQueueLock(eventId);
    if (cancelled) {
        OvsCompleteIrpRequest(irp, 0, STATUS_CANCELLED);
        OVS_LOG_INFO("Event IRP cancelled: %p", irp);
    }
    OVS_LOG_TRACE("Exit: return status: %#x", status);
    return status;
}

/*
 *--------------------------------------------------------------------------
 * Poll event queued in the event queue.always synchronous.
 *
 * Results:
 *     STATUS_SUCCESS event was dequeued
 *     STATUS_UNSUCCESSFUL the queue is empty.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsRemoveVportEventEntry(POVS_OPEN_INSTANCE instance,
                         POVS_VPORT_EVENT_ENTRY entry)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    POVS_EVENT_QUEUE queue;
    POVS_EVENT_QUEUE_ELEM elem;

    OvsAcquireEventQueueLock(OVS_MCAST_VPORT_EVENT);

    queue = (POVS_EVENT_QUEUE)instance->eventQueue;

    if (queue == NULL) {
        ASSERT(queue);
        goto remove_event_done;
    }

    if (queue->numElems) {
        elem = (POVS_EVENT_QUEUE_ELEM)RemoveHeadList(&queue->elemList);
        *entry = elem->vportEvent;
        OvsFreeMemoryWithTag(elem, OVS_EVENT_POOL_TAG);
        queue->numElems--;
        status = STATUS_SUCCESS;
    }

remove_event_done:
    OvsReleaseEventQueueLock(OVS_MCAST_VPORT_EVENT);
    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsPostCtEvent - used to post a Conntrack related event
 *
 * Side effects: User thread may be woken up.
 * XXX - Try to consolidate PostEvent for Vport/Ct events
 * --------------------------------------------------------------------------
 */
VOID
OvsPostCtEvent(POVS_CT_EVENT_ENTRY ctEvent)
{
    POVS_EVENT_QUEUE_ELEM elem;
    POVS_EVENT_QUEUE queue;
    PLIST_ENTRY link;
    LIST_ENTRY list;
    PLIST_ENTRY entry;
    PIRP irp;

    InitializeListHead(&list);

    OvsAcquireEventQueueLock(OVS_MCAST_CT_EVENT);

    LIST_FORALL(&ovsEventQueueArr[OVS_MCAST_CT_EVENT], link) {
        queue = CONTAINING_RECORD(link, OVS_EVENT_QUEUE, queueLink);
        if ((ctEvent->type & queue->mask) == 0) {
            continue;
        }
        ctEvent->type &= queue->mask;

        elem = (POVS_EVENT_QUEUE_ELEM)OvsAllocateMemoryWithTag(
            sizeof(*elem), OVS_EVENT_POOL_TAG);

        if (elem == NULL) {
            OvsReleaseEventQueueLock(OVS_MCAST_CT_EVENT);
            return;
        }

        RtlCopyMemory(&elem->ctEvent, ctEvent, sizeof elem->ctEvent);
        InsertTailList(&queue->elemList, &elem->link);
        queue->numElems++;

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

    OvsReleaseEventQueueLock(OVS_MCAST_CT_EVENT);
    while (!IsListEmpty(&list)) {
        entry = RemoveHeadList(&list);
        irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        OvsCompleteIrpRequest(irp, 0, STATUS_SUCCESS);
    }
}

/*
 *--------------------------------------------------------------------------
 * Poll event queued in the event queue.always synchronous.
 *
 * Results:
 *     STATUS_SUCCESS event was dequeued
 *     STATUS_UNSUCCESSFUL the queue is empty.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsRemoveCtEventEntry(POVS_OPEN_INSTANCE instance,
                      POVS_CT_EVENT_ENTRY entry)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    POVS_EVENT_QUEUE queue;
    POVS_EVENT_QUEUE_ELEM elem;

    OvsAcquireEventQueueLock(OVS_MCAST_CT_EVENT);

    queue = (POVS_EVENT_QUEUE)instance->eventQueue;

    if (queue == NULL) {
        ASSERT(queue);
        goto remove_event_done;
    }

    if (queue->numElems) {
        elem = (POVS_EVENT_QUEUE_ELEM)RemoveHeadList(&queue->elemList);
        *entry = elem->ctEvent;
        OvsFreeMemoryWithTag(elem, OVS_EVENT_POOL_TAG);
        queue->numElems--;
        status = STATUS_SUCCESS;
    }

remove_event_done:
    OvsReleaseEventQueueLock(OVS_MCAST_CT_EVENT);
    return status;
}
