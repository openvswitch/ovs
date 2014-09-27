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

#ifndef __EVENT_H_
#define __EVENT_H_ 1

typedef struct _OVS_EVENT_QUEUE_ELEM {
    LIST_ENTRY link;
    UINT32 portNo;
    UINT32 status;
} OVS_EVENT_QUEUE_ELEM, *POVS_EVENT_QUEUE_ELEM;

typedef struct _OVS_EVENT_QUEUE {
    LIST_ENTRY queueLink;
    LIST_ENTRY elemList;
    UINT32 mask;
    UINT16 numElems;
    BOOLEAN pollAll;
    PIRP pendingIrp;
    PVOID instance;
} OVS_EVENT_QUEUE, *POVS_EVENT_QUEUE;

NTSTATUS OvsInitEventQueue(VOID);
VOID OvsCleanupEventQueue(VOID);

struct _OVS_OPEN_INSTANCE;

VOID OvsCleanupEvent(struct _OVS_OPEN_INSTANCE *instance);
VOID OvsPostEvent(UINT32 portNo, UINT32 status);
NTSTATUS OvsSubscribeEventIoctl(PFILE_OBJECT fileObject, PVOID inputBuffer,
                                UINT32 inputLength);
NTSTATUS OvsPollEventIoctl(PFILE_OBJECT fileObject, PVOID inputBuffer,
                           UINT32 inputLength, PVOID outputBuffer,
                           UINT32 outputLength, UINT32 *replyLen);
NTSTATUS OvsWaitEventIoctl(PIRP irp, PFILE_OBJECT fileObject,
                           PVOID inputBuffer, UINT32 inputLength);
NTSTATUS OvsRemoveEventEntry(PVOID instance, POVS_EVENT_ENTRY entry);

#endif /* __EVENT_H_ */
