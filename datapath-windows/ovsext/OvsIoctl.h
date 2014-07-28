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

#ifndef __OVS_IOCTL_H_
#define __OVS_IOCTL_H_ 1

typedef struct _OVS_DEVICE_EXTENSION {
    INT numberOpenInstance;
} OVS_DEVICE_EXTENSION, *POVS_DEVICE_EXTENSION;


typedef struct _OVS_OPEN_INSTANCE {
    UINT32 cookie;
    PFILE_OBJECT fileObject;
    PVOID eventQueue;
    PVOID packetQueue;
} OVS_OPEN_INSTANCE, *POVS_OPEN_INSTANCE;

NDIS_STATUS OvsCreateDeviceObject(NDIS_HANDLE ovsExtDriverHandle);
VOID OvsDeleteDeviceObject();

POVS_OPEN_INSTANCE OvsGetOpenInstance(PFILE_OBJECT fileObject,
                                      UINT32 dpNo);

NTSTATUS OvsCompleteIrpRequest(PIRP irp, ULONG_PTR infoPtr, NTSTATUS status);

#endif /* __OVS_IOCTL_H_ */
