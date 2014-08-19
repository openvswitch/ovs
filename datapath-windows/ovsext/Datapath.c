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

/*
 * XXX: OVS_USE_NL_INTERFACE is being used to keep the legacy DPIF interface
 * alive while we transition over to the netlink based interface.
 * OVS_USE_NL_INTERFACE = 0 => legacy inteface to use with dpif-windows.c
 * OVS_USE_NL_INTERFACE = 1 => netlink inteface to use with ported dpif-linux.c
 */
#if defined OVS_USE_NL_INTERFACE && OVS_USE_NL_INTERFACE == 1

#include "precomp.h"
#include "OvsDatapath.h"
#include "OvsJhash.h"
#include "OvsSwitch.h"
#include "OvsVport.h"
#include "OvsEvent.h"
#include "OvsUser.h"
#include "OvsPacketIO.h"
#include "OvsNetProto.h"
#include "OvsFlow.h"
#include "OvsUser.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_DATAPATH
#include "OvsDebug.h"

#define NETLINK_FAMILY_NAME_LEN 48

/* Handles to the device object for communication with userspace. */
NDIS_HANDLE gOvsDeviceHandle;
PDEVICE_OBJECT gOvsDeviceObject;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH OvsOpenCloseDevice;

_Dispatch_type_(IRP_MJ_CLEANUP)
DRIVER_DISPATCH OvsCleanupDevice;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH OvsDeviceControl;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, OvsCreateDeviceObject)
#pragma alloc_text(PAGE, OvsOpenCloseDevice)
#pragma alloc_text(PAGE, OvsCleanupDevice)
#pragma alloc_text(PAGE, OvsDeviceControl)
#endif // ALLOC_PRAGMA

#define OVS_MAX_OPEN_INSTANCES 128

POVS_OPEN_INSTANCE ovsOpenInstanceArray[OVS_MAX_OPEN_INSTANCES];
UINT32 ovsNumberOfOpenInstances;
extern POVS_SWITCH_CONTEXT gOvsSwitchContext;

NDIS_SPIN_LOCK ovsCtrlLockObj;
PNDIS_SPIN_LOCK gOvsCtrlLock;


VOID
OvsInit()
{
    gOvsCtrlLock = &ovsCtrlLockObj;
    NdisAllocateSpinLock(gOvsCtrlLock);
    OvsInitEventQueue();
    OvsUserInit();
}

VOID
OvsCleanup()
{
    OvsCleanupEventQueue();
    if (gOvsCtrlLock) {
        NdisFreeSpinLock(gOvsCtrlLock);
        gOvsCtrlLock = NULL;
    }
    OvsUserCleanup();
}

VOID
OvsAcquireCtrlLock()
{
    NdisAcquireSpinLock(gOvsCtrlLock);
}

VOID
OvsReleaseCtrlLock()
{
    NdisReleaseSpinLock(gOvsCtrlLock);
}


/*
 * --------------------------------------------------------------------------
 * Creates the communication device between user and kernel, and also
 * initializes the data associated data structures.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsCreateDeviceObject(NDIS_HANDLE ovsExtDriverHandle)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicDeviceName;
    PDRIVER_DISPATCH dispatchTable[IRP_MJ_MAXIMUM_FUNCTION+1];
    NDIS_DEVICE_OBJECT_ATTRIBUTES deviceAttributes;
    OVS_LOG_TRACE("ovsExtDriverHandle: %p", ovsExtDriverHandle);

    RtlZeroMemory(dispatchTable,
                  (IRP_MJ_MAXIMUM_FUNCTION + 1) * sizeof (PDRIVER_DISPATCH));
    dispatchTable[IRP_MJ_CREATE] = OvsOpenCloseDevice;
    dispatchTable[IRP_MJ_CLOSE] = OvsOpenCloseDevice;
    dispatchTable[IRP_MJ_CLEANUP] = OvsCleanupDevice;
    dispatchTable[IRP_MJ_DEVICE_CONTROL] = OvsDeviceControl;

    NdisInitUnicodeString(&deviceName, OVS_DEVICE_NAME_NT);
    NdisInitUnicodeString(&symbolicDeviceName, OVS_DEVICE_NAME_DOS);

    RtlZeroMemory(&deviceAttributes, sizeof (NDIS_DEVICE_OBJECT_ATTRIBUTES));

    OVS_INIT_OBJECT_HEADER(&deviceAttributes.Header,
                           NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES,
                           NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1,
                           sizeof (NDIS_DEVICE_OBJECT_ATTRIBUTES));

    deviceAttributes.DeviceName = &deviceName;
    deviceAttributes.SymbolicName = &symbolicDeviceName;
    deviceAttributes.MajorFunctions = dispatchTable;
    deviceAttributes.ExtensionSize = sizeof (OVS_DEVICE_EXTENSION);

    status = NdisRegisterDeviceEx(ovsExtDriverHandle,
                                  &deviceAttributes,
                                  &gOvsDeviceObject,
                                  &gOvsDeviceHandle);
    if (status != NDIS_STATUS_SUCCESS) {
        POVS_DEVICE_EXTENSION ovsExt =
            (POVS_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(gOvsDeviceObject);
        ASSERT(gOvsDeviceObject != NULL);
        ASSERT(gOvsDeviceHandle != NULL);

        if (ovsExt) {
            ovsExt->numberOpenInstance = 0;
        }
    } else {
        /* Initialize the associated data structures. */
        OvsInit();
    }
    OVS_LOG_TRACE("DeviceObject: %p", gOvsDeviceObject);
    return status;
}


VOID
OvsDeleteDeviceObject()
{
    if (gOvsDeviceHandle) {
#ifdef DBG
        POVS_DEVICE_EXTENSION ovsExt = (POVS_DEVICE_EXTENSION)
                    NdisGetDeviceReservedExtension(gOvsDeviceObject);
        if (ovsExt) {
            ASSERT(ovsExt->numberOpenInstance == 0);
        }
#endif

        ASSERT(gOvsDeviceObject);
        NdisDeregisterDeviceEx(gOvsDeviceHandle);
        gOvsDeviceHandle = NULL;
        gOvsDeviceObject = NULL;
    }
    OvsCleanup();
}

POVS_OPEN_INSTANCE
OvsGetOpenInstance(PFILE_OBJECT fileObject,
                   UINT32 dpNo)
{
    POVS_OPEN_INSTANCE instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    ASSERT(instance);
    ASSERT(instance->fileObject == fileObject);
    if (gOvsSwitchContext == NULL ||
        gOvsSwitchContext->dpNo != dpNo) {
        return NULL;
    }
    return instance;
}


POVS_OPEN_INSTANCE
OvsFindOpenInstance(PFILE_OBJECT fileObject)
{
    UINT32 i, j;
    for (i = 0, j = 0; i < OVS_MAX_OPEN_INSTANCES &&
                       j < ovsNumberOfOpenInstances; i++) {
        if (ovsOpenInstanceArray[i]) {
            if (ovsOpenInstanceArray[i]->fileObject == fileObject) {
                return ovsOpenInstanceArray[i];
            }
            j++;
        }
    }
    return NULL;
}

NTSTATUS
OvsAddOpenInstance(PFILE_OBJECT fileObject)
{
    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE) OvsAllocateMemory(sizeof (OVS_OPEN_INSTANCE));
    UINT32 i;

    if (instance == NULL) {
        return STATUS_NO_MEMORY;
    }
    OvsAcquireCtrlLock();
    ASSERT(OvsFindOpenInstance(fileObject) == NULL);

    if (ovsNumberOfOpenInstances >= OVS_MAX_OPEN_INSTANCES) {
        OvsReleaseCtrlLock();
        OvsFreeMemory(instance);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(instance, sizeof (OVS_OPEN_INSTANCE));

    for (i = 0; i < OVS_MAX_OPEN_INSTANCES; i++) {
        if (ovsOpenInstanceArray[i] == NULL) {
            ovsOpenInstanceArray[i] = instance;
            instance->cookie = i;
            break;
        }
    }
    ASSERT(i < OVS_MAX_OPEN_INSTANCES);
    instance->fileObject = fileObject;
    ASSERT(fileObject->FsContext == NULL);
    fileObject->FsContext = instance;
    OvsReleaseCtrlLock();
    return STATUS_SUCCESS;
}

static VOID
OvsCleanupOpenInstance(PFILE_OBJECT fileObject)
{
    POVS_OPEN_INSTANCE instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    ASSERT(instance);
    ASSERT(fileObject == instance->fileObject);
    OvsCleanupEvent(instance);
    OvsCleanupPacketQueue(instance);
}

VOID
OvsRemoveOpenInstance(PFILE_OBJECT fileObject)
{
    POVS_OPEN_INSTANCE instance;
    ASSERT(fileObject->FsContext);
    instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    ASSERT(instance->cookie < OVS_MAX_OPEN_INSTANCES);

    OvsAcquireCtrlLock();
    fileObject->FsContext = NULL;
    ASSERT(ovsOpenInstanceArray[instance->cookie] == instance);
    ovsOpenInstanceArray[instance->cookie] = NULL;
    OvsReleaseCtrlLock();
    ASSERT(instance->eventQueue == NULL);
    ASSERT (instance->packetQueue == NULL);
    OvsFreeMemory(instance);
}

NTSTATUS
OvsCompleteIrpRequest(PIRP irp,
                      ULONG_PTR infoPtr,
                      NTSTATUS status)
{
    irp->IoStatus.Information = infoPtr;
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}


NTSTATUS
OvsOpenCloseDevice(PDEVICE_OBJECT deviceObject,
                   PIRP irp)
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS status = STATUS_SUCCESS;
    PFILE_OBJECT fileObject;
    POVS_DEVICE_EXTENSION ovsExt =
        (POVS_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(deviceObject);

    ASSERT(deviceObject == gOvsDeviceObject);
    ASSERT(ovsExt != NULL);

    irpSp = IoGetCurrentIrpStackLocation(irp);
    fileObject = irpSp->FileObject;
    OVS_LOG_TRACE("DeviceObject: %p, fileObject:%p, instance: %u",
                  deviceObject, fileObject,
                  ovsExt->numberOpenInstance);

    switch (irpSp->MajorFunction) {
    case IRP_MJ_CREATE:
        status = OvsAddOpenInstance(fileObject);
        if (STATUS_SUCCESS == status) {
            InterlockedIncrement((LONG volatile *)&ovsExt->numberOpenInstance);
        }
        break;
    case IRP_MJ_CLOSE:
        ASSERT(ovsExt->numberOpenInstance > 0);
        OvsRemoveOpenInstance(fileObject);
        InterlockedDecrement((LONG volatile *)&ovsExt->numberOpenInstance);
        break;
    default:
        ASSERT(0);
    }
    return OvsCompleteIrpRequest(irp, (ULONG_PTR)0, status);
}

_Use_decl_annotations_
NTSTATUS
OvsCleanupDevice(PDEVICE_OBJECT deviceObject,
                 PIRP irp)
{

    PIO_STACK_LOCATION irpSp;
    PFILE_OBJECT fileObject;

    NTSTATUS status = STATUS_SUCCESS;
#ifdef DBG
    POVS_DEVICE_EXTENSION ovsExt =
        (POVS_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(deviceObject);
    if (ovsExt) {
        ASSERT(ovsExt->numberOpenInstance > 0);
    }
#else
    UNREFERENCED_PARAMETER(deviceObject);
#endif
    ASSERT(deviceObject == gOvsDeviceObject);
    irpSp = IoGetCurrentIrpStackLocation(irp);
    fileObject = irpSp->FileObject;

    ASSERT(irpSp->MajorFunction == IRP_MJ_CLEANUP);

    OvsCleanupOpenInstance(fileObject);

    return OvsCompleteIrpRequest(irp, (ULONG_PTR)0, status);
}


/*
 * --------------------------------------------------------------------------
 * IOCTL function handler for the device.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsDeviceControl(PDEVICE_OBJECT deviceObject,
                 PIRP irp)
{

    PIO_STACK_LOCATION irpSp;
    NTSTATUS status = STATUS_SUCCESS;
    PFILE_OBJECT fileObject;
    PVOID inputBuffer;
    PVOID outputBuffer;
    UINT32 inputBufferLen, outputBufferLen;
    UINT32 code, replyLen = 0;
    POVS_OPEN_INSTANCE instance;

#ifdef DBG
    POVS_DEVICE_EXTENSION ovsExt =
        (POVS_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(deviceObject);
    ASSERT(deviceObject == gOvsDeviceObject);
    ASSERT(ovsExt);
    ASSERT(ovsExt->numberOpenInstance > 0);
#else
    UNREFERENCED_PARAMETER(deviceObject);
#endif

    irpSp = IoGetCurrentIrpStackLocation(irp);

    ASSERT(irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL);
    ASSERT(irpSp->FileObject != NULL);

    fileObject = irpSp->FileObject;
    instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    outputBuffer = inputBuffer = irp->AssociatedIrp.SystemBuffer;

    return OvsCompleteIrpRequest(irp, (ULONG_PTR)replyLen, status);
}

#endif /* OVS_USE_NL_INTERFACE */
