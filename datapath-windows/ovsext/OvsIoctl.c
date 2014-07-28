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
#define OVS_DBG_MOD OVS_DBG_IOCTL
#include "OvsDebug.h"

/* Handles to the device object for communication with userspace. */
NDIS_HANDLE gOvsDeviceHandle;
PDEVICE_OBJECT gOvsDeviceObject;

/*
 * There seems to be a skew between the kernel's version of current time and
 * the userspace's version of current time. The skew was seen to
 * monotonically increase as well.
 *
 * In order to deal with the situation, we pass down the userspace's version
 * of the timestamp to the kernel, and let the kernel calculate the delta.
 */
UINT64 ovsUserTimestampDelta;
UINT64 ovsTimeIncrementPerTick;

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
NDIS_SPIN_LOCK ovsFlowLockObj;
PNDIS_SPIN_LOCK gOvsCtrlLock;
PNDIS_SPIN_LOCK ovsFlowLock;

VOID
OvsInitIoctl()
{
    gOvsCtrlLock = &ovsCtrlLockObj;
    ovsFlowLock = &ovsFlowLockObj;
    NdisAllocateSpinLock(ovsFlowLock);
    NdisAllocateSpinLock(gOvsCtrlLock);
}

VOID
OvsCleanupIoctl()
{
    if (ovsFlowLock) {
        NdisFreeSpinLock(ovsFlowLock);
        NdisFreeSpinLock(gOvsCtrlLock);
        gOvsCtrlLock = NULL;
        gOvsCtrlLock = NULL;
    }
}

VOID
OvsInit()
{
    OvsInitIoctl();
    OvsInitEventQueue();
    OvsUserInit();
}

VOID
OvsCleanup()
{
    OvsCleanupEventQueue();
    OvsCleanupIoctl();
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

    NdisInitUnicodeString(&deviceName, OVS_NT_DEVICE_NAME);
    NdisInitUnicodeString(&symbolicDeviceName, OVS_DOS_DEVICE_NAME);

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
 *----------------------------------------------------------------------------
 * OvsGetVersionIoctl --
 *
 *    On entry None
 *    On exit Driver version
 *
 * Result:
 *    STATUS_SUCCESS
 *    STATUS_BUFFER_TOO_SMALL
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsGetVersionIoctl(PVOID outputBuffer,
                   uint32 outputLength,
                   uint32 *replyLen)
{
    POVS_VERSION driverOut = (POVS_VERSION)outputBuffer;

    if (outputLength < sizeof (*driverOut)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *replyLen = sizeof (*driverOut);
    driverOut->mjrDrvVer = OVS_DRIVER_MAJOR_VER;
    driverOut->mnrDrvVer = OVS_DRIVER_MINOR_VER;

    return STATUS_SUCCESS;
}


/*
 *----------------------------------------------------------------------------
 * OvsDpDumpIoctl --
 *    Get All Datapath. For now, we only support one datapath.
 *
 * Result:
 *    STATUS_SUCCESS
 *    STATUS_BUFFER_TOO_SMALL
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsDpDumpIoctl(PVOID outputBuffer,
               UINT32 outputLength,
               UINT32 *replyLen)
{
    *replyLen = sizeof (UINT32);
    if (outputLength < sizeof (UINT32)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    OvsAcquireCtrlLock();
    if (gOvsSwitchContext) {
        *(UINT32 *)outputBuffer = gOvsSwitchContext->dpNo;
    } else {
        *replyLen = 0;
    }
    OvsReleaseCtrlLock();

    return STATUS_SUCCESS;
}


/*
 *----------------------------------------------------------------------------
 * OvsDpGetIoctl --
 *    Given dpNo, get all datapath info as defined in OVS_DP_INFO.
 *
 * Result:
 *    STATUS_SUCCESS
 *    STATUS_BUFFER_TOO_SMALL
 *    STATUS_INVALID_PARAMETER
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsDpGetIoctl(PVOID inputBuffer,
              UINT32 inputLength,
              PVOID outputBuffer,
              UINT32 outputLength,
              UINT32 *replyLen)
{
    UINT32 dpNo;
    POVS_DP_INFO info;
    OVS_DATAPATH  *datapath;

    if (inputLength < sizeof (UINT32)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (outputLength < sizeof (OVS_DP_INFO)) {
        *replyLen = sizeof (OVS_DP_INFO);
        return STATUS_BUFFER_TOO_SMALL;
    }

    dpNo = *(UINT32 *)inputBuffer;
    OvsAcquireCtrlLock();
    if (gOvsSwitchContext == NULL ||
        gOvsSwitchContext->dpNo != dpNo) {
        OvsReleaseCtrlLock();
        return STATUS_INVALID_PARAMETER;
    }
    *replyLen = sizeof (OVS_DP_INFO);
    RtlZeroMemory(outputBuffer, sizeof (OVS_DP_INFO));
    info = (POVS_DP_INFO)outputBuffer;
    RtlCopyMemory(info->name, "ovs-system", sizeof ("ovs-system"));
    datapath = &gOvsSwitchContext->datapath;
    info->nMissed = datapath->misses;
    info->nHit = datapath->hits;
    info->nLost = datapath->lost;
    info->nFlows = datapath->nFlows;
    OvsReleaseCtrlLock();
    return STATUS_SUCCESS;
}

NTSTATUS
OvsDeviceControl(PDEVICE_OBJECT deviceObject,
                 PIRP irp)
{

    PIO_STACK_LOCATION irpSp;
    NTSTATUS status = STATUS_SUCCESS;
    PFILE_OBJECT fileObject;
    PVOID inputBuffer;
    PVOID outputBuffer;
    UINT32 inputBufferLen, outputBufferLen, mdlBufferLen;
    UINT32 code, replyLen = 0;
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
    code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    /*
     * In case of an IRP with METHOD_IN_DIRECT or METHOD_OUT_DIRECT, the size
     * of the MDL is stored in Parameters.DeviceIoControl.OutputBufferLength.
     */
    mdlBufferLen = outputBufferLen;
    outputBuffer = inputBuffer = irp->AssociatedIrp.SystemBuffer;

    switch(code) {
    case OVS_IOCTL_VERSION_GET:
        status = OvsGetVersionIoctl(outputBuffer, outputBufferLen,
                                    &replyLen);
        break;
    case OVS_IOCTL_DP_DUMP:
        status = OvsDpDumpIoctl(outputBuffer, outputBufferLen, &replyLen);
        break;
    case OVS_IOCTL_DP_GET:
        if (irp->MdlAddress == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        outputBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                                                    NormalPagePriority);
        if (outputBuffer == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            status = OvsDpGetIoctl(inputBuffer, inputBufferLen,
                                   outputBuffer, outputBufferLen, &replyLen);
        }
        break;
    case OVS_IOCTL_DP_SET:
        status = STATUS_NOT_IMPLEMENTED;
        break;
    case OVS_IOCTL_VPORT_DUMP:
        if (irp->MdlAddress == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        outputBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                                                    NormalPagePriority);
        if (outputBuffer) {
            status = OvsDumpVportIoctl(inputBuffer, inputBufferLen,
                                       outputBuffer, outputBufferLen,
                                       &replyLen);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        break;
    case OVS_IOCTL_VPORT_GET:
        if (irp->MdlAddress == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        outputBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                                                    NormalPagePriority);
        if (outputBuffer) {
            status = OvsGetVportIoctl(inputBuffer, inputBufferLen,
                                      outputBuffer, outputBufferLen,
                                      &replyLen);
        } else {
            status =  STATUS_INSUFFICIENT_RESOURCES;
        }
        break;
    case OVS_IOCTL_VPORT_SET:
        status = STATUS_NOT_IMPLEMENTED;
        break;
    case OVS_IOCTL_VPORT_ADD:
        if (irp->MdlAddress == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        outputBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                                                    NormalPagePriority);
        if (outputBuffer) {
            status = OvsAddVportIoctl(inputBuffer, inputBufferLen,
                                      outputBuffer, outputBufferLen,
                                      &replyLen);
        }  else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        break;
    case OVS_IOCTL_VPORT_DEL:
        status = OvsDelVportIoctl(inputBuffer, inputBufferLen,
                                  &replyLen);
        break;
    case OVS_IOCTL_VPORT_EXT_INFO:
        if (irp->MdlAddress == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        outputBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                                                    NormalPagePriority);
        if (outputBuffer) {
            status = OvsGetExtInfoIoctl(inputBuffer, inputBufferLen,
                                          outputBuffer, outputBufferLen,
                                          &replyLen);
        } else {
            OVS_LOG_INFO("ExtInfo: fail to get outputBuffer address");
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        break;
    case OVS_IOCTL_FLOW_DUMP:
        if (irp->MdlAddress == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        outputBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                                                    NormalPagePriority);
        if (outputBuffer) {
            status = OvsDumpFlowIoctl(inputBuffer, inputBufferLen,
                                      outputBuffer, outputBufferLen,
                                      &replyLen);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        break;
    case OVS_IOCTL_FLOW_GET:
        if (irp->MdlAddress == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        outputBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                                                    NormalPagePriority);
        if (outputBuffer) {
            status = OvsGetFlowIoctl(inputBuffer, inputBufferLen,
                                     outputBuffer, outputBufferLen,
                                     &replyLen);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        break;
    case OVS_IOCTL_FLOW_PUT:
        // XXX: This is not really working - mapping the input buffer
        // XXX: inputBufferLen = mdlBufferLen;
        // inputBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                                                   // NormalPagePriority);
        status = OvsPutFlowIoctl(inputBuffer, inputBufferLen,
                                 outputBuffer, outputBufferLen,
                                 &replyLen);
        break;
    case OVS_IOCTL_FLOW_FLUSH:
        status = OvsFlushFlowIoctl(inputBuffer, inputBufferLen);
        break;
    case OVS_IOCTL_QOS_QUEUE_DUMP:
    case OVS_IOCTL_QOS_QUEUE_GET:
    case OVS_IOCTL_QOS_QUEUE_SET:
        status = STATUS_NOT_IMPLEMENTED;
        break;
    case OVS_IOCTL_DATAPATH_SUBSCRIBE:
        status = OvsSubscribeDpIoctl(fileObject, inputBuffer,
                                           inputBufferLen);
        break;
    case OVS_IOCTL_DATAPATH_READ:
        if (irp->MdlAddress == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        outputBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                                                    NormalPagePriority);
        if (outputBuffer) {
            status = OvsReadDpIoctl(fileObject, outputBuffer,
                                          outputBufferLen, &replyLen);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        break;
    case OVS_IOCTL_DATAPATH_OPERATE:
        status = STATUS_NOT_IMPLEMENTED;
        break;
    case OVS_IOCTL_DATAPATH_EXECUTE:
        // XXX: need to make the input direct
        status = OvsExecuteDpIoctl(inputBuffer, inputBufferLen,
                                         outputBufferLen);
        break;
    case OVS_IOCTL_DATAPATH_PURGE:
        status = OvsPurgeDpIoctl(fileObject);
        break;
    case OVS_IOCTL_DATAPATH_WAIT:
        status = OvsWaitDpIoctl(irp, fileObject);
        break;
    case OVS_IOCTL_EVENT_SUBSCRIBE:
        status = OvsSubscribeEventIoctl(fileObject, inputBuffer,
                                        inputBufferLen);
        break;
    case OVS_IOCTL_EVENT_POLL:
        if (irp->MdlAddress == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        outputBuffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                                                    NormalPagePriority);
        if (outputBuffer == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            status = OvsPollEventIoctl(fileObject, inputBuffer,
                                       inputBufferLen, outputBuffer,
                                       outputBufferLen, &replyLen);
        }
        break;
    case OVS_IOCTL_EVENT_WAIT:
        status = OvsWaitEventIoctl(irp, fileObject,
                                   inputBuffer, inputBufferLen);
        break;
    case OVS_IOCTL_DP_TIMESTAMP_SET:
        if (inputBufferLen != sizeof (ovsUserTimestampDelta)) {
            status = STATUS_INFO_LENGTH_MISMATCH;
        } else {
            int64 currentUserTS = *(int64 *)inputBuffer;
            LARGE_INTEGER tickCount;

            /* So many ticks since system booted. */
            KeQueryTickCount(&tickCount);
            ovsUserTimestampDelta = currentUserTS -
                                    (tickCount.QuadPart * ovsTimeIncrementPerTick);
            status = STATUS_SUCCESS;
        }
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    if (status == STATUS_PENDING) {
        return status;
    } else {
        /*
         * When the system-address-space mapping that is returned by
         * MmGetSystemAddressForMdlSafe is no longer needed, it must be
         * released.
         * http://msdn.microsoft.com/en-us/library/windows/hardware/ff554559(v=vs.85).aspx
         *
         * We might have to release the MDL here.
         */
        return OvsCompleteIrpRequest(irp, (ULONG_PTR)replyLen, status);
    }
}
