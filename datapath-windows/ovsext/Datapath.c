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

#include "precomp.h"
#include "Switch.h"
#include "User.h"
#include "Datapath.h"
#include "Jhash.h"
#include "Vport.h"
#include "Event.h"
#include "User.h"
#include "PacketIO.h"
#include "NetProto.h"
#include "Flow.h"
#include "User.h"
#include "Vxlan.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_DATAPATH
#include "Debug.h"

#define NETLINK_FAMILY_NAME_LEN 48


/*
 * Netlink messages are grouped by family (aka type), and each family supports
 * a set of commands, and can be passed both from kernel -> userspace or
 * vice-versa. To call into the kernel, userspace uses a device operation which
 * is outside of a netlink message.
 *
 * Each command results in the invocation of a handler function to implement the
 * request functionality.
 *
 * Expectedly, only certain combinations of (device operation, netlink family,
 * command) are valid.
 *
 * Here, we implement the basic infrastructure to perform validation on the
 * incoming message, version checking, and also to invoke the corresponding
 * handler to do the heavy-lifting.
 */

/*
 * Handler for a given netlink command. Not all the parameters are used by all
 * the handlers.
 */
typedef NTSTATUS(NetlinkCmdHandler)(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                    UINT32 *replyLen);

typedef struct _NETLINK_CMD {
    UINT16 cmd;
    NetlinkCmdHandler *handler;
    UINT32 supportedDevOp;      /* Supported device operations. */
    BOOLEAN validateDpIndex;    /* Does command require a valid DP argument. */
} NETLINK_CMD, *PNETLINK_CMD;

/* A netlink family is a group of commands. */
typedef struct _NETLINK_FAMILY {
    CHAR *name;
    UINT16 id;
    UINT8 version;
    UINT8 pad1;
    UINT16 maxAttr;
    UINT16 pad2;
    NETLINK_CMD *cmds;          /* Array of netlink commands and handlers. */
    UINT16 opsCount;
} NETLINK_FAMILY, *PNETLINK_FAMILY;

/* Handlers for the various netlink commands. */
static NetlinkCmdHandler OvsPendEventCmdHandler,
                         OvsPendPacketCmdHandler,
                         OvsSubscribeEventCmdHandler,
                         OvsSubscribePacketCmdHandler,
                         OvsReadEventCmdHandler,
                         OvsReadPacketCmdHandler,
                         OvsNewDpCmdHandler,
                         OvsGetDpCmdHandler,
                         OvsSetDpCmdHandler;

NetlinkCmdHandler        OvsGetNetdevCmdHandler,
                         OvsGetVportCmdHandler,
                         OvsSetVportCmdHandler,
                         OvsNewVportCmdHandler,
                         OvsDeleteVportCmdHandler;

static NTSTATUS HandleGetDpTransaction(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                       UINT32 *replyLen);
static NTSTATUS HandleGetDpDump(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                UINT32 *replyLen);
static NTSTATUS HandleDpTransactionCommon(
                    POVS_USER_PARAMS_CONTEXT usrParamsCtx, UINT32 *replyLen);
static NTSTATUS OvsGetPidHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                    UINT32 *replyLen);

/*
 * The various netlink families, along with the supported commands. Most of
 * these families and commands are part of the openvswitch specification for a
 * netlink datapath. In addition, each platform can implement a few families
 * and commands as extensions.
 */

/* Netlink control family: this is a Windows specific family. */
NETLINK_CMD nlControlFamilyCmdOps[] = {
    { .cmd = OVS_CTRL_CMD_WIN_PEND_REQ,
      .handler = OvsPendEventCmdHandler,
      .supportedDevOp = OVS_WRITE_DEV_OP,
      .validateDpIndex = TRUE,
    },
    { .cmd = OVS_CTRL_CMD_WIN_PEND_PACKET_REQ,
      .handler = OvsPendPacketCmdHandler,
      .supportedDevOp = OVS_WRITE_DEV_OP,
      .validateDpIndex = TRUE,
    },
    { .cmd = OVS_CTRL_CMD_MC_SUBSCRIBE_REQ,
      .handler = OvsSubscribeEventCmdHandler,
      .supportedDevOp = OVS_WRITE_DEV_OP,
      .validateDpIndex = TRUE,
    },
    { .cmd = OVS_CTRL_CMD_PACKET_SUBSCRIBE_REQ,
      .handler = OvsSubscribePacketCmdHandler,
      .supportedDevOp = OVS_WRITE_DEV_OP,
      .validateDpIndex = TRUE,
    },
    { .cmd = OVS_CTRL_CMD_EVENT_NOTIFY,
      .handler = OvsReadEventCmdHandler,
      .supportedDevOp = OVS_READ_DEV_OP,
      .validateDpIndex = FALSE,
    },
    { .cmd = OVS_CTRL_CMD_READ_NOTIFY,
      .handler = OvsReadPacketCmdHandler,
      .supportedDevOp = OVS_READ_DEV_OP,
      .validateDpIndex = FALSE,
    }
};

NETLINK_FAMILY nlControlFamilyOps = {
    .name     = OVS_WIN_CONTROL_FAMILY,
    .id       = OVS_WIN_NL_CTRL_FAMILY_ID,
    .version  = OVS_WIN_CONTROL_VERSION,
    .maxAttr  = OVS_WIN_CONTROL_ATTR_MAX,
    .cmds     = nlControlFamilyCmdOps,
    .opsCount = ARRAY_SIZE(nlControlFamilyCmdOps)
};

/* Netlink datapath family. */
NETLINK_CMD nlDatapathFamilyCmdOps[] = {
    { .cmd             = OVS_DP_CMD_NEW,
      .handler         = OvsNewDpCmdHandler,
      .supportedDevOp  = OVS_TRANSACTION_DEV_OP,
      .validateDpIndex = FALSE
    },
    { .cmd             = OVS_DP_CMD_GET,
      .handler         = OvsGetDpCmdHandler,
      .supportedDevOp  = OVS_WRITE_DEV_OP | OVS_READ_DEV_OP |
                         OVS_TRANSACTION_DEV_OP,
      .validateDpIndex = FALSE
    },
    { .cmd             = OVS_DP_CMD_SET,
      .handler         = OvsSetDpCmdHandler,
      .supportedDevOp  = OVS_WRITE_DEV_OP | OVS_READ_DEV_OP |
                         OVS_TRANSACTION_DEV_OP,
      .validateDpIndex = TRUE
    }
};

NETLINK_FAMILY nlDatapathFamilyOps = {
    .name     = OVS_DATAPATH_FAMILY,
    .id       = OVS_WIN_NL_DATAPATH_FAMILY_ID,
    .version  = OVS_DATAPATH_VERSION,
    .maxAttr  = OVS_DP_ATTR_MAX,
    .cmds     = nlDatapathFamilyCmdOps,
    .opsCount = ARRAY_SIZE(nlDatapathFamilyCmdOps)
};

/* Netlink packet family. */

NETLINK_CMD nlPacketFamilyCmdOps[] = {
    { .cmd             = OVS_PACKET_CMD_EXECUTE,
      .handler         = OvsNlExecuteCmdHandler,
      .supportedDevOp  = OVS_TRANSACTION_DEV_OP,
      .validateDpIndex = TRUE
    }
};

NETLINK_FAMILY nlPacketFamilyOps = {
    .name     = OVS_PACKET_FAMILY,
    .id       = OVS_WIN_NL_PACKET_FAMILY_ID,
    .version  = OVS_PACKET_VERSION,
    .maxAttr  = OVS_PACKET_ATTR_MAX,
    .cmds     = nlPacketFamilyCmdOps,
    .opsCount = ARRAY_SIZE(nlPacketFamilyCmdOps)
};

/* Netlink vport family. */
NETLINK_CMD nlVportFamilyCmdOps[] = {
    { .cmd = OVS_VPORT_CMD_GET,
      .handler = OvsGetVportCmdHandler,
      .supportedDevOp = OVS_WRITE_DEV_OP | OVS_READ_DEV_OP |
                        OVS_TRANSACTION_DEV_OP,
      .validateDpIndex = TRUE
    },
    { .cmd = OVS_VPORT_CMD_NEW,
      .handler = OvsNewVportCmdHandler,
      .supportedDevOp = OVS_TRANSACTION_DEV_OP,
      .validateDpIndex = TRUE
    },
    { .cmd = OVS_VPORT_CMD_SET,
      .handler = OvsSetVportCmdHandler,
      .supportedDevOp = OVS_TRANSACTION_DEV_OP,
      .validateDpIndex = TRUE
    },
    { .cmd = OVS_VPORT_CMD_DEL,
      .handler = OvsDeleteVportCmdHandler,
      .supportedDevOp = OVS_TRANSACTION_DEV_OP,
      .validateDpIndex = TRUE
    },
};

NETLINK_FAMILY nlVportFamilyOps = {
    .name     = OVS_VPORT_FAMILY,
    .id       = OVS_WIN_NL_VPORT_FAMILY_ID,
    .version  = OVS_VPORT_VERSION,
    .maxAttr  = OVS_VPORT_ATTR_MAX,
    .cmds     = nlVportFamilyCmdOps,
    .opsCount = ARRAY_SIZE(nlVportFamilyCmdOps)
};

/* Netlink flow family. */

NETLINK_CMD nlFlowFamilyCmdOps[] = {
    { .cmd              = OVS_FLOW_CMD_NEW,
      .handler          = OvsFlowNlCmdHandler,
      .supportedDevOp   = OVS_TRANSACTION_DEV_OP,
      .validateDpIndex  = TRUE
    },
    { .cmd              = OVS_FLOW_CMD_SET,
      .handler          = OvsFlowNlCmdHandler,
      .supportedDevOp   = OVS_TRANSACTION_DEV_OP,
      .validateDpIndex  = TRUE
    },
    { .cmd              = OVS_FLOW_CMD_DEL,
      .handler          = OvsFlowNlCmdHandler,
      .supportedDevOp   = OVS_TRANSACTION_DEV_OP,
      .validateDpIndex  = TRUE
    },
    { .cmd              = OVS_FLOW_CMD_GET,
      .handler          = OvsFlowNlGetCmdHandler,
      .supportedDevOp   = OVS_TRANSACTION_DEV_OP |
                          OVS_WRITE_DEV_OP | OVS_READ_DEV_OP,
      .validateDpIndex  = TRUE
    },
};

NETLINK_FAMILY nlFLowFamilyOps = {
    .name     = OVS_FLOW_FAMILY,
    .id       = OVS_WIN_NL_FLOW_FAMILY_ID,
    .version  = OVS_FLOW_VERSION,
    .maxAttr  = OVS_FLOW_ATTR_MAX,
    .cmds     = nlFlowFamilyCmdOps,
    .opsCount = ARRAY_SIZE(nlFlowFamilyCmdOps)
};

/* Netlink netdev family. */
NETLINK_CMD nlNetdevFamilyCmdOps[] = {
    { .cmd = OVS_WIN_NETDEV_CMD_GET,
      .handler = OvsGetNetdevCmdHandler,
      .supportedDevOp = OVS_TRANSACTION_DEV_OP,
      .validateDpIndex = FALSE
    },
};

NETLINK_FAMILY nlNetdevFamilyOps = {
    .name     = OVS_WIN_NETDEV_FAMILY,
    .id       = OVS_WIN_NL_NETDEV_FAMILY_ID,
    .version  = OVS_WIN_NETDEV_VERSION,
    .maxAttr  = OVS_WIN_NETDEV_ATTR_MAX,
    .cmds     = nlNetdevFamilyCmdOps,
    .opsCount = ARRAY_SIZE(nlNetdevFamilyCmdOps)
};

static NTSTATUS MapIrpOutputBuffer(PIRP irp,
                                   UINT32 bufferLength,
                                   UINT32 requiredLength,
                                   PVOID *buffer);
static NTSTATUS ValidateNetlinkCmd(UINT32 devOp,
                                   POVS_OPEN_INSTANCE instance,
                                   POVS_MESSAGE ovsMsg,
                                   NETLINK_FAMILY *nlFamilyOps);
static NTSTATUS InvokeNetlinkCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                        NETLINK_FAMILY *nlFamilyOps,
                                        UINT32 *replyLen);

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

/*
 * We might hit this limit easily since userspace opens a netlink descriptor for
 * each thread, and at least one descriptor per vport. Revisit this later.
 */
#define OVS_MAX_OPEN_INSTANCES 512
#define OVS_SYSTEM_DP_NAME     "ovs-system"

POVS_OPEN_INSTANCE ovsOpenInstanceArray[OVS_MAX_OPEN_INSTANCES];
UINT32 ovsNumberOfOpenInstances;
extern POVS_SWITCH_CONTEXT gOvsSwitchContext;

NDIS_SPIN_LOCK ovsCtrlLockObj;
PNDIS_SPIN_LOCK gOvsCtrlLock;

NTSTATUS
InitUserDumpState(POVS_OPEN_INSTANCE instance,
                  POVS_MESSAGE ovsMsg)
{
    /* Clear the dumpState from a previous dump sequence. */
    ASSERT(instance->dumpState.ovsMsg == NULL);
    ASSERT(ovsMsg);

    instance->dumpState.ovsMsg =
        (POVS_MESSAGE)OvsAllocateMemoryWithTag(sizeof(OVS_MESSAGE),
                                               OVS_DATAPATH_POOL_TAG);
    if (instance->dumpState.ovsMsg == NULL) {
        return STATUS_NO_MEMORY;
    }
    RtlCopyMemory(instance->dumpState.ovsMsg, ovsMsg,
                  sizeof *instance->dumpState.ovsMsg);
    RtlZeroMemory(instance->dumpState.index,
                  sizeof instance->dumpState.index);

    return STATUS_SUCCESS;
}

VOID
FreeUserDumpState(POVS_OPEN_INSTANCE instance)
{
    if (instance->dumpState.ovsMsg != NULL) {
        OvsFreeMemoryWithTag(instance->dumpState.ovsMsg,
                             OVS_DATAPATH_POOL_TAG);
        RtlZeroMemory(&instance->dumpState, sizeof instance->dumpState);
    }
}

VOID
OvsInit()
{
    gOvsCtrlLock = &ovsCtrlLockObj;
    NdisAllocateSpinLock(gOvsCtrlLock);
    OvsInitEventQueue();
}

VOID
OvsCleanup()
{
    OvsCleanupEventQueue();
    if (gOvsCtrlLock) {
        NdisFreeSpinLock(gOvsCtrlLock);
        gOvsCtrlLock = NULL;
    }
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
        OvsRegisterSystemProvider((PVOID)gOvsDeviceObject);
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

        OvsUnregisterSystemProvider();
    }
}

POVS_OPEN_INSTANCE
OvsGetOpenInstance(PFILE_OBJECT fileObject,
                   UINT32 dpNo)
{
    POVS_OPEN_INSTANCE instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    ASSERT(instance);
    ASSERT(instance->fileObject == fileObject);
    if (gOvsSwitchContext->dpNo != dpNo) {
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
OvsAddOpenInstance(POVS_DEVICE_EXTENSION ovsExt,
                   PFILE_OBJECT fileObject)
{
    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)OvsAllocateMemoryWithTag(sizeof(OVS_OPEN_INSTANCE),
                                                     OVS_DATAPATH_POOL_TAG);
    UINT32 i;

    if (instance == NULL) {
        return STATUS_NO_MEMORY;
    }
    OvsAcquireCtrlLock();
    ASSERT(OvsFindOpenInstance(fileObject) == NULL);

    if (ovsNumberOfOpenInstances >= OVS_MAX_OPEN_INSTANCES) {
        OvsReleaseCtrlLock();
        OvsFreeMemoryWithTag(instance, OVS_DATAPATH_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(instance, sizeof (OVS_OPEN_INSTANCE));

    for (i = 0; i < OVS_MAX_OPEN_INSTANCES; i++) {
        if (ovsOpenInstanceArray[i] == NULL) {
            ovsOpenInstanceArray[i] = instance;
            ovsNumberOfOpenInstances++;
            instance->cookie = i;
            break;
        }
    }
    ASSERT(i < OVS_MAX_OPEN_INSTANCES);
    instance->fileObject = fileObject;
    ASSERT(fileObject->FsContext == NULL);
    instance->pid = (UINT32)InterlockedIncrement((LONG volatile *)&ovsExt->pidCount);
    if (instance->pid == 0) {
        /* XXX: check for rollover. */
    }
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
    ovsNumberOfOpenInstances--;
    OvsReleaseCtrlLock();
    ASSERT(instance->eventQueue == NULL);
    ASSERT (instance->packetQueue == NULL);
    OvsFreeMemoryWithTag(instance, OVS_DATAPATH_POOL_TAG);
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
        status = OvsAddOpenInstance(ovsExt, fileObject);
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
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    UINT32 inputBufferLen, outputBufferLen;
    UINT32 code, replyLen = 0;
    POVS_OPEN_INSTANCE instance;
    UINT32 devOp;
    OVS_MESSAGE ovsMsgReadOp;
    POVS_MESSAGE ovsMsg;
    NETLINK_FAMILY *nlFamilyOps;
    OVS_USER_PARAMS_CONTEXT usrParamsCtx;

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
    inputBuffer = irp->AssociatedIrp.SystemBuffer;

    /* Check if the extension is enabled. */
    if (NULL == gOvsSwitchContext) {
        status = STATUS_NOT_FOUND;
        goto exit;
    }

    if (!OvsAcquireSwitchContext()) {
        status = STATUS_NOT_FOUND;
        goto exit;
    }

    /*
     * Validate the input/output buffer arguments depending on the type of the
     * operation.
     */
    switch (code) {
    case OVS_IOCTL_GET_PID:
        /* Both input buffer and output buffer use the same location. */
        outputBuffer = irp->AssociatedIrp.SystemBuffer;
        if (outputBufferLen != 0) {
            InitUserParamsCtx(irp, instance, 0, NULL,
                              inputBuffer, inputBufferLen,
                              outputBuffer, outputBufferLen,
                              &usrParamsCtx);

            ASSERT(outputBuffer);
        } else {
            status = STATUS_NDIS_INVALID_LENGTH;
            goto done;
        }

        status = OvsGetPidHandler(&usrParamsCtx, &replyLen);
        goto done;

    case OVS_IOCTL_TRANSACT:
        /* Both input buffer and output buffer are mandatory. */
        if (outputBufferLen != 0) {
            status = MapIrpOutputBuffer(irp, outputBufferLen,
                                        sizeof *ovsMsg, &outputBuffer);
            if (status != STATUS_SUCCESS) {
                goto done;
            }
            ASSERT(outputBuffer);
        } else {
            status = STATUS_NDIS_INVALID_LENGTH;
            goto done;
        }

        if (inputBufferLen < sizeof (*ovsMsg)) {
            status = STATUS_NDIS_INVALID_LENGTH;
            goto done;
        }

        ovsMsg = inputBuffer;
        devOp = OVS_TRANSACTION_DEV_OP;
        break;

    case OVS_IOCTL_READ_EVENT:
    case OVS_IOCTL_READ_PACKET:
        /*
         * Output buffer is mandatory. These IOCTLs are used to read events and
         * packets respectively. It is convenient to have separate ioctls.
         */
        if (outputBufferLen != 0) {
            status = MapIrpOutputBuffer(irp, outputBufferLen,
                                        sizeof *ovsMsg, &outputBuffer);
            if (status != STATUS_SUCCESS) {
                goto done;
            }
            ASSERT(outputBuffer);
        } else {
            status = STATUS_NDIS_INVALID_LENGTH;
            goto done;
        }
        inputBuffer = NULL;
        inputBufferLen = 0;

        ovsMsg = &ovsMsgReadOp;
        RtlZeroMemory(ovsMsg, sizeof *ovsMsg);
        ovsMsg->nlMsg.nlmsgLen = sizeof *ovsMsg;
        ovsMsg->nlMsg.nlmsgType = nlControlFamilyOps.id;
        ovsMsg->nlMsg.nlmsgPid = instance->pid;

        /* An "artificial" command so we can use NL family function table*/
        ovsMsg->genlMsg.cmd = (code == OVS_IOCTL_READ_EVENT) ?
                              OVS_CTRL_CMD_EVENT_NOTIFY :
                              OVS_CTRL_CMD_READ_NOTIFY;
        ovsMsg->genlMsg.version = nlControlFamilyOps.version;

        devOp = OVS_READ_DEV_OP;
        break;

    case OVS_IOCTL_READ:
        /* Output buffer is mandatory. */
        if (outputBufferLen != 0) {
            status = MapIrpOutputBuffer(irp, outputBufferLen,
                                        sizeof *ovsMsg, &outputBuffer);
            if (status != STATUS_SUCCESS) {
                goto done;
            }
            ASSERT(outputBuffer);
        } else {
            status = STATUS_NDIS_INVALID_LENGTH;
            goto done;
        }

        /*
         * Operate in the mode that read ioctl is similar to ReadFile(). This
         * might change as the userspace code gets implemented.
         */
        inputBuffer = NULL;
        inputBufferLen = 0;

        /*
         * For implementing read (ioctl or otherwise), we need to store some
         * state in the instance to indicate the command that started the dump
         * operation. The state can setup 'ovsMsgReadOp' appropriately. Note
         * that 'ovsMsgReadOp' is needed only in this function to call into the
         * appropriate handler. The handler itself can access the state in the
         * instance.
         *
         * In the absence of a dump start, return 0 bytes.
         */
        if (instance->dumpState.ovsMsg == NULL) {
            replyLen = 0;
            status = STATUS_SUCCESS;
            goto done;
        }
        RtlCopyMemory(&ovsMsgReadOp, instance->dumpState.ovsMsg,
                      sizeof (ovsMsgReadOp));

        /* Create an NL message for consumption. */
        ovsMsg = &ovsMsgReadOp;
        devOp = OVS_READ_DEV_OP;

        break;

    case OVS_IOCTL_WRITE:
        /* Input buffer is mandatory. */
        if (inputBufferLen < sizeof (*ovsMsg)) {
            status = STATUS_NDIS_INVALID_LENGTH;
            goto done;
        }

        ovsMsg = inputBuffer;
        devOp = OVS_WRITE_DEV_OP;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

    ASSERT(ovsMsg);
    switch (ovsMsg->nlMsg.nlmsgType) {
    case OVS_WIN_NL_CTRL_FAMILY_ID:
        nlFamilyOps = &nlControlFamilyOps;
        break;
    case OVS_WIN_NL_DATAPATH_FAMILY_ID:
        nlFamilyOps = &nlDatapathFamilyOps;
        break;
    case OVS_WIN_NL_FLOW_FAMILY_ID:
         nlFamilyOps = &nlFLowFamilyOps;
         break;
    case OVS_WIN_NL_PACKET_FAMILY_ID:
         nlFamilyOps = &nlPacketFamilyOps;
         break;
    case OVS_WIN_NL_VPORT_FAMILY_ID:
        nlFamilyOps = &nlVportFamilyOps;
        break;
    case OVS_WIN_NL_NETDEV_FAMILY_ID:
        nlFamilyOps = &nlNetdevFamilyOps;
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    /*
     * For read operation, avoid duplicate validation since 'ovsMsg' is either
     * "artificial" or was copied from a previously validated 'ovsMsg'.
     */
    if (devOp != OVS_READ_DEV_OP) {
        status = ValidateNetlinkCmd(devOp, instance, ovsMsg, nlFamilyOps);
        if (status != STATUS_SUCCESS) {
            goto done;
        }
    }

    InitUserParamsCtx(irp, instance, devOp, ovsMsg,
                      inputBuffer, inputBufferLen,
                      outputBuffer, outputBufferLen,
                      &usrParamsCtx);

    status = InvokeNetlinkCmdHandler(&usrParamsCtx, nlFamilyOps, &replyLen);

done:
    OvsReleaseSwitchContext(gOvsSwitchContext);

exit:
    /* Should not complete a pending IRP unless proceesing is completed. */
    if (status == STATUS_PENDING) {
        /* STATUS_PENDING is returned by the NL handler when the request is
         * to be processed later, so we mark the IRP as pending and complete
         * it in another thread when the request is processed. */
        IoMarkIrpPending(irp);
    }
    return OvsCompleteIrpRequest(irp, (ULONG_PTR)replyLen, status);
}


/*
 * --------------------------------------------------------------------------
 * Function to validate a netlink command. Only certain combinations of
 * (device operation, netlink family, command) are valid.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
ValidateNetlinkCmd(UINT32 devOp,
                   POVS_OPEN_INSTANCE instance,
                   POVS_MESSAGE ovsMsg,
                   NETLINK_FAMILY *nlFamilyOps)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    UINT16 i;

    for (i = 0; i < nlFamilyOps->opsCount; i++) {
        if (nlFamilyOps->cmds[i].cmd == ovsMsg->genlMsg.cmd) {
            /* Validate if the command is valid for the device operation. */
            if ((devOp & nlFamilyOps->cmds[i].supportedDevOp) == 0) {
                status = STATUS_INVALID_PARAMETER;
                goto done;
            }

            /* Validate the version. */
            if (nlFamilyOps->version > ovsMsg->genlMsg.version) {
                status = STATUS_INVALID_PARAMETER;
                goto done;
            }

            /* Validate the DP for commands that require a DP. */
            if (nlFamilyOps->cmds[i].validateDpIndex == TRUE) {
                if (ovsMsg->ovsHdr.dp_ifindex !=
                                          (INT)gOvsSwitchContext->dpNo) {
                    status = STATUS_INVALID_PARAMETER;
                    goto done;
                }
            }

            /* Validate the PID. */
            if (ovsMsg->nlMsg.nlmsgPid != instance->pid) {
                status = STATUS_INVALID_PARAMETER;
                goto done;
            }

            status = STATUS_SUCCESS;
            break;
        }
    }

done:
    return status;
}

/*
 * --------------------------------------------------------------------------
 * Function to invoke the netlink command handler. The function also stores
 * the return value of the handler function to construct a 'NL_ERROR' message,
 * and in turn returns success to the caller.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
InvokeNetlinkCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                        NETLINK_FAMILY *nlFamilyOps,
                        UINT32 *replyLen)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    UINT16 i;

    for (i = 0; i < nlFamilyOps->opsCount; i++) {
        if (nlFamilyOps->cmds[i].cmd == usrParamsCtx->ovsMsg->genlMsg.cmd) {
            NetlinkCmdHandler *handler = nlFamilyOps->cmds[i].handler;
            ASSERT(handler);
            if (handler) {
                status = handler(usrParamsCtx, replyLen);
            }
            break;
        }
    }

    /*
     * Netlink socket semantics dictate that the return value of the netlink
     * function should be an error ONLY under fatal conditions. If the message
     * made it all the way to the handler function, it is not a fatal condition.
     * Absorb the error returned by the handler function into a 'struct
     * NL_ERROR' and populate the 'output buffer' to return to userspace.
     *
     * This behavior is obviously applicable only to netlink commands that
     * specify an 'output buffer'. For other commands, we return the error as
     * is.
     *
     * 'STATUS_PENDING' is a special return value and userspace is equipped to
     * handle it.
     */
    if (status != STATUS_SUCCESS && status != STATUS_PENDING) {
        if (usrParamsCtx->devOp != OVS_WRITE_DEV_OP && *replyLen == 0) {
            NL_ERROR nlError = NlMapStatusToNlErr(status);
            POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
            POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
                usrParamsCtx->outputBuffer;

            ASSERT(msgError);
            NlBuildErrorMsg(msgIn, msgError, nlError);
            *replyLen = msgError->nlMsg.nlmsgLen;
        }

        if (*replyLen != 0) {
            status = STATUS_SUCCESS;
        }
    }

#ifdef DBG
    if (usrParamsCtx->devOp != OVS_WRITE_DEV_OP) {
        ASSERT(status == STATUS_PENDING || *replyLen != 0 || status == STATUS_SUCCESS);
    }
#endif

    return status;
}

/*
 * --------------------------------------------------------------------------
 *  Handler for 'OVS_IOCTL_GET_PID'.
 *
 *  Each handle on the device is assigned a unique PID when the handle is
 *  created. This function passes the PID to userspace using METHOD_BUFFERED
 *  method.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsGetPidHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                 UINT32 *replyLen)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUINT32 msgOut = (PUINT32)usrParamsCtx->outputBuffer;

    if (usrParamsCtx->outputLength >= sizeof *msgOut) {
        POVS_OPEN_INSTANCE instance =
            (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;

        RtlZeroMemory(msgOut, sizeof *msgOut);
        RtlCopyMemory(msgOut, &instance->pid, sizeof(*msgOut));
        *replyLen = sizeof *msgOut;
    } else {
        *replyLen = sizeof *msgOut;
        status = STATUS_NDIS_INVALID_LENGTH;
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * Utility function to fill up information about the datapath in a reply to
 * userspace.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsDpFillInfo(POVS_SWITCH_CONTEXT ovsSwitchContext,
              POVS_MESSAGE msgIn,
              PNL_BUFFER nlBuf)
{
    BOOLEAN writeOk;
    OVS_MESSAGE msgOutTmp;
    OVS_DATAPATH *datapath = &ovsSwitchContext->datapath;
    PNL_MSG_HDR nlMsg;

    ASSERT(NlBufAt(nlBuf, 0, 0) != 0 && NlBufRemLen(nlBuf) >= sizeof *msgIn);

    msgOutTmp.nlMsg.nlmsgType = OVS_WIN_NL_DATAPATH_FAMILY_ID;
    msgOutTmp.nlMsg.nlmsgFlags = 0;  /* XXX: ? */
    msgOutTmp.nlMsg.nlmsgSeq = msgIn->nlMsg.nlmsgSeq;
    msgOutTmp.nlMsg.nlmsgPid = msgIn->nlMsg.nlmsgPid;

    msgOutTmp.genlMsg.cmd = OVS_DP_CMD_GET;
    msgOutTmp.genlMsg.version = nlDatapathFamilyOps.version;
    msgOutTmp.genlMsg.reserved = 0;

    msgOutTmp.ovsHdr.dp_ifindex = ovsSwitchContext->dpNo;

    writeOk = NlMsgPutHead(nlBuf, (PCHAR)&msgOutTmp, sizeof msgOutTmp);
    if (writeOk) {
        writeOk = NlMsgPutTailString(nlBuf, OVS_DP_ATTR_NAME,
                                     OVS_SYSTEM_DP_NAME);
    }
    if (writeOk) {
        OVS_DP_STATS dpStats;

        dpStats.n_hit = datapath->hits;
        dpStats.n_missed = datapath->misses;
        dpStats.n_lost = datapath->lost;
        dpStats.n_flows = datapath->nFlows;
        writeOk = NlMsgPutTailUnspec(nlBuf, OVS_DP_ATTR_STATS,
                                     (PCHAR)&dpStats, sizeof dpStats);
    }
    nlMsg = (PNL_MSG_HDR)NlBufAt(nlBuf, 0, 0);
    nlMsg->nlmsgLen = NlBufSize(nlBuf);

    return writeOk ? STATUS_SUCCESS : STATUS_INVALID_BUFFER_SIZE;
}

/*
 * --------------------------------------------------------------------------
 * Handler for queueing an IRP used for event notification. The IRP is
 * completed when a port state changes. STATUS_PENDING is returned on
 * success. User mode keep a pending IRP at all times.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsPendEventCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                       UINT32 *replyLen)
{
    NDIS_STATUS status;

    UNREFERENCED_PARAMETER(replyLen);

    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    OVS_EVENT_POLL poll;

    poll.dpNo = msgIn->ovsHdr.dp_ifindex;
    status = OvsWaitEventIoctl(usrParamsCtx->irp, instance->fileObject,
                               &poll, sizeof poll);
    return status;
}

/*
 * --------------------------------------------------------------------------
 *  Handler for the subscription for the event queue
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsSubscribeEventCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                            UINT32 *replyLen)
{
    NDIS_STATUS status;
    OVS_EVENT_SUBSCRIBE request;
    BOOLEAN rc;
    UINT8 join;
    PNL_ATTR attrs[2];
    const NL_POLICY policy[] =  {
        [OVS_NL_ATTR_MCAST_GRP] = {.type = NL_A_U32 },
        [OVS_NL_ATTR_MCAST_JOIN] = {.type = NL_A_U8 },
        };

    UNREFERENCED_PARAMETER(replyLen);

    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;

    rc = NlAttrParse(&msgIn->nlMsg, sizeof (*msgIn),
         NlMsgAttrsLen((PNL_MSG_HDR)msgIn), policy, attrs, ARRAY_SIZE(attrs));
    if (!rc) {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    /* XXX Ignore the MC group for now */
    join = NlAttrGetU8(attrs[OVS_NL_ATTR_MCAST_JOIN]);
    request.dpNo = msgIn->ovsHdr.dp_ifindex;
    request.subscribe = join;
    request.mask = OVS_EVENT_MASK_ALL;

    status = OvsSubscribeEventIoctl(instance->fileObject, &request,
                                    sizeof request);
done:
    return status;
}

/*
 * --------------------------------------------------------------------------
 *  Command Handler for 'OVS_DP_CMD_NEW'.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsNewDpCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                   UINT32 *replyLen)
{
    return HandleDpTransactionCommon(usrParamsCtx, replyLen);
}

/*
 * --------------------------------------------------------------------------
 *  Command Handler for 'OVS_DP_CMD_GET'.
 *
 *  The function handles both the dump based as well as the transaction based
 *  'OVS_DP_CMD_GET' command. In the dump command, it handles the initial
 *  call to setup dump state, as well as subsequent calls to continue dumping
 *  data.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsGetDpCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                   UINT32 *replyLen)
{
    if (usrParamsCtx->devOp == OVS_TRANSACTION_DEV_OP) {
        return HandleDpTransactionCommon(usrParamsCtx, replyLen);
    } else {
        return HandleGetDpDump(usrParamsCtx, replyLen);
    }
}

/*
 * --------------------------------------------------------------------------
 *  Function for handling the transaction based 'OVS_DP_CMD_GET' command.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
HandleGetDpTransaction(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                       UINT32 *replyLen)
{
    return HandleDpTransactionCommon(usrParamsCtx, replyLen);
}


/*
 * --------------------------------------------------------------------------
 *  Function for handling the dump-based 'OVS_DP_CMD_GET' command.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
HandleGetDpDump(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                UINT32 *replyLen)
{
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;

    if (usrParamsCtx->devOp == OVS_WRITE_DEV_OP) {
        *replyLen = 0;
        OvsSetupDumpStart(usrParamsCtx);
    } else {
        NL_BUFFER nlBuf;
        NTSTATUS status;
        POVS_MESSAGE msgIn = instance->dumpState.ovsMsg;

        ASSERT(usrParamsCtx->devOp == OVS_READ_DEV_OP);

        if (instance->dumpState.ovsMsg == NULL) {
            ASSERT(FALSE);
            return STATUS_INVALID_DEVICE_STATE;
        }

        /* Dump state must have been deleted after previous dump operation. */
        ASSERT(instance->dumpState.index[0] == 0);

        /* Output buffer has been validated while validating read dev op. */
        ASSERT(msgOut != NULL && usrParamsCtx->outputLength >= sizeof *msgOut);

        NlBufInit(&nlBuf, usrParamsCtx->outputBuffer,
                  usrParamsCtx->outputLength);

        status = OvsDpFillInfo(gOvsSwitchContext, msgIn, &nlBuf);

        if (status != STATUS_SUCCESS) {
            *replyLen = 0;
            FreeUserDumpState(instance);
            return status;
        }

        /* Increment the dump index. */
        instance->dumpState.index[0] = 1;
        *replyLen = msgOut->nlMsg.nlmsgLen;

        /* Free up the dump state, since there's no more data to continue. */
        FreeUserDumpState(instance);
    }

    return STATUS_SUCCESS;
}


/*
 * --------------------------------------------------------------------------
 *  Command Handler for 'OVS_DP_CMD_SET'.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsSetDpCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                   UINT32 *replyLen)
{
    return HandleDpTransactionCommon(usrParamsCtx, replyLen);
}

/*
 * --------------------------------------------------------------------------
 *  Function for handling transaction based 'OVS_DP_CMD_NEW', 'OVS_DP_CMD_GET'
 *  and 'OVS_DP_CMD_SET' commands.
 *
 * 'OVS_DP_CMD_NEW' is implemented to keep userspace code happy. Creation of a
 * new datapath is not supported currently.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
HandleDpTransactionCommon(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                          UINT32 *replyLen)
{
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    NL_BUFFER nlBuf;
    NL_ERROR nlError = NL_ERROR_SUCCESS;
    static const NL_POLICY ovsDatapathSetPolicy[] = {
        [OVS_DP_ATTR_NAME] = { .type = NL_A_STRING, .maxLen = IFNAMSIZ },
        [OVS_DP_ATTR_UPCALL_PID] = { .type = NL_A_U32, .optional = TRUE },
        [OVS_DP_ATTR_USER_FEATURES] = { .type = NL_A_U32, .optional = TRUE },
    };
    PNL_ATTR dpAttrs[ARRAY_SIZE(ovsDatapathSetPolicy)];

    UNREFERENCED_PARAMETER(msgOut);

    /* input buffer has been validated while validating write dev op. */
    ASSERT(msgIn != NULL && usrParamsCtx->inputLength >= sizeof *msgIn);

    /* Parse any attributes in the request. */
    if (usrParamsCtx->ovsMsg->genlMsg.cmd == OVS_DP_CMD_SET ||
        usrParamsCtx->ovsMsg->genlMsg.cmd == OVS_DP_CMD_NEW) {
        if (!NlAttrParse((PNL_MSG_HDR)msgIn,
                        NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN,
                        NlMsgAttrsLen((PNL_MSG_HDR)msgIn),
                        ovsDatapathSetPolicy, dpAttrs, ARRAY_SIZE(dpAttrs))) {
            return STATUS_INVALID_PARAMETER;
        }

        /*
        * XXX: Not clear at this stage if there's any role for the
        * OVS_DP_ATTR_UPCALL_PID and OVS_DP_ATTR_USER_FEATURES attributes passed
        * from userspace.
        */

    } else {
        RtlZeroMemory(dpAttrs, sizeof dpAttrs);
    }

    /* Output buffer has been validated while validating transact dev op. */
    ASSERT(msgOut != NULL && usrParamsCtx->outputLength >= sizeof *msgOut);

    NlBufInit(&nlBuf, usrParamsCtx->outputBuffer, usrParamsCtx->outputLength);

    if (dpAttrs[OVS_DP_ATTR_NAME] != NULL) {
        if (!OvsCompareString(NlAttrGet(dpAttrs[OVS_DP_ATTR_NAME]),
                              OVS_SYSTEM_DP_NAME)) {

            /* Creation of new datapaths is not supported. */
            if (usrParamsCtx->ovsMsg->genlMsg.cmd == OVS_DP_CMD_SET) {
                nlError = NL_ERROR_NOTSUPP;
                goto cleanup;
            }

            nlError = NL_ERROR_NODEV;
            goto cleanup;
        }
    } else if ((UINT32)msgIn->ovsHdr.dp_ifindex != gOvsSwitchContext->dpNo) {
        nlError = NL_ERROR_NODEV;
        goto cleanup;
    }

    if (usrParamsCtx->ovsMsg->genlMsg.cmd == OVS_DP_CMD_NEW) {
        nlError = NL_ERROR_EXIST;
        goto cleanup;
    }

    status = OvsDpFillInfo(gOvsSwitchContext, msgIn, &nlBuf);

    *replyLen = NlBufSize(&nlBuf);

cleanup:
    if (nlError != NL_ERROR_SUCCESS) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
            usrParamsCtx->outputBuffer;

        NlBuildErrorMsg(msgIn, msgError, nlError);
        *replyLen = msgError->nlMsg.nlmsgLen;
    }

    return STATUS_SUCCESS;
}


NTSTATUS
OvsSetupDumpStart(POVS_USER_PARAMS_CONTEXT usrParamsCtx)
{
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;

    /* input buffer has been validated while validating write dev op. */
    ASSERT(msgIn != NULL && usrParamsCtx->inputLength >= sizeof *msgIn);

    /* A write operation that does not indicate dump start is invalid. */
    if ((msgIn->nlMsg.nlmsgFlags & NLM_F_DUMP) != NLM_F_DUMP) {
        return STATUS_INVALID_PARAMETER;
    }
    /* XXX: Handle other NLM_F_* flags in the future. */

    /*
     * This operation should be setting up the dump state. If there's any
     * previous state, clear it up so as to set it up afresh.
     */
    FreeUserDumpState(instance);

    return InitUserDumpState(instance, msgIn);
}


/*
 * --------------------------------------------------------------------------
 *  Utility function to map the output buffer in an IRP. The buffer is assumed
 *  to have been passed down using METHOD_OUT_DIRECT (Direct I/O).
 * --------------------------------------------------------------------------
 */
static NTSTATUS
MapIrpOutputBuffer(PIRP irp,
                   UINT32 bufferLength,
                   UINT32 requiredLength,
                   PVOID *buffer)
{
    ASSERT(irp);
    ASSERT(buffer);
    ASSERT(bufferLength);
    ASSERT(requiredLength);
    if (!buffer || !irp || bufferLength == 0 || requiredLength == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (bufferLength < requiredLength) {
        return STATUS_NDIS_INVALID_LENGTH;
    }
    if (irp->MdlAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *buffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
                                           NormalPagePriority);
    if (*buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * Utility function to fill up information about the state of a port in a reply
 * to* userspace.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsPortFillInfo(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                POVS_EVENT_ENTRY eventEntry,
                PNL_BUFFER nlBuf)
{
    NTSTATUS status;
    BOOLEAN ok;
    OVS_MESSAGE msgOutTmp;
    PNL_MSG_HDR nlMsg;
    POVS_VPORT_ENTRY vport;

    ASSERT(NlBufAt(nlBuf, 0, 0) != 0 && nlBuf->bufRemLen >= sizeof msgOutTmp);

    msgOutTmp.nlMsg.nlmsgType = OVS_WIN_NL_VPORT_FAMILY_ID;
    msgOutTmp.nlMsg.nlmsgFlags = 0;  /* XXX: ? */

    /* driver intiated messages should have zerp seq number*/
    msgOutTmp.nlMsg.nlmsgSeq = 0;
    msgOutTmp.nlMsg.nlmsgPid = usrParamsCtx->ovsInstance->pid;

    msgOutTmp.genlMsg.version = nlVportFamilyOps.version;
    msgOutTmp.genlMsg.reserved = 0;

    /* we don't have netdev yet, treat link up/down a adding/removing a port*/
    if (eventEntry->status & (OVS_EVENT_LINK_UP | OVS_EVENT_CONNECT)) {
        msgOutTmp.genlMsg.cmd = OVS_VPORT_CMD_NEW;
    } else if (eventEntry->status &
             (OVS_EVENT_LINK_DOWN | OVS_EVENT_DISCONNECT)) {
        msgOutTmp.genlMsg.cmd = OVS_VPORT_CMD_DEL;
    } else {
        ASSERT(FALSE);
        return STATUS_UNSUCCESSFUL;
    }
    msgOutTmp.ovsHdr.dp_ifindex = gOvsSwitchContext->dpNo;

    ok = NlMsgPutHead(nlBuf, (PCHAR)&msgOutTmp, sizeof msgOutTmp);
    if (!ok) {
        status = STATUS_INVALID_BUFFER_SIZE;
        goto cleanup;
    }

    vport = OvsFindVportByPortNo(gOvsSwitchContext, eventEntry->portNo);
    if (!vport) {
        status = STATUS_DEVICE_DOES_NOT_EXIST;
        goto cleanup;
    }

    ok = NlMsgPutTailU32(nlBuf, OVS_VPORT_ATTR_PORT_NO, eventEntry->portNo) &&
         NlMsgPutTailU32(nlBuf, OVS_VPORT_ATTR_TYPE, vport->ovsType) &&
         NlMsgPutTailU32(nlBuf, OVS_VPORT_ATTR_UPCALL_PID,
                         vport->upcallPid) &&
         NlMsgPutTailString(nlBuf, OVS_VPORT_ATTR_NAME, vport->ovsName);
    if (!ok) {
        status = STATUS_INVALID_BUFFER_SIZE;
        goto cleanup;
    }

    /* XXXX Should we add the port stats attributes?*/
    nlMsg = (PNL_MSG_HDR)NlBufAt(nlBuf, 0, 0);
    nlMsg->nlmsgLen = NlBufSize(nlBuf);
    status = STATUS_SUCCESS;

cleanup:
    return status;
}


/*
 * --------------------------------------------------------------------------
 * Handler for reading events from the driver event queue. This handler is
 * executed when user modes issues a socket receive on a socket assocaited
 * with the MC group for events.
 * XXX user mode should read multiple events in one system call
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsReadEventCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                       UINT32 *replyLen)
{
#ifdef DBG
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;
#endif
    NL_BUFFER nlBuf;
    NTSTATUS status;
    OVS_EVENT_ENTRY eventEntry;

    ASSERT(usrParamsCtx->devOp == OVS_READ_DEV_OP);

    /* Should never read events with a dump socket */
    ASSERT(instance->dumpState.ovsMsg == NULL);

    /* Must have an event queue */
    ASSERT(instance->eventQueue != NULL);

    /* Output buffer has been validated while validating read dev op. */
    ASSERT(msgOut != NULL && usrParamsCtx->outputLength >= sizeof *msgOut);

    NlBufInit(&nlBuf, usrParamsCtx->outputBuffer, usrParamsCtx->outputLength);

    /* remove an event entry from the event queue */
    status = OvsRemoveEventEntry(usrParamsCtx->ovsInstance, &eventEntry);
    if (status != STATUS_SUCCESS) {
        /* If there were not elements, read should return no data. */
        status = STATUS_SUCCESS;
        *replyLen = 0;
        goto cleanup;
    }

    status = OvsPortFillInfo(usrParamsCtx, &eventEntry, &nlBuf);
    if (status == NDIS_STATUS_SUCCESS) {
        *replyLen = NlBufSize(&nlBuf);
    }

cleanup:
    return status;
}

/*
 * --------------------------------------------------------------------------
 * Handler for reading missed pacckets from the driver event queue. This
 * handler is executed when user modes issues a socket receive on a socket
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsReadPacketCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                       UINT32 *replyLen)
{
#ifdef DBG
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
#endif
    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;
    NTSTATUS status;

    ASSERT(usrParamsCtx->devOp == OVS_READ_DEV_OP);

    /* Should never read events with a dump socket */
    ASSERT(instance->dumpState.ovsMsg == NULL);

    /* Must have an packet queue */
    ASSERT(instance->packetQueue != NULL);

    /* Output buffer has been validated while validating read dev op. */
    ASSERT(msgOut != NULL && usrParamsCtx->outputLength >= sizeof *msgOut);

    /* Read a packet from the instance queue */
    status = OvsReadDpIoctl(instance->fileObject, usrParamsCtx->outputBuffer,
                            usrParamsCtx->outputLength, replyLen);
    return status;
}

/*
 * --------------------------------------------------------------------------
 *  Handler for the subscription for a packet queue
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsSubscribePacketCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                            UINT32 *replyLen)
{
    NDIS_STATUS status;
    BOOLEAN rc;
    UINT8 join;
    UINT32 pid;
    const NL_POLICY policy[] =  {
        [OVS_NL_ATTR_PACKET_PID] = {.type = NL_A_U32 },
        [OVS_NL_ATTR_PACKET_SUBSCRIBE] = {.type = NL_A_U8 }
        };
    PNL_ATTR attrs[ARRAY_SIZE(policy)];

    UNREFERENCED_PARAMETER(replyLen);

    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;

    rc = NlAttrParse(&msgIn->nlMsg, sizeof (*msgIn),
         NlMsgAttrsLen((PNL_MSG_HDR)msgIn), policy, attrs, ARRAY_SIZE(attrs));
    if (!rc) {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    join = NlAttrGetU8(attrs[OVS_NL_ATTR_PACKET_PID]);
    pid = NlAttrGetU32(attrs[OVS_NL_ATTR_PACKET_PID]);

    /* The socket subscribed with must be the same socket we perform receive*/
    ASSERT(pid == instance->pid);

    status = OvsSubscribeDpIoctl(instance, pid, join);

    /*
     * XXX Need to add this instance to a global data structure
     * which hold all packet based instances. The data structure (hash)
     * should be searched through the pid field of the instance for
     * placing the missed packet into the correct queue
     */
done:
    return status;
}

/*
 * --------------------------------------------------------------------------
 * Handler for queueing an IRP used for missed packet notification. The IRP is
 * completed when a packet received and mismatched. STATUS_PENDING is returned
 * on success. User mode keep a pending IRP at all times.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsPendPacketCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                       UINT32 *replyLen)
{
    UNREFERENCED_PARAMETER(replyLen);

    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;

    /*
     * XXX access to packet queue must be through acquiring a lock as user mode
     * could unsubscribe and the instnace will be freed.
     */
    return OvsWaitDpIoctl(usrParamsCtx->irp, instance->fileObject);
}
