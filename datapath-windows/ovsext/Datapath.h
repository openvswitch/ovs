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

#ifndef __DATAPATH_H_
#define __DATAPATH_H_ 1

/*
 * Device operations to tag netlink commands with. This is a bitmask since it
 * is possible that a particular command can be invoked via different device
 * operations.
 */
#define OVS_READ_DEV_OP          (1 << 0)
#define OVS_WRITE_DEV_OP         (1 << 1)
#define OVS_TRANSACTION_DEV_OP   (1 << 2)

typedef struct _OVS_DEVICE_EXTENSION {
    INT numberOpenInstance;
    INT pidCount;
} OVS_DEVICE_EXTENSION, *POVS_DEVICE_EXTENSION;

// forward declaration
typedef struct _OVS_USER_PACKET_QUEUE OVS_USER_PACKET_QUEUE,
                                      *POVS_USER_PACKET_QUEUE;

/*
 * Private context for each handle on the device.
 */
typedef struct _OVS_OPEN_INSTANCE {
    UINT32 cookie;
    PFILE_OBJECT fileObject;
    PVOID eventQueue;
    POVS_USER_PACKET_QUEUE packetQueue;
    UINT32 pid;

    struct {
        POVS_MESSAGE ovsMsg;    /* OVS message passed during dump start. */
        UINT32 index[2];        /* markers to continue dump from. One or more
                                 * of them may be used. Eg. in flow dump, the
                                 * markers can store the row and the column
                                 * indices. */
    } dumpState;                /* data to support dump commands. */
    LIST_ENTRY             pidLink; /* Links the instance to
                                     * pidHashArray */
} OVS_OPEN_INSTANCE, *POVS_OPEN_INSTANCE;

NDIS_STATUS OvsCreateDeviceObject(NDIS_HANDLE ovsExtDriverHandle);
VOID OvsDeleteDeviceObject();
VOID OvsInit();
VOID OvsCleanup();

POVS_OPEN_INSTANCE OvsGetOpenInstance(PFILE_OBJECT fileObject,
                                      UINT32 dpNo);

NTSTATUS OvsCompleteIrpRequest(PIRP irp, ULONG_PTR infoPtr, NTSTATUS status);

VOID OvsAcquireCtrlLock();
VOID OvsReleaseCtrlLock();

/*
 * Utility structure and functions to collect in one place all the parameters
 * passed during a call from userspace.
 */
typedef struct _OVS_USER_PARAMS_CONTEXT {
    PIRP irp;            /* The IRP used for the userspace call. */
    POVS_OPEN_INSTANCE ovsInstance; /* Private data of the device handle. */
    UINT32 devOp;        /* Device operation of the userspace call. */
    POVS_MESSAGE ovsMsg; /* OVS message that userspace passed down. */
    PVOID inputBuffer;   /* Input data specified by userspace. Maybe NULL. */
    UINT32 inputLength;  /* Length of input buffer. */
    PVOID outputBuffer;  /* Output buffer specified by userspace for reading
                          * data. Maybe NULL. */
    UINT32 outputLength; /* Length of output buffer. */
} OVS_USER_PARAMS_CONTEXT, *POVS_USER_PARAMS_CONTEXT;

static __inline VOID
InitUserParamsCtx(PIRP irp,
                  POVS_OPEN_INSTANCE ovsInstance,
                  UINT32 devOp,
                  POVS_MESSAGE ovsMsg,
                  PVOID inputBuffer,
                  UINT32 inputLength,
                  PVOID outputBuffer,
                  UINT32 outputLength,
                  POVS_USER_PARAMS_CONTEXT usrParamsCtx)
{
    usrParamsCtx->irp = irp;
    usrParamsCtx->ovsInstance = ovsInstance;
    usrParamsCtx->devOp = devOp;
    usrParamsCtx->ovsMsg = ovsMsg;
    usrParamsCtx->inputBuffer = inputBuffer;
    usrParamsCtx->inputLength = inputLength;
    usrParamsCtx->outputBuffer = outputBuffer;
    usrParamsCtx->outputLength = outputLength;
}

NTSTATUS InitUserDumpState(POVS_OPEN_INSTANCE instance,
                           POVS_MESSAGE ovsMsg);

VOID FreeUserDumpState(POVS_OPEN_INSTANCE instance);

NTSTATUS OvsSetupDumpStart(POVS_USER_PARAMS_CONTEXT usrParamsCtx);

#endif /* __DATAPATH_H_ */
