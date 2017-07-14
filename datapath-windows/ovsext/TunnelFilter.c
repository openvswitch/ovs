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

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union
#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_TUNFLT
#include "Debug.h"


#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>
#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>

#include "Tunnel.h"
#include "Switch.h"
#include "Vport.h"
#include "Event.h"
#include "User.h"
#include "Vxlan.h"


#define INITGUID
#include <guiddef.h>

/* Infinite timeout */
#define INFINITE                        0xFFFFFFFF

/* The provider name should always match the provider string from the install
 * file. */
#define OVS_TUNNEL_PROVIDER_NAME        L"The Linux Foundation (R)"

/* The provider description should always contain the OVS service description
 * string from the install file. */
#define OVS_TUNNEL_PROVIDER_DESC        L"Open vSwitch Extension tunnel provider"

/* The session name isn't required but it's useful for diagnostics. */
#define OVS_TUNNEL_SESSION_NAME         L"OVS tunnel session"

/* Maximum number of tunnel threads to be created. */
#define OVS_TUNFLT_MAX_THREADS          8

/*
 * Callout and sublayer GUIDs
 */

/* b16b0a6e-2b2a-41a3-8b39-bd3ffc855ff8 */
DEFINE_GUID(
    OVS_TUNNEL_CALLOUT_V4,
    0xb16b0a6e,
    0x2b2a,
    0x41a3,
    0x8b, 0x39, 0xbd, 0x3f, 0xfc, 0x85, 0x5f, 0xf8
    );

/* 0104fd7e-c825-414e-94c9-f0d525bbc169 */
DEFINE_GUID(
    OVS_TUNNEL_SUBLAYER,
    0x0104fd7e,
    0xc825,
    0x414e,
    0x94, 0xc9, 0xf0, 0xd5, 0x25, 0xbb, 0xc1, 0x69
    );

/* 6fc957d7-14e7-47c7-812b-4668be994ba1 */
DEFINE_GUID(
    OVS_TUNNEL_PROVIDER_KEY,
    0x6fc957d7,
    0x14e7,
    0x47c7,
    0x81, 0x2b, 0x46, 0x68, 0xbe, 0x99, 0x4b, 0xa1
    );

/* bfd4814c-9650-4de3-a536-1eedb9e9ba6a */
DEFINE_GUID(
    OVS_TUNNEL_FILTER_KEY,
    0xbfd4814c,
    0x9650,
    0x4de3,
    0xa5, 0x36, 0x1e, 0xed, 0xb9, 0xe9, 0xba, 0x6a
    );

/*
 * Callout driver type definitions
 */
typedef enum _OVS_TUNFLT_OPERATION {
    OVS_TUN_FILTER_CREATE = 0,
    OVS_TUN_FILTER_DELETE
} OVS_TUNFLT_OPERATION;

typedef struct _OVS_TUNFLT_REQUEST {
    LIST_ENTRY              entry;
    /* Tunnel filter destination port. */
    UINT16                  port;
    /* XXX: We also need to specify the tunnel L4 protocol, because there are
     * different protocols that can use the same destination port.*/
    union {
        /* Tunnel filter identification used for filter deletion. */
        UINT64                  delID;
        /* Pointer used to return filter ID to the caller on filter creation. */
        PUINT64                 addID;
    } filterID;
    /* Requested operation to be performed. */
    OVS_TUNFLT_OPERATION    operation;
    /* Current I/O request to be completed when requested
     * operation is finished. */
    PIRP                    irp;
    /* Callback function called before completing the IRP. */
    PFNTunnelVportPendingOp callback;
    /* Context passed to the callback function. */
    PVOID                   context;
} OVS_TUNFLT_REQUEST, *POVS_TUNFLT_REQUEST;

typedef struct _OVS_TUNFLT_REQUEST_LIST {
    /* SpinLock for syncronizing access to the requests list. */
    NDIS_SPIN_LOCK spinlock;
    /* Head of the requests list. */
    LIST_ENTRY     head;
    /* Number of requests in the list. This variable is used by
     * InterlockedCompareExchange function and needs to be aligned
     * at 32-bit boundaries. */
    UINT32         numEntries;
} OVS_TUNFLT_REQUEST_LIST, *POVS_TUNFLT_REQUEST_LIST;

typedef struct _OVS_TUNFLT_THREAD_CONTEXT {
    /* Thread identification. */
    UINT                    threadID;
    /* Thread initialization flag. */
    UINT32                  isInitialized;
    /* Thread's engine session handle. */
    HANDLE                  engineSession;
    /* Reference of the thread object. */
    PVOID                   threadObject;
    /* Requests queue list. */
    OVS_TUNFLT_REQUEST_LIST listRequests;
    /* Event signaling that there are requests to process. */
    KEVENT                  requestEvent;
    /* Event for stopping thread execution. */
    KEVENT                  stopEvent;
} OVS_TUNFLT_THREAD_CONTEXT, *POVS_TUNFLT_THREAD_CONTEXT;

KSTART_ROUTINE  OvsTunnelFilterThreadProc;

static NTSTATUS OvsTunnelFilterStartThreads();
static NTSTATUS OvsTunnelFilterThreadStart(POVS_TUNFLT_THREAD_CONTEXT threadCtx);
static VOID     OvsTunnelFilterStopThreads();
static VOID     OvsTunnelFilterThreadStop(POVS_TUNFLT_THREAD_CONTEXT threadCtx,
                                          BOOLEAN signalEvent);
static NTSTATUS OvsTunnelFilterThreadInit(POVS_TUNFLT_THREAD_CONTEXT threadCtx);
static VOID     OvsTunnelFilterThreadUninit(POVS_TUNFLT_THREAD_CONTEXT threadCtx);
static VOID     OvsTunnelFilterSetIrpContext(POVS_TUNFLT_REQUEST_LIST listRequests,
                                             POVS_TUNFLT_REQUEST request);
DRIVER_CANCEL   OvsTunnelFilterCancelIrp;

/*
 * Callout driver global variables
 */

/* Pointer to the device object that must be create before we can register our
 * callout to the base filtering engine. */
static PDEVICE_OBJECT            gDeviceObject = NULL;
/* Handle to an open session to the filter engine that is used for adding
 * tunnel's callout. */
static HANDLE                    gEngineHandle = NULL;
/* A pointer to the received handle that is associated with the registration of
 * the OvsTunnelProviderBfeCallback callback. */
static HANDLE                    gTunnelProviderBfeHandle = NULL;
/* A pointer to the received handle that is associated with the registration of
 * the OvsTunnelInitBfeCallback callback. */
static HANDLE                    gTunnelInitBfeHandle = NULL;
/* Runtime identifier for tunnel's callout which is retrieved at tunnel
 * initialization phase when the callout is registered. This ID is then used
 * for removing the callout object from the system at tunnel
 * uninitialization phase. */
static UINT32                    gCalloutIdV4 = 0;
/* Array used for storing tunnel thread's private data. */
static OVS_TUNFLT_THREAD_CONTEXT gTunnelThreadCtx[OVS_TUNFLT_MAX_THREADS] = { 0 };

/*
 * Callout driver implementation.
 */

NTSTATUS
OvsTunnelEngineOpen(HANDLE *engineSession)
{
    NTSTATUS status;
    FWPM_SESSION session = { 0 };

    /*
    * Set an infinite wait timeout, so we don't have to handle FWP_E_TIMEOUT
    * errors while waiting to acquire the transaction lock.
    */
    session.txnWaitTimeoutInMSec = INFINITE;

    /* The authentication service should always be RPC_C_AUTHN_DEFAULT. */
    status = FwpmEngineOpen(NULL,
                            RPC_C_AUTHN_DEFAULT,
                            NULL,
                            &session,
                            engineSession);
    if (!NT_SUCCESS(status)) {
        OVS_LOG_ERROR("Failed to open filtering engine session, status: %x.",
                      status);
    }

    return status;
}

VOID
OvsTunnelEngineClose(HANDLE *engineSession)
{
    if (*engineSession) {
        FwpmEngineClose(*engineSession);
        *engineSession = NULL;
    }
}

VOID
OvsTunnelAddSystemProvider(HANDLE engineSession)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN inTransaction = FALSE;
    FWPM_PROVIDER provider = { 0 };

    do {
        status = FwpmTransactionBegin(engineSession, 0);
        if (!NT_SUCCESS(status)) {
            break;
        }
        inTransaction = TRUE;

        memset(&provider, 0, sizeof(provider));
        provider.providerKey = OVS_TUNNEL_PROVIDER_KEY;
        provider.displayData.name = OVS_TUNNEL_PROVIDER_NAME;
        provider.displayData.description = OVS_TUNNEL_PROVIDER_DESC;
        /*
         * Since we always want the provider to be present, it's easiest to add
         * it as persistent object during driver load.
         */
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

        status = FwpmProviderAdd(engineSession,
                                 &provider,
                                 NULL);
        if (!NT_SUCCESS(status)) {
            if (STATUS_FWP_ALREADY_EXISTS != status) {
                OVS_LOG_ERROR("Failed to add WFP provider, status: %x.",
                              status);
                break;
            }
        }

        status = FwpmTransactionCommit(engineSession);
        if (!NT_SUCCESS(status)) {
            break;
        }

        inTransaction = FALSE;
    } while (inTransaction);

    if (inTransaction){
        FwpmTransactionAbort(engineSession);
    }
}

VOID
OvsTunnelRemoveSystemProvider(HANDLE engineSession)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN inTransaction = FALSE;

    do {
        status = FwpmTransactionBegin(engineSession, 0);
        if (!NT_SUCCESS(status)) {
            break;
        }
        inTransaction = TRUE;

        status = FwpmProviderDeleteByKey(engineSession,
                                         &OVS_TUNNEL_PROVIDER_KEY);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = FwpmTransactionCommit(engineSession);
        if (!NT_SUCCESS(status)) {
            break;
        }

        inTransaction = FALSE;
    } while (inTransaction);

    if (inTransaction){
        FwpmTransactionAbort(engineSession);
    }
}

NTSTATUS
OvsTunnelAddFilter(HANDLE engineSession,
                   PWSTR filterName,
                   const PWSTR filterDesc,
                   USHORT remotePort,
                   FWP_DIRECTION direction,
                   UINT64 context,
                   const GUID *filterKey,
                   const GUID *layerKey,
                   const GUID *calloutKey,
                   UINT64 *filterID)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_FILTER filter = {0};
    FWPM_FILTER_CONDITION filterConditions[3] = {0};
    UINT conditionIndex;

    if (filterKey) {
        filter.filterKey = *filterKey;
    }
    filter.layerKey = *layerKey;
    filter.displayData.name = (wchar_t*)filterName;
    filter.displayData.description = (wchar_t*)filterDesc;

    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = *calloutKey;
    filter.filterCondition = filterConditions;
    filter.subLayerKey = OVS_TUNNEL_SUBLAYER;
    filter.weight.type = FWP_EMPTY; // auto-weight.
    filter.rawContext = context;

    conditionIndex = 0;

    filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_DIRECTION;
    filterConditions[conditionIndex].matchType = FWP_MATCH_EQUAL;
    filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
    filterConditions[conditionIndex].conditionValue.uint32 = direction;

    conditionIndex++;

    filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    filterConditions[conditionIndex].matchType = FWP_MATCH_EQUAL;
    filterConditions[conditionIndex].conditionValue.type = FWP_UINT16;
    filterConditions[conditionIndex].conditionValue.uint16 = remotePort;

    conditionIndex++;

    filter.numFilterConditions = conditionIndex;

    status = FwpmFilterAdd(engineSession,
                           &filter,
                           NULL,
                           filterID);

    return status;
}

/*
 * --------------------------------------------------------------------------
 * This function registers callouts for intercepting UDP traffic at WFP
 * FWPM_LAYER_DATAGRAM_DATA_V4 layer.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsTunnelRegisterDatagramDataCallouts(const GUID *layerKey,
                                      const GUID *calloutKey,
                                      VOID *deviceObject,
                                      UINT32 *calloutId)
{
    NTSTATUS status;

    FWPS_CALLOUT sCallout = {0};
    FWPM_CALLOUT mCallout = {0};

    FWPM_DISPLAY_DATA displayData = {0};

    BOOLEAN calloutRegistered = FALSE;

    sCallout.calloutKey = *calloutKey;
    sCallout.classifyFn = OvsTunnelClassify;
    sCallout.notifyFn = OvsTunnelNotify;
#if FLOW_CONTEXT
    /* Currently we don't associate a context with the flow */
    sCallout.flowDeleteFn = OvsTunnelFlowDelete;
    sCallout.flags = FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW;
#endif

    status = FwpsCalloutRegister(deviceObject, &sCallout, calloutId);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    calloutRegistered = TRUE;

    displayData.name = L"Datagram-Data OVS Callout";
    displayData.description = L"Proxies destination address/port for UDP";

    mCallout.calloutKey = *calloutKey;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = *layerKey;

    status = FwpmCalloutAdd(gEngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        if (STATUS_FWP_ALREADY_EXISTS != status) {
            OVS_LOG_ERROR("Failed to add WFP callout, status: %x.",
                          status);
            goto Exit;
        }
        status = STATUS_SUCCESS;
    }

Exit:

    if (!NT_SUCCESS(status)){
        if (calloutRegistered) {
            FwpsCalloutUnregisterById(*calloutId);
            *calloutId = 0;
        }
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * This function registers non-dynamic callouts for intercepting UDP traffic.
 * Callouts will be removed during un-initializing phase.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsTunnelRegisterCallouts(VOID *deviceObject)
{
    NTSTATUS        status;
    BOOLEAN         inTransaction = FALSE;
    FWPM_SUBLAYER   OvsTunnelSubLayer;

    status = FwpmTransactionBegin(gEngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    inTransaction = TRUE;

    RtlZeroMemory(&OvsTunnelSubLayer, sizeof(FWPM_SUBLAYER));

    OvsTunnelSubLayer.subLayerKey = OVS_TUNNEL_SUBLAYER;
    OvsTunnelSubLayer.displayData.name = L"Datagram-Data OVS Sub-Layer";
    OvsTunnelSubLayer.displayData.description =
        L"Sub-Layer for use by Datagram-Data OVS callouts";
    OvsTunnelSubLayer.flags = 0;
    OvsTunnelSubLayer.weight = FWP_EMPTY; /* auto-weight */

    status = FwpmSubLayerAdd(gEngineHandle, &OvsTunnelSubLayer, NULL);
    if (!NT_SUCCESS(status)) {
        if (STATUS_FWP_ALREADY_EXISTS != status) {
            OVS_LOG_ERROR("Failed to add WFP sublayer, status: %x.",
                          status);
            goto Exit;
        }
    }

    /* In order to use this callout a socket must be opened. */
    status = OvsTunnelRegisterDatagramDataCallouts(&FWPM_LAYER_DATAGRAM_DATA_V4,
                                                   &OVS_TUNNEL_CALLOUT_V4,
                                                   deviceObject,
                                                   &gCalloutIdV4);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = FwpmTransactionCommit(gEngineHandle);
    if (!NT_SUCCESS(status)){
        goto Exit;
    }
    inTransaction = FALSE;

Exit:

    if (!NT_SUCCESS(status)) {
        if (inTransaction) {
            FwpmTransactionAbort(gEngineHandle);
        }
    }

    return status;
}

VOID
OvsTunnelUnregisterCallouts()
{
    FwpsCalloutUnregisterById(gCalloutIdV4);
    FwpmSubLayerDeleteByKey(gEngineHandle, &OVS_TUNNEL_SUBLAYER);
    FwpmCalloutDeleteById(gEngineHandle, gCalloutIdV4);
}

VOID
OvsTunnelFilterUninitialize(PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);

    OvsTunnelFilterStopThreads();

    OvsTunnelUnregisterCallouts();
    OvsTunnelEngineClose(&gEngineHandle);

    if (gDeviceObject) {
        IoDeleteDevice(gDeviceObject);
    }
}


NTSTATUS
OvsTunnelFilterInitialize(PDRIVER_OBJECT driverObject)
{
    NTSTATUS        status;
    UNICODE_STRING  deviceName;

    RtlInitUnicodeString(&deviceName,
                         L"\\Device\\OvsTunnelFilter");

    status = IoCreateDevice(driverObject,
                            0,
                            &deviceName,
                            FILE_DEVICE_NETWORK,
                            0,
                            FALSE,
                            &gDeviceObject);

    if (!NT_SUCCESS(status)){
        OVS_LOG_ERROR("Failed to create tunnel filter device, status: %x.",
                      status);
        goto Exit;
    }

    status = OvsTunnelFilterStartThreads();
    if (!NT_SUCCESS(status)){
        goto Exit;
    }

    status = OvsTunnelEngineOpen(&gEngineHandle);
    if (!NT_SUCCESS(status)){
        goto Exit;
    }

    status = OvsTunnelRegisterCallouts(gDeviceObject);
    if (!NT_SUCCESS(status)) {
        OVS_LOG_ERROR("Failed to register callout, status: %x.",
                      status);
    }

Exit:

    if (!NT_SUCCESS(status)){
        OvsTunnelFilterUninitialize(driverObject);
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * This function adds OVS system provider to the system if the BFE (Base
 * Filtering Engine) is running.
 * --------------------------------------------------------------------------
 */
VOID NTAPI
OvsTunnelProviderBfeCallback(PVOID context,
                             FWPM_SERVICE_STATE bfeState)
{
    HANDLE engineSession = NULL;

    DBG_UNREFERENCED_PARAMETER(context);

    if (FWPM_SERVICE_RUNNING == bfeState) {
        OvsTunnelEngineOpen(&engineSession);
        if (engineSession) {
            OvsTunnelAddSystemProvider(engineSession);
        }
        OvsTunnelEngineClose(&engineSession);
    }
}

/*
 * --------------------------------------------------------------------------
 * This function registers the OvsTunnelProviderBfeCallback callback that is
 * called whenever there is a change to the state of base filtering engine.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsSubscribeTunnelProviderBfeStateChanges(PVOID deviceObject)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!gTunnelProviderBfeHandle) {
        status = FwpmBfeStateSubscribeChanges(deviceObject,
                                              OvsTunnelProviderBfeCallback,
                                              NULL,
                                              &gTunnelProviderBfeHandle);
        if (!NT_SUCCESS(status)) {
            OVS_LOG_ERROR(
                "Failed to subscribe BFE tunnel provider callback, status: %x.",
                status);
        }
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * This function unregisters the OvsTunnelProviderBfeCallback callback that
 * was previously registered by OvsSubscribeTunnelProviderBfeStateChanges
 * function.
 * --------------------------------------------------------------------------
 */
VOID
OvsUnsubscribeTunnelProviderBfeStateChanges()
{
    NTSTATUS status = STATUS_SUCCESS;

    if (gTunnelProviderBfeHandle) {
        status = FwpmBfeStateUnsubscribeChanges(gTunnelProviderBfeHandle);
        if (!NT_SUCCESS(status)) {
            OVS_LOG_ERROR(
                "Failed to unsubscribe BFE tunnel provider callback, status: %x.",
                status);
        }
        gTunnelProviderBfeHandle = NULL;
    }
}

/*
 * --------------------------------------------------------------------------
 * This function registers the OVS system provider if the BFE (Base Filtering
 * Engine) is running.
 * Otherwise, it will register the OvsTunnelProviderBfeCallback callback.

 * Note: Before calling FwpmBfeStateGet, the callout driver must call the
 * FwpmBfeStateSubscribeChanges function to register the callback function
 * to be called whenever the state of the filter engine changes.
 *
 * Register WFP system provider call hierarchy:
 * <DriverEntry>
 *     <OvsCreateDeviceObject>
 *         <OvsRegisterSystemProvider>
 *             <OvsSubscribeTunnelProviderBfeStateChanges>
 *                 --> registers OvsTunnelProviderBfeCallback callback
 *                     <OvsTunnelProviderBfeCallback>
 *                         --> if BFE is running:
 *                             <OvsTunnelAddSystemProvider>
 *             --> if BFE is running:
 *                 <OvsTunnelAddSystemProvider>
 *                 <OvsUnsubscribeTunnelProviderBfeStateChanges>
 *                     --> unregisters OvsTunnelProviderBfeCallback callback
 *
 * --------------------------------------------------------------------------
 */
VOID
OvsRegisterSystemProvider(PVOID deviceObject)
{
    NTSTATUS status;
    HANDLE engineSession = NULL;

    status = OvsSubscribeTunnelProviderBfeStateChanges(deviceObject);
    if (NT_SUCCESS(status)) {
        if (FWPM_SERVICE_RUNNING == FwpmBfeStateGet()) {
            OvsTunnelEngineOpen(&engineSession);
            if (engineSession) {
                OvsTunnelAddSystemProvider(engineSession);
            }
            OvsTunnelEngineClose(&engineSession);

            OvsUnsubscribeTunnelProviderBfeStateChanges();
        }
    }
}

/*
 * --------------------------------------------------------------------------
 * This function removes the OVS system provider and unregisters the
 * OvsTunnelProviderBfeCallback callback from BFE (Base Filtering Engine).
 *
 * Unregister WFP system provider call hierarchy:
 * <OvsExtUnload>
 *     <OvsDeleteDeviceObject>
 *         <OvsUnregisterSystemProvider>
 *             <OvsTunnelRemoveSystemProvider>
 *             <OvsUnsubscribeTunnelProviderBfeStateChanges>
 *                 --> unregisters OvsTunnelProviderBfeCallback callback
 *
 * --------------------------------------------------------------------------
 */
VOID
OvsUnregisterSystemProvider()
{
    HANDLE engineSession = NULL;

    OvsTunnelEngineOpen(&engineSession);
    if (engineSession) {
        OvsTunnelRemoveSystemProvider(engineSession);
    }
    OvsTunnelEngineClose(&engineSession);

    OvsUnsubscribeTunnelProviderBfeStateChanges();
}

/*
 * --------------------------------------------------------------------------
 * This function initializes the tunnel filter if the BFE is running.
 * --------------------------------------------------------------------------
 */
VOID NTAPI
OvsTunnelInitBfeCallback(PVOID context,
                         FWPM_SERVICE_STATE bfeState)
{
    NTSTATUS status = STATUS_SUCCESS;
    PDRIVER_OBJECT driverObject = (PDRIVER_OBJECT) context;

    if (FWPM_SERVICE_RUNNING == bfeState) {
        status = OvsTunnelFilterInitialize(driverObject);
        if (!NT_SUCCESS(status)) {
            OVS_LOG_ERROR(
                "Failed to initialize tunnel filter, status: %x.",
                status);
        }
    }
}

/*
 * --------------------------------------------------------------------------
 * This function registers the OvsTunnelInitBfeCallback callback that is
 * called whenever there is a change to the state of base filtering engine.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsSubscribeTunnelInitBfeStateChanges(PDRIVER_OBJECT driverObject,
                                      PVOID deviceObject)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (!gTunnelInitBfeHandle) {
        status = FwpmBfeStateSubscribeChanges(deviceObject,
                                              OvsTunnelInitBfeCallback,
                                              driverObject,
                                              &gTunnelInitBfeHandle);
        if (!NT_SUCCESS(status)) {
            OVS_LOG_ERROR(
                "Failed to subscribe BFE tunnel init callback, status: %x.",
                status);
        }
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * This function unregisters the OvsTunnelInitBfeCallback callback that
 * was previously registered by OvsSubscribeTunnelInitBfeStateChanges
 * function.
 * --------------------------------------------------------------------------
 */
VOID
OvsUnsubscribeTunnelInitBfeStateChanges()
{
    NTSTATUS status = STATUS_SUCCESS;

    if (gTunnelInitBfeHandle) {
        status = FwpmBfeStateUnsubscribeChanges(gTunnelInitBfeHandle);
        if (!NT_SUCCESS(status)) {
            OVS_LOG_ERROR(
                "Failed to unsubscribe BFE tunnel init callback, status: %x.",
                status);
        }
        gTunnelInitBfeHandle = NULL;
    }
}

/*
 * --------------------------------------------------------------------------
 * This function initializes the OVS tunnel filter if the BFE (Base Filtering
 * Engine) is running.
 * Otherwise, it will register the OvsTunnelInitBfeCallback callback.

 * Note: Before calling FwpmBfeStateGet, the callout driver must call the
 * FwpmBfeStateSubscribeChanges function to register the callback function
 * to be called whenever the state of the filter engine changes.
 *
 * Initialize OVS tunnel filter call hierarchy:
 * <OvsExtAttach>
 *     <OvsCreateSwitch>
 *         <OvsInitTunnelFilter>
 *             <OvsSubscribeTunnelInitBfeStateChanges>
 *                 --> registers OvsTunnelInitBfeCallback callback
 *                     <OvsTunnelInitBfeCallback>
 *                         --> if BFE is running:
 *                             <OvsTunnelFilterInitialize>
 *                                 <IoCreateDevice>
 *                                 <OvsTunnelFilterStartThreads>
 *                                 <OvsTunnelRegisterCallouts>
 *             --> if BFE is running:
 *                 <OvsTunnelFilterInitialize>
 *                     <IoCreateDevice>
 *                     <OvsTunnelFilterStartThreads>
 *                     <OvsTunnelRegisterCallouts>
 *                 <OvsUnsubscribeTunnelInitBfeStateChanges>
 *                     --> unregisters OvsTunnelInitBfeCallback callback
 *
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsInitTunnelFilter(PDRIVER_OBJECT driverObject, PVOID deviceObject)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (deviceObject) {
        status = OvsSubscribeTunnelInitBfeStateChanges(driverObject, deviceObject);
        if (NT_SUCCESS(status)) {
            if (FWPM_SERVICE_RUNNING == FwpmBfeStateGet()) {
                status = OvsTunnelFilterInitialize(driverObject);
                if (!NT_SUCCESS(status)) {
                    /* XXX: We need to decide what actions to take in case of
                     * failure to initialize tunnel filter. */
                    ASSERT(status == NDIS_STATUS_SUCCESS);
                    OVS_LOG_ERROR(
                        "Failed to initialize tunnel filter, status: %x.",
                        status);
                }
                OvsUnsubscribeTunnelInitBfeStateChanges();
            }
        }
    } else {
        status = OvsTunnelFilterInitialize(driverObject);
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * This function uninitializes the OVS tunnel filter and unregisters the
 * OvsTunnelInitBfeCallback callback from BFE.
 *
 * Uninitialize OVS tunnel filter call hierarchy:
 * <OvsExtDetach>
 *     <OvsDeleteSwitch>
 *         <OvsUninitTunnelFilter>
 *             <OvsTunnelFilterUninitialize>
 *                 <OvsTunnelFilterStopThreads>
 *                 <OvsTunnelUnregisterCallouts>
 *                 <IoDeleteDevice>
 *             <OvsUnsubscribeTunnelInitBfeStateChanges>
 *                 --> unregisters OvsTunnelInitBfeCallback callback
 *
 * --------------------------------------------------------------------------
 */
VOID OvsUninitTunnelFilter(PDRIVER_OBJECT driverObject)
{
    OvsTunnelFilterUninitialize(driverObject);
    OvsUnsubscribeTunnelInitBfeStateChanges();
}

NTSTATUS
OvsTunnelAddFilterEx(HANDLE engineSession,
                     UINT32 filterPort,
                     UINT64 *filterID)
{
    NTSTATUS status;

    status = OvsTunnelAddFilter(engineSession,
                                L"Datagram-Data OVS Filter (Inbound)",
                                L"address/port for UDP",
                                (USHORT)filterPort,
                                FWP_DIRECTION_INBOUND,
                                0,
                                NULL,
                                &FWPM_LAYER_DATAGRAM_DATA_V4,
                                &OVS_TUNNEL_CALLOUT_V4,
                                filterID);
    if (!NT_SUCCESS(status)) {
        OVS_LOG_ERROR("Failed to add tunnel filter for port: %d, status: %x.",
                      filterPort, status);
    } else {
        OVS_LOG_INFO("Filter added, filter port: %d, filter ID: %d.",
                     filterPort, *filterID);
    }

    return status;
}

NTSTATUS
OvsTunnelRemoveFilterEx(HANDLE engineSession,
                        UINT64 filterID)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN  error = TRUE;

    do {
        if (filterID == 0) {
            OVS_LOG_INFO("No tunnel filter to remove.");
            break;
        }

        status = FwpmFilterDeleteById(engineSession, filterID);
        if (!NT_SUCCESS(status)) {
            OVS_LOG_ERROR("Failed to remove tunnel with filter ID: %d,\
                           status: %x.", filterID, status);
            break;
        }
        OVS_LOG_INFO("Filter removed, filter ID: %d.",
                     filterID);

        error = FALSE;
    } while (error);

    return status;
}

NTSTATUS
OvsTunnelFilterExecuteAction(HANDLE engineSession,
                             POVS_TUNFLT_REQUEST request)
{
    NTSTATUS status = STATUS_SUCCESS;

    switch (request->operation)
    {
    case OVS_TUN_FILTER_CREATE:
        status = OvsTunnelAddFilterEx(engineSession,
                                      request->port,
                                      request->filterID.addID);
        break;
    case OVS_TUN_FILTER_DELETE:
        status = OvsTunnelRemoveFilterEx(engineSession,
                                         request->filterID.delID);
        break;
    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * This function pops the head request from the queue while holding the
 * queue lock. If the request has already been cancelled or is about to be
 * cancelled, the function retrieves the next valid request.
 *
 * Returns a pointer to the OVS_TUNFLT_REQUEST_LIST request object retrieved
 * from the queue.
 * --------------------------------------------------------------------------
 */
POVS_TUNFLT_REQUEST
OvsTunnelFilterRequestPop(POVS_TUNFLT_REQUEST_LIST listRequests)
{
    POVS_TUNFLT_REQUEST request = NULL;
    PLIST_ENTRY         link, next, head;

    NdisAcquireSpinLock(&listRequests->spinlock);

    if (!IsListEmpty(&listRequests->head)) {
        head = &listRequests->head;
        LIST_FORALL_SAFE(head, link, next) {
            PDRIVER_CANCEL oldCancelRoutine;

            request = CONTAINING_RECORD(link, OVS_TUNFLT_REQUEST, entry);
            if (request->irp) {
                oldCancelRoutine = IoSetCancelRoutine(request->irp, NULL);
                if (oldCancelRoutine == NULL) {
                    /*
                     * The Cancel routine for the current IRP is running. The
                     * request is to be completed by the Cancel routine. Leave
                     * this request alone and go to the next one.
                     */
                    continue;
                } else {
                    /*
                     * The Cancel routine cannot run now and cannot already have
                     * started to run. This request can be processed.
                     */
                }
            }

            RemoveEntryList(&request->entry);
            listRequests->numEntries--;
            break;
        }
    }

    NdisReleaseSpinLock(&listRequests->spinlock);

    return request;
}

/*
 * --------------------------------------------------------------------------
 * This function pushes the received request to the queue, marks the IRP as
 * pending and sets its Cancel routine, while holding the queue lock.
 *
 * Returns STATUS_CANCELLED if the IRP has already been cancelled. Otherwise,
 * STATUS_SUCCESS is returned.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsTunnelFilterRequestPush(POVS_TUNFLT_REQUEST_LIST listRequests,
                           POVS_TUNFLT_REQUEST request)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIRP irp = request->irp;
    PDRIVER_CANCEL oldCancelRoutine;
    BOOLEAN cancelled = FALSE;

    NdisAcquireSpinLock(&listRequests->spinlock);

    if (irp) {
        /*
         * Mark the IRP pending to indicate that the request may complete on
         * a different thread.
         */
        IoMarkIrpPending(irp);

        /*
         * Set the Cancel routine for the pending IRP, before checking the
         * Cancel flag.
         */
        oldCancelRoutine = IoSetCancelRoutine(irp, OvsTunnelFilterCancelIrp);
        ASSERT(oldCancelRoutine == NULL);

        if (irp->Cancel) {
            /*
             * The IRP has already been cancelled.
             * Determine wheather the Cancel routine has started to run.
             */
            oldCancelRoutine = IoSetCancelRoutine(irp, NULL);
            if (oldCancelRoutine) {
                /*
                 * The I/O Manager has not called the Cancel routine and it
                 * won't be called anymore, because we just set it to NULL.
                 * Return STATUS_CANCELLED and complete the request after
                 * releasing the lock.
                 */
                status = STATUS_CANCELLED;
                cancelled = TRUE;
            } else {
                /*
                 * The Cancel routine has already started to run, but it is
                 * blocked while it waits for the queue lock. Release the lock
                 * and return STATUS_SUCCESS to avoid completing the request.
                 * It will be completed in the Cancel routine.
                 */
            }
        } else {
            /*
             * The IRP has not been cancelled, so set its context used in the
             * Cancel routine.
             */
            OvsTunnelFilterSetIrpContext(listRequests, request);
        }
    }

    if (!cancelled) {
        InsertTailList(&listRequests->head, &(request->entry));
        listRequests->numEntries++;
    }

    NdisReleaseSpinLock(&listRequests->spinlock);

    return status;
}

/*
 * --------------------------------------------------------------------------
 * This function pushes the received request to the corresponding thread
 * request queue. The arrival of the new request is signaled to the thread,
 * in order to start processing it.
 *
 * Note:
 * If the thread is not initialized, no operation is performed.
 *
 * For a uniform distribution of requests to thread queues, a thread index is
 * calculated based on the received destination port.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsTunnelFilterThreadPush(POVS_TUNFLT_REQUEST request)
{
    NTSTATUS status = STATUS_REQUEST_ABORTED;
    UINT32 count = OVS_TUNFLT_MAX_THREADS;
    UINT32 threadIndex;

    threadIndex = request->port % OVS_TUNFLT_MAX_THREADS;

    while (count--) {
        if (gTunnelThreadCtx[threadIndex].isInitialized) {

            status = OvsTunnelFilterRequestPush(
                &gTunnelThreadCtx[threadIndex].listRequests,
                request);

            if (NT_SUCCESS(status)) {
                KeSetEvent(&gTunnelThreadCtx[threadIndex].requestEvent,
                           IO_NO_INCREMENT,
                           FALSE);
            }

            break;
        } else {
            OVS_LOG_INFO("OVS tunnel filter thread %d not initialized.",
                         threadIndex);
        }

        threadIndex = (threadIndex + 1) % OVS_TUNFLT_MAX_THREADS;
    }

    return status;
}

VOID
OvsTunnelFilterCompleteRequest(PIRP irp,
                               PFNTunnelVportPendingOp callback,
                               PVOID context,
                               NTSTATUS status)
{
    UINT32 replyLen = 0;

    if (callback) {
        callback(context, status, &replyLen);
        /* Release the context passed to the callback function. */
        OvsFreeMemory(context);
    }

    if (irp) {
        OvsCompleteIrpRequest(irp, (ULONG_PTR)replyLen, status);
    }
}

VOID
OvsTunnelFilterRequestListProcess(POVS_TUNFLT_THREAD_CONTEXT threadCtx)
{
    POVS_TUNFLT_REQUEST request = NULL;
    NTSTATUS            status = STATUS_SUCCESS;
    BOOLEAN             inTransaction = FALSE;

    do {
        if (!InterlockedCompareExchange(
            (LONG volatile *)&threadCtx->listRequests.numEntries, 0, 0)) {
            OVS_LOG_INFO("Nothing to do... request list is empty.");
            break;
        }

        status = FwpmTransactionBegin(threadCtx->engineSession, 0);
        if (!NT_SUCCESS(status)) {
            OVS_LOG_ERROR("Failed to start transaction, status: %x.",
                          status);
            break;
        }
        inTransaction = TRUE;

        while (NULL !=
            (request = OvsTunnelFilterRequestPop(&threadCtx->listRequests))) {

            status = OvsTunnelFilterExecuteAction(threadCtx->engineSession,
                                                  request);

            /* Complete the IRP with the last operation status. */
            OvsTunnelFilterCompleteRequest(request->irp,
                                           request->callback,
                                           request->context,
                                           status);

            OvsFreeMemory(request);
            request = NULL;
        }

        status = FwpmTransactionCommit(threadCtx->engineSession);
        if (!NT_SUCCESS(status)) {
            OVS_LOG_ERROR("Failed to commit transaction, status: %x.",
                          status);
            break;
        }

        inTransaction = FALSE;
    } while (inTransaction);

    if (inTransaction) {
        FwpmTransactionAbort(threadCtx->engineSession);
        OVS_LOG_ERROR("Failed to execute request, status: %x.\
                       Transaction aborted.", status);
    }
}

/*
 *----------------------------------------------------------------------------
 * System thread routine that processes thread's requests queue. The thread
 * routine initializes thread's necessary data and waits on two events,
 * requestEvent and stopEvent. Whenever a request is pushed to the thread's
 * queue, the requestEvent is signaled and the thread routine starts processing
 * the arrived requests. When stopEvent is signaled, all subsequent requests
 * are completed with STATUS_CANCELED, without being added to the thread's
 * queue, and the routine finishes processing all existing requests from the
 * queue before uninitializing the thread and exiting.
 *----------------------------------------------------------------------------
 */
_Use_decl_annotations_
VOID
OvsTunnelFilterThreadProc(PVOID context)
{
    NTSTATUS                   status = STATUS_SUCCESS;
    POVS_TUNFLT_THREAD_CONTEXT threadCtx = (POVS_TUNFLT_THREAD_CONTEXT)context;
    PKEVENT                    eventArray[2] = { 0 };
    ULONG                      count = 0;
    BOOLEAN                    exit = FALSE;
    BOOLEAN                    error = TRUE;

    OVS_LOG_INFO("Starting OVS Tunnel system thread %d.",
                 threadCtx->threadID);

    eventArray[0] = &threadCtx->stopEvent;
    eventArray[1] = &threadCtx->requestEvent;
    count = ARRAY_SIZE(eventArray);

    do {
        status = OvsTunnelFilterThreadInit(threadCtx);
        if (!NT_SUCCESS(status)) {
            OVS_LOG_ERROR("Failed to initialize tunnel filter thread %d.",
                threadCtx->threadID);
            break;
        }

        do {
            status = KeWaitForMultipleObjects(count,
                                              (PVOID)eventArray,
                                              WaitAny,
                                              Executive,
                                              KernelMode,
                                              FALSE,
                                              NULL,
                                              NULL);
            switch (status) {
                case STATUS_WAIT_1:
                    /* Start processing requests. */
                    OvsTunnelFilterRequestListProcess(threadCtx);
                    break;
                default:
                    /* Finish processing the remaining requests and exit. */
                    OvsTunnelFilterRequestListProcess(threadCtx);
                    exit = TRUE;
                    break;
            }
        } while (!exit);

        OvsTunnelFilterThreadUninit(threadCtx);

        error = FALSE;
    } while (error);

    OVS_LOG_INFO("Terminating OVS Tunnel system thread %d.",
                 threadCtx->threadID);

    PsTerminateSystemThread(STATUS_SUCCESS);
};

static NTSTATUS
OvsTunnelFilterStartThreads()
{
    NTSTATUS status = STATUS_SUCCESS;

    for (UINT index = 0; index < OVS_TUNFLT_MAX_THREADS; index++) {
        gTunnelThreadCtx[index].threadID = index;

        status = OvsTunnelFilterThreadStart(&gTunnelThreadCtx[index]);
        if (!NT_SUCCESS(status)) {
            OVS_LOG_ERROR("Failed to start tunnel filter thread %d.", index);
            break;
        }
    }

    return status;
}

static NTSTATUS
OvsTunnelFilterThreadStart(POVS_TUNFLT_THREAD_CONTEXT threadCtx)
{
    NTSTATUS    status = STATUS_SUCCESS;
    HANDLE      threadHandle = NULL;
    BOOLEAN     error = TRUE;

    do {
        status = PsCreateSystemThread(&threadHandle,
                                      SYNCHRONIZE,
                                      NULL,
                                      NULL,
                                      NULL,
                                      OvsTunnelFilterThreadProc,
                                      threadCtx);
        if (!NT_SUCCESS(status)) {
            OVS_LOG_ERROR("Failed to create tunnel thread, status: %x.",
                          status);
            break;
        }

        ObReferenceObjectByHandle(threadHandle,
                                  SYNCHRONIZE,
                                  NULL,
                                  KernelMode,
                                  &threadCtx->threadObject,
                                  NULL);
        ZwClose(threadHandle);
        threadHandle = NULL;

        error = FALSE;
    } while (error);

    return status;
}

static VOID
OvsTunnelFilterStopThreads()
{
    /* Signal all threads to stop and ignore all subsequent requests. */
    for (UINT index = 0; index < OVS_TUNFLT_MAX_THREADS; index++) {
        OvsTunnelFilterThreadStop(&gTunnelThreadCtx[index], TRUE);
    }

    /* Wait for all threads to finish processing the requests. */
    for (UINT index = 0; index < OVS_TUNFLT_MAX_THREADS; index++) {
        OvsTunnelFilterThreadStop(&gTunnelThreadCtx[index], FALSE);
    }
}

static VOID
OvsTunnelFilterThreadStop(POVS_TUNFLT_THREAD_CONTEXT threadCtx,
                          BOOLEAN signalEvent)
{
    if (threadCtx->isInitialized) {

        if (signalEvent) {
            /* Signal stop thread event. */
            OVS_LOG_INFO("Received stop event for OVS Tunnel system thread %d.",
                         threadCtx->threadID);
            KeSetEvent(&threadCtx->stopEvent, IO_NO_INCREMENT, FALSE);
        } else {
            /* Wait for the tunnel thread to finish. */
            KeWaitForSingleObject(threadCtx->threadObject,
                                  Executive,
                                  KernelMode,
                                  FALSE,
                                  NULL);

            ObDereferenceObject(threadCtx->threadObject);
        }
    }
}

/*
 * --------------------------------------------------------------------------
 * This function initializes thread's necessary data. Each thread has its own
 * session object to the BFE that is used for processing the requests from
 * the thread's queue.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
OvsTunnelFilterThreadInit(POVS_TUNFLT_THREAD_CONTEXT threadCtx)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN error = TRUE;

    do {
        /* Create thread's engine session object. */
        status = OvsTunnelEngineOpen(&threadCtx->engineSession);
        if (!NT_SUCCESS(status)) {
            break;
        }

        NdisAllocateSpinLock(&threadCtx->listRequests.spinlock);

        InitializeListHead(&threadCtx->listRequests.head);

        KeInitializeEvent(&threadCtx->stopEvent,
            NotificationEvent,
            FALSE);

        KeInitializeEvent(&threadCtx->requestEvent,
            SynchronizationEvent,
            FALSE);

        threadCtx->isInitialized = TRUE;

        error = FALSE;
    } while (error);

    return status;
}

/*
 * --------------------------------------------------------------------------
 * This function uninitializes thread's private data. Thread's engine session
 * handle is closed and set to NULL.
 * --------------------------------------------------------------------------
 */
static VOID
OvsTunnelFilterThreadUninit(POVS_TUNFLT_THREAD_CONTEXT threadCtx)
{
    if (threadCtx->engineSession) {
        /* Close thread's FWPM session. */
        OvsTunnelEngineClose(&threadCtx->engineSession);

        NdisFreeSpinLock(&threadCtx->listRequests.spinlock);

        threadCtx->isInitialized = FALSE;
    }
}

/*
 * --------------------------------------------------------------------------
 * This function creates a new tunnel filter request and push it to a thread
 * queue. If the thread stop event is signaled, the request is completed with
 * STATUS_REQUEST_ABORTED without pushing it to any queue.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsTunnelFilterQueueRequest(PIRP irp,
                            UINT16 remotePort,
                            UINT64 *filterID,
                            OVS_TUNFLT_OPERATION operation,
                            PFNTunnelVportPendingOp callback,
                            PVOID tunnelContext)
{
    POVS_TUNFLT_REQUEST request = NULL;
    NTSTATUS            status = STATUS_PENDING;
    NTSTATUS            result = STATUS_SUCCESS;
    BOOLEAN             error = TRUE;
    UINT64              timeout = 0;

    do {
        /* Verify if the stop event was signaled. */
        if (STATUS_SUCCESS == KeWaitForSingleObject(
                                  &gTunnelThreadCtx[0].stopEvent,
                                  Executive,
                                  KernelMode,
                                  FALSE,
                                  (LARGE_INTEGER *)&timeout)) {
            /* The stop event is signaled. Completed the IRP with
             * STATUS_REQUEST_ABORTED. */
            status = STATUS_REQUEST_ABORTED;
            break;
        }

        if (NULL == filterID) {
            OVS_LOG_ERROR("Invalid request.");
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        request = (POVS_TUNFLT_REQUEST)
            OvsAllocateMemoryWithTag(sizeof(*request),
                                     OVS_TUNFLT_POOL_TAG);
        if (NULL == request) {
            OVS_LOG_ERROR("Failed to allocate list item.");
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        request->port = remotePort;
        request->operation = operation;
        switch (operation) {
            case OVS_TUN_FILTER_CREATE:
                request->filterID.addID = filterID;
                break;
            case OVS_TUN_FILTER_DELETE:
                request->filterID.delID = *filterID;
                break;
        }
        request->irp = irp;
        request->callback = callback;
        request->context = tunnelContext;

        result = OvsTunnelFilterThreadPush(request);
        if (!NT_SUCCESS(result)) {
            status = result;
            break;
        }

        error = FALSE;
    } while (error);

    if (error) {
        OvsTunnelFilterCompleteRequest(irp,
                                       callback,
                                       tunnelContext,
                                       status);
        if (request) {
            OvsFreeMemory(request);
            request = NULL;
        }
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 *  This function adds a new WFP filter for the received port and returns the
 *  ID of the created WFP filter.
 *
 *  Note:
 *  All necessary calls to the WFP filtering engine must be running at IRQL =
 *  PASSIVE_LEVEL. Because the function is called at IRQL = DISPATCH_LEVEL,
 *  we register an OVS_TUN_FILTER_CREATE request that will be processed by
 *  the tunnel filter thread routine at IRQL = PASSIVE_LEVEL.
 *
 * OVS VXLAN port add call hierarchy:
 * <OvsNewVportCmdHandler>
 *     <OvsInitTunnelVport>
 *         <OvsInitVxlanTunnel>
 *             <OvsTunnelFilterCreate>
 *                 <OvsTunnelFilterQueueRequest>
 *                     --> if thread STOP event is signalled:
 *                         --> Complete request with STATUS_CANCELLED
 *                         --> EXIT
 *                     <OvsTunnelFilterThreadPush>
 *                         --> add the request to one of tunnel thread queues
 *
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsTunnelFilterCreate(PIRP irp,
                      UINT16 filterPort,
                      UINT64 *filterID,
                      PFNTunnelVportPendingOp callback,
                      PVOID tunnelContext)
{
    return OvsTunnelFilterQueueRequest(irp,
                                       filterPort,
                                       filterID,
                                       OVS_TUN_FILTER_CREATE,
                                       callback,
                                       tunnelContext);
}

/*
 * --------------------------------------------------------------------------
 *  This function removes a WFP filter using the received filter ID.
 *
 *  Note:
 *  All necessary calls to the WFP filtering engine must be running at IRQL =
 *  PASSIVE_LEVEL. Because the function is called at IRQL = DISPATCH_LEVEL,
 *  we register an OVS_TUN_FILTER_DELETE request that will be processed by
 *  the tunnel filter thread routine at IRQL = PASSIVE_LEVEL.
 *
 * OVS VXLAN port delete call hierarchy:
 * <OvsDeleteVportCmdHandler>
 *     <OvsRemoveAndDeleteVport>
 *         <OvsCleanupVxlanTunnel>
 *             <OvsTunnelFilterDelete>
 *                 <OvsTunnelFilterQueueRequest>
 *                     --> if thread STOP event is signalled:
 *                         --> Complete request with STATUS_CANCELLED
 *                         --> EXIT
 *                     <OvsTunnelFilterThreadPush>
 *                         --> add the request to one of tunnel thread queues
 *
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsTunnelFilterDelete(PIRP irp,
                      UINT64 filterID,
                      PFNTunnelVportPendingOp callback,
                      PVOID tunnelContext)
{
    return OvsTunnelFilterQueueRequest(irp,
                                       0,
                                       &filterID,
                                       OVS_TUN_FILTER_DELETE,
                                       callback,
                                       tunnelContext);
}

/*
 * --------------------------------------------------------------------------
 * This function sets the context for the IRP. The context is used by the
 * Cancel routine, in order to identify the request object, corresponding to
 * the IRP, to be completed and to have access to the queue lock to remove
 * the request link from the queue.
 * --------------------------------------------------------------------------
 */
VOID
OvsTunnelFilterSetIrpContext(POVS_TUNFLT_REQUEST_LIST listRequests,
                             POVS_TUNFLT_REQUEST request)
{
    PIRP irp = request->irp;

    if (irp) {
        /* Set the IRP's DriverContext to be used for later. */
        irp->Tail.Overlay.DriverContext[0] = (PVOID)request;
        irp->Tail.Overlay.DriverContext[1] = (PVOID)listRequests;
    }
}

/*
 * --------------------------------------------------------------------------
 * This function is the Cancel routine to be called by the I/O Manager in the
 * case the IRP is canceled.
 * --------------------------------------------------------------------------
 */
VOID
OvsTunnelFilterCancelIrp(PDEVICE_OBJECT DeviceObject,
                         PIRP irp)
{
    POVS_TUNFLT_REQUEST request =
        (POVS_TUNFLT_REQUEST)irp->Tail.Overlay.DriverContext[0];
    POVS_TUNFLT_REQUEST_LIST listRequests =
        (POVS_TUNFLT_REQUEST_LIST)irp->Tail.Overlay.DriverContext[1];

    DBG_UNREFERENCED_PARAMETER(DeviceObject);

    /* Release the global cancel spinlock. */
    IoReleaseCancelSpinLock(irp->CancelIrql);

    /* Clear the cancel routine from the IRP. */
    IoSetCancelRoutine(irp, NULL);

    NdisAcquireSpinLock(&listRequests->spinlock);

    /* Remove the request from the corresponding tunnel filter thread queue. */
    RemoveEntryList(&request->entry);
    listRequests->numEntries--;

    NdisReleaseSpinLock(&listRequests->spinlock);

    /* We are done with this IRP, so complete it with STATUS_CANCELLED. */
    OvsTunnelFilterCompleteRequest(request->irp,
                                   request->callback,
                                   request->context,
                                   STATUS_CANCELLED);

    OvsFreeMemory(request);
}
