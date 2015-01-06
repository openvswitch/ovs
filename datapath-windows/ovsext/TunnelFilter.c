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

/*
 * The provider name should always match the provider string from the install
 * file.
 */
#define OVS_TUNNEL_PROVIDER_NAME        L"Open vSwitch"

/*
 * The provider description should always contain the OVS service description
 * string from the install file.
 */
#define OVS_TUNNEL_PROVIDER_DESC        L"Open vSwitch Extension tunnel provider"

/* The session name isn't required but it's useful for diagnostics. */
#define OVS_TUNNEL_SESSION_NAME         L"OVS tunnel session"

/* Configurable parameters (addresses and ports are in host order) */
UINT16   configNewDestPort = VXLAN_UDP_PORT;

/*
 * Callout and sublayer GUIDs
 */
// b16b0a6e-2b2a-41a3-8b39-bd3ffc855ff8
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
 * Callout driver global variables
 */
PDEVICE_OBJECT gDeviceObject;

HANDLE gEngineHandle = NULL;
UINT32 gCalloutIdV4;


/* Callout driver implementation */

NTSTATUS
OvsTunnelEngineOpen(HANDLE *handle)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_SESSION session = { 0 };

    /* The session name isn't required but may be useful for diagnostics. */
    session.displayData.name = OVS_TUNNEL_SESSION_NAME;
    /*
    * Set an infinite wait timeout, so we don't have to handle FWP_E_TIMEOUT
    * errors while waiting to acquire the transaction lock.
    */
    session.txnWaitTimeoutInMSec = INFINITE;
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    /* The authentication service should always be RPC_C_AUTHN_DEFAULT. */
    status = FwpmEngineOpen(NULL,
                            RPC_C_AUTHN_DEFAULT,
                            NULL,
                            &session,
                            handle);
    if (!NT_SUCCESS(status)) {
        OVS_LOG_ERROR("Fail to open filtering engine session, status: %x.",
                      status);
    }

    return status;
}

VOID
OvsTunnelEngineClose(HANDLE *handle)
{
    if (*handle) {
        FwpmEngineClose(*handle);
        *handle = NULL;
    }
}

VOID
OvsTunnelAddSystemProvider(HANDLE handle)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN inTransaction = FALSE;
    FWPM_PROVIDER provider = { 0 };

    do {
        status = FwpmTransactionBegin(handle, 0);
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

        status = FwpmProviderAdd(handle,
                                 &provider,
                                 NULL);
        if (!NT_SUCCESS(status)) {
            OVS_LOG_ERROR("Fail to add WFP provider, status: %x.", status);
            break;
        }

        status = FwpmTransactionCommit(handle);
        if (!NT_SUCCESS(status)) {
            break;
        }

        inTransaction = FALSE;
    } while (inTransaction);

    if (inTransaction){
        FwpmTransactionAbort(handle);
    }
}

VOID
OvsTunnelRemoveSystemProvider(HANDLE handle)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN inTransaction = FALSE;

    do {
        status = FwpmTransactionBegin(handle, 0);
        if (!NT_SUCCESS(status)) {
            break;
        }
        inTransaction = TRUE;

        status = FwpmProviderDeleteByKey(handle,
                                         &OVS_TUNNEL_PROVIDER_KEY);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = FwpmTransactionCommit(handle);
        if (!NT_SUCCESS(status)) {
            break;
        }

        inTransaction = FALSE;
    } while (inTransaction);

    if (inTransaction){
        FwpmTransactionAbort(handle);
    }
}

NTSTATUS
OvsTunnelAddFilter(PWSTR filterName,
                   const PWSTR filterDesc,
                   USHORT remotePort,
                   FWP_DIRECTION direction,
                   UINT64 context,
                   const GUID *filterKey,
                   const GUID *layerKey,
                   const GUID *calloutKey)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_FILTER filter = {0};
    FWPM_FILTER_CONDITION filterConditions[3] = {0};
    UINT conditionIndex;

    UNREFERENCED_PARAMETER(remotePort);
    UNREFERENCED_PARAMETER(direction);

    filter.filterKey = *filterKey;
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

    status = FwpmFilterAdd(gEngineHandle,
                           &filter,
                           NULL,
                           NULL);

    return status;
}

NTSTATUS
OvsTunnelRemoveFilter(const GUID *filterKey,
                      const GUID *sublayerKey)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN inTransaction = FALSE;

    do {
        status = FwpmTransactionBegin(gEngineHandle, 0);
        if (!NT_SUCCESS(status)) {
            break;
        }

        inTransaction = TRUE;

        /*
         * We have to delete the filter first since it references the
         * sublayer. If we tried to delete the sublayer first, it would fail
         * with FWP_ERR_IN_USE.
         */
        status = FwpmFilterDeleteByKey(gEngineHandle,
                                       filterKey);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = FwpmSubLayerDeleteByKey(gEngineHandle,
                                         sublayerKey);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = FwpmTransactionCommit(gEngineHandle);
        if (!NT_SUCCESS(status)){
            break;
        }

        inTransaction = FALSE;
    } while (inTransaction);

    if (inTransaction) {
        FwpmTransactionAbort(gEngineHandle);
    }
    return status;
}

/*
 * --------------------------------------------------------------------------
 * This function registers callouts and filters that intercept UDP traffic at
 * WFP FWPM_LAYER_DATAGRAM_DATA_V4
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsTunnelRegisterDatagramDataCallouts(const GUID *layerKey,
                                      const GUID *calloutKey,
                                      VOID *deviceObject,
                                      UINT32 *calloutId)
{
    NTSTATUS status = STATUS_SUCCESS;

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

    status = FwpsCalloutRegister(deviceObject,
                                 &sCallout,
                                 calloutId);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    calloutRegistered = TRUE;

    displayData.name = L"Datagram-Data OVS Callout";
    displayData.description = L"Proxies destination address/port for UDP";

    mCallout.calloutKey = *calloutKey;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = *layerKey;

    status = FwpmCalloutAdd(gEngineHandle,
                            &mCallout,
                            NULL,
                            NULL);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = OvsTunnelAddFilter(L"Datagram-Data OVS Filter (Inbound)",
                                L"address/port for UDP",
                                configNewDestPort,
                                FWP_DIRECTION_INBOUND,
                                0,
                                &OVS_TUNNEL_FILTER_KEY,
                                layerKey,
                                calloutKey);

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
 * This function registers dynamic callouts and filters that intercept UDP
 * Callouts and filters will be removed during De-Initialize.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsTunnelRegisterCallouts(VOID *deviceObject)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_SUBLAYER OvsTunnelSubLayer;

    BOOLEAN engineOpened = FALSE;
    BOOLEAN inTransaction = FALSE;

    status = OvsTunnelEngineOpen(&gEngineHandle);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    engineOpened = TRUE;

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
    /*
     * Link all objects to the tunnel provider. When multiple providers are
     * installed on a computer, this makes it easy to determine who added what.
     */
    OvsTunnelSubLayer.providerKey = (GUID*) &OVS_TUNNEL_PROVIDER_KEY;

    status = FwpmSubLayerAdd(gEngineHandle, &OvsTunnelSubLayer, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
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
        if (engineOpened) {
            OvsTunnelEngineClose(&gEngineHandle);
        }
    }

    return status;
}

VOID
OvsTunnelUnregisterCallouts(VOID)
{
    OvsTunnelRemoveFilter(&OVS_TUNNEL_FILTER_KEY,
                          &OVS_TUNNEL_SUBLAYER);
    FwpsCalloutUnregisterById(gCalloutIdV4);
    FwpmCalloutDeleteById(gEngineHandle, gCalloutIdV4);
    OvsTunnelEngineClose(&gEngineHandle);
}

VOID
OvsTunnelFilterUninitialize(PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);

    OvsTunnelUnregisterCallouts();
    IoDeleteDevice(gDeviceObject);
}


NTSTATUS
OvsTunnelFilterInitialize(PDRIVER_OBJECT driverObject)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING deviceName;

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
        goto Exit;
    }

    status = OvsTunnelRegisterCallouts(gDeviceObject);

Exit:

    if (!NT_SUCCESS(status)){
        if (gEngineHandle != NULL) {
            OvsTunnelUnregisterCallouts();
        }

        if (gDeviceObject) {
            IoDeleteDevice(gDeviceObject);
        }
    }

    return status;
}
