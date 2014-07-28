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


#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>
#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>

#include "OvsTunnel.h"
#include "OvsSwitch.h"
#include "OvsVport.h"
#include "OvsEvent.h"
#include "OvsUser.h"
#include "OvsVxlan.h"


#define INITGUID
#include <guiddef.h>


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

/*
 * Callout driver global variables
 */
PDEVICE_OBJECT gDeviceObject;

HANDLE gEngineHandle;
UINT32 gCalloutIdV4;


/* Callout driver implementation */

NTSTATUS
OvsTunnelAddFilter(PWSTR filterName,
                   const PWSTR filterDesc,
                   USHORT remotePort,
                   FWP_DIRECTION direction,
                   UINT64 context,
                   const GUID *layerKey,
                   const GUID *calloutKey)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_FILTER filter = {0};
    FWPM_FILTER_CONDITION filterConditions[3] = {0};
    UINT conditionIndex;

    UNREFERENCED_PARAMETER(remotePort);
    UNREFERENCED_PARAMETER(direction);

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
    /* Currnetly we don't associate a context with the flow */
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

    FWPM_SESSION session = {0};

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    status = FwpmEngineOpen(NULL,
                            RPC_C_AUTHN_WINNT,
                            NULL,
                            &session,
                            &gEngineHandle);

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

    status = FwpmSubLayerAdd(gEngineHandle, &OvsTunnelSubLayer, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // In order to use this callout a socket must be opened
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
            FwpmEngineClose(gEngineHandle);
            gEngineHandle = NULL;
        }
    }

    return status;
}

VOID
OvsTunnelUnregisterCallouts(VOID)
{
    FwpmEngineClose(gEngineHandle);
    gEngineHandle = NULL;
    FwpsCalloutUnregisterById(gCalloutIdV4);
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
