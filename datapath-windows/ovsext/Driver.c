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
#include "Switch.h"
#include "User.h"
#include "Datapath.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_DRIVER
#include "Debug.h"

/* Global handles. XXX: Some of them need not be global. */
/*
 * Maps to DriverObject and FilterDriverContext parameters in the NDIS filter
 * driver functions.
 * DriverObject is specified by NDIS.
 * FilterDriverContext is specified by the filter driver.
 */
NDIS_HANDLE gOvsExtDriverObject;

/*
 * Maps to NdisFilterHandle parameter in the NDIS filter driver functions.
 * NdisFilterHandle is returned by NDISFRegisterFilterDriver.
 */
NDIS_HANDLE gOvsExtDriverHandle;

/*
 * Maps to FilterModuleContext parameter in the NDIS filter driver functions.
 * FilterModuleContext is a allocated by the driver in the FilterAttach
 * function.
 */
extern POVS_SWITCH_CONTEXT gOvsSwitchContext;

static PWCHAR ovsExtFriendlyName = L"dbosoft Open vSwitch Extension";
static PWCHAR ovsExtServiceName = L"DBO_OVSE";
NDIS_STRING ovsExtGuidUC;
NDIS_STRING ovsExtFriendlyNameUC;

static PWCHAR ovsExtGuidStr = L"{63E968D9-754E-4704-A5CE-6E3BF7DDF59B}";
static const GUID ovsExtGuid = {
      0x63e968d9,
      0x754e,
      0x4704,
      {0xa5, 0xce, 0x6e, 0x3b, 0xf7, 0xdd, 0xf5, 0x9b}
};

DRIVER_INITIALIZE DriverEntry;

/* Declarations of callback functions for the filter driver. */
DRIVER_UNLOAD OvsExtUnload;
FILTER_NET_PNP_EVENT OvsExtNetPnPEvent;
FILTER_STATUS OvsExtStatus;

FILTER_ATTACH OvsExtAttach;
FILTER_DETACH OvsExtDetach;
FILTER_RESTART OvsExtRestart;
FILTER_PAUSE OvsExtPause;

FILTER_SEND_NET_BUFFER_LISTS OvsExtSendNBL;
FILTER_SEND_NET_BUFFER_LISTS_COMPLETE OvsExtSendNBLComplete;
FILTER_CANCEL_SEND_NET_BUFFER_LISTS OvsExtCancelSendNBL;
FILTER_RECEIVE_NET_BUFFER_LISTS OvsExtReceiveNBL;
FILTER_RETURN_NET_BUFFER_LISTS OvsExtReturnNBL;

FILTER_OID_REQUEST OvsExtOidRequest;
FILTER_OID_REQUEST_COMPLETE OvsExtOidRequestComplete;
FILTER_CANCEL_OID_REQUEST OvsExtCancelOidRequest;


/*
 * --------------------------------------------------------------------------
 * Init/Load function for the OVSEXT filter Driver.
 * --------------------------------------------------------------------------
 */
NTSTATUS
DriverEntry(PDRIVER_OBJECT driverObject,
            PUNICODE_STRING registryPath)
{
    NDIS_STATUS status;
    NDIS_FILTER_DRIVER_CHARACTERISTICS driverChars;

    UNREFERENCED_PARAMETER(registryPath);

    /* Initialize driver associated data structures. */
    status = OvsInit();
    if (status != NDIS_STATUS_SUCCESS) {
        goto cleanup;
    }

    gOvsExtDriverObject = driverObject;

    RtlZeroMemory(&driverChars, sizeof driverChars);
    driverChars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
    driverChars.Header.Size = sizeof driverChars;
    driverChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
    driverChars.MajorNdisVersion = NDIS_FILTER_MAJOR_VERSION;
    driverChars.MinorNdisVersion = NDIS_FILTER_MINOR_VERSION;
    driverChars.MajorDriverVersion = 1;
    driverChars.MinorDriverVersion = 0;
    driverChars.Flags = 0;

    RtlInitUnicodeString(&driverChars.ServiceName, ovsExtServiceName);
    RtlInitUnicodeString(&ovsExtFriendlyNameUC, ovsExtFriendlyName);
    RtlInitUnicodeString(&ovsExtGuidUC, ovsExtGuidStr);

    driverChars.FriendlyName = ovsExtFriendlyNameUC;
    driverChars.UniqueName = ovsExtGuidUC;

    driverChars.AttachHandler = OvsExtAttach;
    driverChars.DetachHandler = OvsExtDetach;
    driverChars.RestartHandler = OvsExtRestart;
    driverChars.PauseHandler = OvsExtPause;

    driverChars.SendNetBufferListsHandler = OvsExtSendNBL;
    driverChars.SendNetBufferListsCompleteHandler = OvsExtSendNBLComplete;
    driverChars.CancelSendNetBufferListsHandler = OvsExtCancelSendNBL;
    driverChars.ReceiveNetBufferListsHandler = NULL;
    driverChars.ReturnNetBufferListsHandler = NULL;

    driverChars.OidRequestHandler = OvsExtOidRequest;
    driverChars.OidRequestCompleteHandler = OvsExtOidRequestComplete;
    driverChars.CancelOidRequestHandler = OvsExtCancelOidRequest;

    driverChars.DevicePnPEventNotifyHandler = NULL;
    driverChars.NetPnPEventHandler = OvsExtNetPnPEvent;
    driverChars.StatusHandler = NULL;

    driverObject->DriverUnload = OvsExtUnload;

    gOvsExtDriverHandle = NULL;
    status = NdisFRegisterFilterDriver(driverObject,
                                       (NDIS_HANDLE)gOvsExtDriverObject,
                                       &driverChars,
                                       &gOvsExtDriverHandle);
    if (status != NDIS_STATUS_SUCCESS) {
        goto cleanup;
    }

    /* Create the communication channel for userspace. */
    status = OvsCreateDeviceObject(gOvsExtDriverHandle);
    if (status != NDIS_STATUS_SUCCESS) {
        NdisFDeregisterFilterDriver(gOvsExtDriverHandle);
        gOvsExtDriverHandle = NULL;
        goto cleanup;
    }

cleanup:
    if (status != NDIS_STATUS_SUCCESS){
        OvsCleanup();
    }

    return status;
}


/*
 * --------------------------------------------------------------------------
 * Un-init/Unload function for the OVS intermediate Driver.
 * --------------------------------------------------------------------------
 */
VOID
OvsExtUnload(struct _DRIVER_OBJECT *driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);

    OvsDeleteDeviceObject();

    NdisFDeregisterFilterDriver(gOvsExtDriverHandle);

    /* Release driver associated data structures. */
    OvsCleanup();
}


/*
 * --------------------------------------------------------------------------
 *  Implements filter driver's FilterStatus function.
 * --------------------------------------------------------------------------
 */
VOID
OvsExtStatus(NDIS_HANDLE filterModuleContext,
             PNDIS_STATUS_INDICATION statusIndication)
{
    UNREFERENCED_PARAMETER(statusIndication);
    POVS_SWITCH_CONTEXT switchObject = (POVS_SWITCH_CONTEXT)filterModuleContext;

    NdisFIndicateStatus(switchObject->NdisFilterHandle, statusIndication);
}
