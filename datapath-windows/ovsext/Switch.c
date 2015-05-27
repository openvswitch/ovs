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
 * This file contains the implementation of the management functionality of the
 * OVS.
 */

#include "precomp.h"

#include "Switch.h"
#include "Vport.h"
#include "Event.h"
#include "Flow.h"
#include "IpHelper.h"
#include "Oid.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_SWITCH
#include "Debug.h"

POVS_SWITCH_CONTEXT gOvsSwitchContext;
LONG volatile gOvsInAttach;
UINT64 ovsTimeIncrementPerTick;

extern NDIS_HANDLE gOvsExtDriverHandle;
extern NDIS_HANDLE gOvsExtDriverObject;
extern PDEVICE_OBJECT gOvsDeviceObject;

/*
 * Reference count used to prevent premature deallocation of the global switch
 * context structure, gOvsSwitchContext.
 */
volatile LONG      gOvsSwitchContextRefCount = 1;

static NDIS_STATUS OvsCreateSwitch(NDIS_HANDLE ndisFilterHandle,
                                   POVS_SWITCH_CONTEXT *switchContextOut);
static NDIS_STATUS OvsInitSwitchContext(POVS_SWITCH_CONTEXT switchContext);
static VOID OvsDeleteSwitch(POVS_SWITCH_CONTEXT switchContext);
static VOID OvsUninitSwitchContext(POVS_SWITCH_CONTEXT switchContext);
static NDIS_STATUS OvsActivateSwitch(POVS_SWITCH_CONTEXT switchContext);


/*
 * --------------------------------------------------------------------------
 *  Implements filter driver's FilterAttach function.
 *
 *  This function allocates the switch context, and initializes its necessary
 *  members.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsExtAttach(NDIS_HANDLE ndisFilterHandle,
             NDIS_HANDLE filterDriverContext,
             PNDIS_FILTER_ATTACH_PARAMETERS attachParameters)
{
    NDIS_STATUS status = NDIS_STATUS_FAILURE;
    NDIS_FILTER_ATTRIBUTES ovsExtAttributes;
    POVS_SWITCH_CONTEXT switchContext = NULL;

    UNREFERENCED_PARAMETER(filterDriverContext);

    OVS_LOG_TRACE("Enter: ndisFilterHandle %p", ndisFilterHandle);

    ASSERT(filterDriverContext == (NDIS_HANDLE)gOvsExtDriverObject);
    if (attachParameters->MiniportMediaType != NdisMedium802_3) {
        status = NDIS_STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    if (gOvsExtDriverHandle == NULL) {
        OVS_LOG_TRACE("Exit: OVSEXT driver is not loaded.");
        ASSERT(FALSE);
        goto cleanup;
    }

    if (gOvsSwitchContext) {
        OVS_LOG_TRACE("Exit: Failed to create OVS Switch, only one datapath is"
                      "supported, %p.", gOvsSwitchContext);
        goto cleanup;
    }

    if (InterlockedCompareExchange(&gOvsInAttach, 1, 0)) {
        /* Just fail the request. */
        OVS_LOG_TRACE("Exit: Failed to create OVS Switch, since another attach"
                      "instance is in attach process.");
        goto cleanup;
    }

    status = OvsInitIpHelper(ndisFilterHandle);
    if (status != STATUS_SUCCESS) {
        OVS_LOG_ERROR("Exit: Failed to initialize IP helper.");
        goto cleanup;
    }

    status = OvsCreateSwitch(ndisFilterHandle, &switchContext);
    if (status != NDIS_STATUS_SUCCESS) {
        OvsCleanupIpHelper();
        goto cleanup;
    }
    ASSERT(switchContext);

    /*
     * Register the switch context with NDIS so NDIS can pass it back to the
     * FilterXXX callback functions as the 'FilterModuleContext' parameter.
     */
    RtlZeroMemory(&ovsExtAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));
    ovsExtAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
    ovsExtAttributes.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
    ovsExtAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
    ovsExtAttributes.Flags = 0;

    NDIS_DECLARE_FILTER_MODULE_CONTEXT(OVS_SWITCH_CONTEXT);
    status = NdisFSetAttributes(ndisFilterHandle, switchContext, &ovsExtAttributes);
    if (status != NDIS_STATUS_SUCCESS) {
        OVS_LOG_ERROR("Failed to set attributes.");
        OvsCleanupIpHelper();
        goto cleanup;
    }

    /* Setup the state machine. */
    switchContext->controlFlowState = OvsSwitchAttached;
    switchContext->dataFlowState = OvsSwitchPaused;

    gOvsSwitchContext = switchContext;
    KeMemoryBarrier();

cleanup:
    gOvsInAttach = FALSE;
    if (status != NDIS_STATUS_SUCCESS) {
        if (switchContext != NULL) {
            OvsDeleteSwitch(switchContext);
        }
    }
    OVS_LOG_TRACE("Exit: status %x", status);

    return status;
}


/*
 * --------------------------------------------------------------------------
 *  This function allocated the switch context, and initializes its necessary
 *  members.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsCreateSwitch(NDIS_HANDLE ndisFilterHandle,
                POVS_SWITCH_CONTEXT *switchContextOut)
{
    NDIS_STATUS status;
    POVS_SWITCH_CONTEXT switchContext;
    NDIS_SWITCH_CONTEXT hostSwitchContext;
    NDIS_SWITCH_OPTIONAL_HANDLERS hostSwitchHandler;

    OVS_LOG_TRACE("Enter: Create switch object");

    switchContext = (POVS_SWITCH_CONTEXT) OvsAllocateMemoryWithTag(
        sizeof(OVS_SWITCH_CONTEXT), OVS_SWITCH_POOL_TAG);
    if (switchContext == NULL) {
        status = NDIS_STATUS_RESOURCES;
        goto create_switch_done;
    }
    RtlZeroMemory(switchContext, sizeof(OVS_SWITCH_CONTEXT));

    /* Initialize the switch. */
    hostSwitchHandler.Header.Type = NDIS_OBJECT_TYPE_SWITCH_OPTIONAL_HANDLERS;
    hostSwitchHandler.Header.Size = NDIS_SIZEOF_SWITCH_OPTIONAL_HANDLERS_REVISION_1;
    hostSwitchHandler.Header.Revision = NDIS_SWITCH_OPTIONAL_HANDLERS_REVISION_1;

    status = NdisFGetOptionalSwitchHandlers(ndisFilterHandle,
                                            &hostSwitchContext,
                                            &hostSwitchHandler);
    if (status != NDIS_STATUS_SUCCESS) {
        OVS_LOG_ERROR("OvsExtAttach: Extension is running in "
                      "non-switch environment.");
        OvsFreeMemoryWithTag(switchContext, OVS_SWITCH_POOL_TAG);
        goto create_switch_done;
    }

    switchContext->NdisFilterHandle = ndisFilterHandle;
    switchContext->NdisSwitchContext = hostSwitchContext;
    RtlCopyMemory(&switchContext->NdisSwitchHandlers, &hostSwitchHandler,
                  sizeof(NDIS_SWITCH_OPTIONAL_HANDLERS));

    status = OvsInitSwitchContext(switchContext);
    if (status != NDIS_STATUS_SUCCESS) {
        OvsFreeMemoryWithTag(switchContext, OVS_SWITCH_POOL_TAG);
        goto create_switch_done;
    }

    status = OvsInitTunnelFilter(gOvsExtDriverObject, gOvsDeviceObject);
    if (status != NDIS_STATUS_SUCCESS) {
        OvsUninitSwitchContext(switchContext);
        goto create_switch_done;
    }

    *switchContextOut = switchContext;

create_switch_done:
    OVS_LOG_TRACE("Exit: switchContext: %p status: %#lx",
                  switchContext, status);
    return status;
}


/*
 * --------------------------------------------------------------------------
 *  Implements filter driver's FilterDetach function.
 * --------------------------------------------------------------------------
 */
_Use_decl_annotations_
VOID
OvsExtDetach(NDIS_HANDLE filterModuleContext)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)filterModuleContext;

    OVS_LOG_TRACE("Enter: filterModuleContext %p", filterModuleContext);

    ASSERT(switchContext->dataFlowState == OvsSwitchPaused);
    switchContext->controlFlowState = OvsSwitchDetached;
    KeMemoryBarrier();
    while(switchContext->pendingOidCount > 0) {
        NdisMSleep(1000);
    }
    OvsDeleteSwitch(switchContext);
    OvsCleanupIpHelper();
    gOvsSwitchContext = NULL;
    /* This completes the cleanup, and a new attach can be handled now. */

    OVS_LOG_TRACE("Exit: OvsDetach Successfully");
}


/*
 * --------------------------------------------------------------------------
 *  This function deletes the switch by freeing all memory previously allocated.
 *  XXX need synchronization with other path.
 * --------------------------------------------------------------------------
 */
VOID
OvsDeleteSwitch(POVS_SWITCH_CONTEXT switchContext)
{
    UINT32 dpNo = (UINT32) -1;

    OVS_LOG_TRACE("Enter: switchContext:%p", switchContext);

    if (switchContext)
    {
        dpNo = switchContext->dpNo;
        OvsClearAllSwitchVports(switchContext);
        OvsUninitTunnelFilter(gOvsExtDriverObject);
        OvsUninitSwitchContext(switchContext);
    }
    OVS_LOG_TRACE("Exit: deleted switch %p  dpNo: %d", switchContext, dpNo);
}


/*
 * --------------------------------------------------------------------------
 *  Implements filter driver's FilterRestart function.
 * --------------------------------------------------------------------------
 */
_Use_decl_annotations_
NDIS_STATUS
OvsExtRestart(NDIS_HANDLE filterModuleContext,
              PNDIS_FILTER_RESTART_PARAMETERS filterRestartParameters)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)filterModuleContext;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    BOOLEAN switchActive;

    UNREFERENCED_PARAMETER(filterRestartParameters);

    OVS_LOG_TRACE("Enter: filterModuleContext %p",
                  filterModuleContext);

    /* Activate the switch if this is the first restart. */
    if (!switchContext->isActivated && !switchContext->isActivateFailed) {
        status = OvsQuerySwitchActivationComplete(switchContext,
                                                  &switchActive);
        if (status != NDIS_STATUS_SUCCESS) {
            switchContext->isActivateFailed = TRUE;
            status = NDIS_STATUS_RESOURCES;
            goto cleanup;
        }

        if (switchActive) {
            status = OvsActivateSwitch(switchContext);

            if (status != NDIS_STATUS_SUCCESS) {
                OVS_LOG_WARN("Failed to activate switch, dpNo:%d",
                             switchContext->dpNo);
                status = NDIS_STATUS_RESOURCES;
                goto cleanup;
            }
        }
    }

    ASSERT(switchContext->dataFlowState == OvsSwitchPaused);
    switchContext->dataFlowState = OvsSwitchRunning;

cleanup:
    OVS_LOG_TRACE("Exit: Restart switch:%p, dpNo: %d, status: %#x",
                  switchContext, switchContext->dpNo, status);
    return status;
}


/*
 * --------------------------------------------------------------------------
 *  Implements filter driver's FilterPause function
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsExtPause(NDIS_HANDLE filterModuleContext,
            PNDIS_FILTER_PAUSE_PARAMETERS pauseParameters)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)filterModuleContext;

    UNREFERENCED_PARAMETER(pauseParameters);
    OVS_LOG_TRACE("Enter: filterModuleContext %p",
                  filterModuleContext);

    ASSERT(switchContext->dataFlowState == OvsSwitchRunning);
    switchContext->dataFlowState = OvsSwitchPaused;
    KeMemoryBarrier();
    while(switchContext->pendingOidCount > 0) {
        NdisMSleep(1000);
    }

    OVS_LOG_TRACE("Exit: OvsDetach Successfully");
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
OvsInitSwitchContext(POVS_SWITCH_CONTEXT switchContext)
{
    int i;
    NTSTATUS status;

    OVS_LOG_TRACE("Enter: switchContext: %p", switchContext);

    switchContext->dispatchLock =
        NdisAllocateRWLock(switchContext->NdisFilterHandle);

    switchContext->portNoHashArray = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_MAX_VPORT_ARRAY_SIZE, OVS_SWITCH_POOL_TAG);
    switchContext->ovsPortNameHashArray = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_MAX_VPORT_ARRAY_SIZE, OVS_SWITCH_POOL_TAG);
    switchContext->portIdHashArray= (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_MAX_VPORT_ARRAY_SIZE, OVS_SWITCH_POOL_TAG);
    switchContext->pidHashArray = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_MAX_PID_ARRAY_SIZE, OVS_SWITCH_POOL_TAG);
    switchContext->tunnelVportsArray = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_MAX_VPORT_ARRAY_SIZE, OVS_SWITCH_POOL_TAG);
    status = OvsAllocateFlowTable(&switchContext->datapath, switchContext);

    if (status == NDIS_STATUS_SUCCESS) {
        status = OvsInitBufferPool(switchContext);
    }
    if (status != NDIS_STATUS_SUCCESS ||
        switchContext->dispatchLock == NULL ||
        switchContext->portNoHashArray == NULL ||
        switchContext->ovsPortNameHashArray == NULL ||
        switchContext->portIdHashArray== NULL ||
        switchContext->pidHashArray == NULL ||
        switchContext->tunnelVportsArray == NULL) {
        if (switchContext->dispatchLock) {
            NdisFreeRWLock(switchContext->dispatchLock);
        }
        if (switchContext->portNoHashArray) {
            OvsFreeMemoryWithTag(switchContext->portNoHashArray,
                                 OVS_SWITCH_POOL_TAG);
        }
        if (switchContext->ovsPortNameHashArray) {
            OvsFreeMemoryWithTag(switchContext->ovsPortNameHashArray,
                                 OVS_SWITCH_POOL_TAG);
        }
        if (switchContext->portIdHashArray) {
            OvsFreeMemoryWithTag(switchContext->portIdHashArray,
                                 OVS_SWITCH_POOL_TAG);
        }
        if (switchContext->pidHashArray) {
            OvsFreeMemoryWithTag(switchContext->pidHashArray,
                                 OVS_SWITCH_POOL_TAG);
        }

        if (switchContext->tunnelVportsArray) {
            OvsFreeMemory(switchContext->tunnelVportsArray);
        }

        OvsDeleteFlowTable(&switchContext->datapath);
        OvsCleanupBufferPool(switchContext);

        OVS_LOG_TRACE("Exit: Failed to init switchContext");
        return NDIS_STATUS_RESOURCES;
    }

    for (i = 0; i < OVS_MAX_VPORT_ARRAY_SIZE; i++) {
        InitializeListHead(&switchContext->ovsPortNameHashArray[i]);
        InitializeListHead(&switchContext->portIdHashArray[i]);
        InitializeListHead(&switchContext->portNoHashArray[i]);
        InitializeListHead(&switchContext->tunnelVportsArray[i]);
    }

    for (i = 0; i < OVS_MAX_PID_ARRAY_SIZE; i++) {
        InitializeListHead(&switchContext->pidHashArray[i]);
    }

    NdisAllocateSpinLock(&(switchContext->pidHashLock));
    switchContext->isActivated = FALSE;
    switchContext->isActivateFailed = FALSE;
    switchContext->dpNo = OVS_DP_NUMBER;
    ovsTimeIncrementPerTick = KeQueryTimeIncrement() / 10000;

    OVS_LOG_TRACE("Exit: Succesfully initialized switchContext: %p",
                  switchContext);
    return NDIS_STATUS_SUCCESS;
}

static VOID
OvsUninitSwitchContext(POVS_SWITCH_CONTEXT switchContext)
{
    OvsReleaseSwitchContext(switchContext);
}

/*
 * --------------------------------------------------------------------------
 *  Frees up the contents of and also the switch context.
 * --------------------------------------------------------------------------
 */
static VOID
OvsDeleteSwitchContext(POVS_SWITCH_CONTEXT switchContext)
{
    OVS_LOG_TRACE("Enter: Delete switchContext:%p", switchContext);

    /* We need to do cleanup for tunnel port here. */
    ASSERT(switchContext->numHvVports == 0);
    ASSERT(switchContext->numNonHvVports == 0);

    NdisFreeRWLock(switchContext->dispatchLock);
    switchContext->dispatchLock = NULL;
    NdisFreeSpinLock(&(switchContext->pidHashLock));
    OvsFreeMemoryWithTag(switchContext->ovsPortNameHashArray,
                         OVS_SWITCH_POOL_TAG);
    switchContext->ovsPortNameHashArray = NULL;
    OvsFreeMemoryWithTag(switchContext->portIdHashArray,
                         OVS_SWITCH_POOL_TAG);
    switchContext->portIdHashArray = NULL;
    OvsFreeMemoryWithTag(switchContext->portNoHashArray,
                         OVS_SWITCH_POOL_TAG);
    switchContext->portNoHashArray = NULL;
    OvsFreeMemoryWithTag(switchContext->pidHashArray,
                         OVS_SWITCH_POOL_TAG);
    switchContext->pidHashArray = NULL;
    OvsFreeMemory(switchContext->tunnelVportsArray);
    switchContext->tunnelVportsArray = NULL;
    OvsDeleteFlowTable(&switchContext->datapath);
    OvsCleanupBufferPool(switchContext);

    OvsFreeMemoryWithTag(switchContext, OVS_SWITCH_POOL_TAG);
    OVS_LOG_TRACE("Exit: Delete switchContext: %p", switchContext);
}

VOID
OvsReleaseSwitchContext(POVS_SWITCH_CONTEXT switchContext)
{
    LONG ref = 0;
    LONG newRef = 0;
    LONG icxRef = 0;

    do {
        ref = gOvsSwitchContextRefCount;
        newRef = (0 == ref) ? 0 : ref - 1;
        icxRef = InterlockedCompareExchange(&gOvsSwitchContextRefCount,
                                            newRef,
                                            ref);
    } while (icxRef != ref);

    if (ref == 1) {
        OvsDeleteSwitchContext(switchContext);
    }
}

BOOLEAN
OvsAcquireSwitchContext(VOID)
{
    LONG ref = 0;
    LONG newRef = 0;
    LONG icxRef = 0;
    BOOLEAN ret = FALSE;

    do {
        ref = gOvsSwitchContextRefCount;
        newRef = (0 == ref) ? 0 : ref + 1;
        icxRef = InterlockedCompareExchange(&gOvsSwitchContextRefCount,
                                            newRef,
                                            ref);
    } while (icxRef != ref);

    if (ref != 0) {
        ret = TRUE;
    }

    return ret;
}

/*
 * --------------------------------------------------------------------------
 *  This function activates the switch by initializing it with all the runtime
 *  state. First it queries all of the MAC addresses set as custom switch policy
 *  to allow sends from, and adds tme to the property list. Then it queries the
 *  NIC list and verifies it can support all of the NICs currently connected to
 *  the switch, and adds the NICs to the NIC list.
 * --------------------------------------------------------------------------
 */
static NDIS_STATUS
OvsActivateSwitch(POVS_SWITCH_CONTEXT switchContext)
{
    NDIS_STATUS status;

    ASSERT(!switchContext->isActivated);

    OVS_LOG_TRACE("Enter: activate switch %p, dpNo: %ld",
                  switchContext, switchContext->dpNo);

    status = OvsAddConfiguredSwitchPorts(switchContext);

    if (status != NDIS_STATUS_SUCCESS) {
        OVS_LOG_WARN("Failed to add configured switch ports");
        goto cleanup;

    }
    status = OvsInitConfiguredSwitchNics(switchContext);

    if (status != NDIS_STATUS_SUCCESS) {
        OVS_LOG_WARN("Failed to add configured vports");
        OvsClearAllSwitchVports(switchContext);
        goto cleanup;
    }
    switchContext->isActivated = TRUE;
    OvsPostEvent(OVS_DEFAULT_PORT_NO, OVS_DEFAULT_EVENT_STATUS);

cleanup:
    OVS_LOG_TRACE("Exit: activate switch:%p, isActivated: %s, status = %lx",
                  switchContext,
                  (switchContext->isActivated ? "TRUE" : "FALSE"), status);
    return status;
}


/*
 * --------------------------------------------------------------------------
 * Implements filter driver's FilterNetPnPEvent function.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsExtNetPnPEvent(NDIS_HANDLE filterModuleContext,
                  PNET_PNP_EVENT_NOTIFICATION netPnPEvent)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)filterModuleContext;
    BOOLEAN switchActive;

    OVS_LOG_TRACE("Enter: filterModuleContext: %p, NetEvent: %d",
                  filterModuleContext, (netPnPEvent->NetPnPEvent).NetEvent);
    /*
     * The only interesting event is the NetEventSwitchActivate. It provides
     * an asynchronous notification of the switch completing activation.
     */
    if (netPnPEvent->NetPnPEvent.NetEvent == NetEventSwitchActivate) {
        status = OvsQuerySwitchActivationComplete(switchContext, &switchActive);
        if (status != NDIS_STATUS_SUCCESS) {
            switchContext->isActivateFailed = TRUE;
        } else {
            ASSERT(switchContext->isActivated == FALSE);
            if (switchContext->isActivated == FALSE && switchActive == TRUE) {
                status = OvsActivateSwitch(switchContext);
                OVS_LOG_TRACE("OvsExtNetPnPEvent: activated switch: %p "
                              "status: %s", switchContext,
                              status ? "TRUE" : "FALSE");
            }
        }
    }

    if (status == NDIS_STATUS_SUCCESS) {
        status = NdisFNetPnPEvent(switchContext->NdisFilterHandle,
                                  netPnPEvent);
    }
    OVS_LOG_TRACE("Exit: OvsExtNetPnPEvent");

    return status;
}
