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

#include "Datapath.h"
#include "Event.h"
#include "Gre.h"
#include "IpHelper.h"
#include "Jhash.h"
#include "Oid.h"
#include "Stt.h"
#include "Switch.h"
#include "User.h"
#include "Vport.h"
#include "Vxlan.h"
#include "Geneve.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_VPORT
#include "Debug.h"

#define VPORT_NIC_ENTER(_nic) \
    OVS_LOG_TRACE("Enter: PortId: %x, NicIndex: %d", _nic->PortId, \
                                                     _nic->NicIndex)

#define VPORT_NIC_EXIT(_nic) \
    OVS_LOG_TRACE("Exit: PortId: %x, NicIndex: %d", _nic->PortId, \
                                                    _nic->NicIndex)

#define VPORT_PORT_ENTER(_port) \
    OVS_LOG_TRACE("Enter: PortId: %x", _port->PortId)

#define VPORT_PORT_EXIT(_port) \
    OVS_LOG_TRACE("Exit: PortId: %x", _port->PortId)

#define OVS_VPORT_DEFAULT_WAIT_TIME_MICROSEC    100

/* Context structure used to pass back and forth information to the tunnel
 * filter threads. */
typedef struct _OVS_TUNFLT_INIT_CONTEXT {
    POVS_SWITCH_CONTEXT switchContext;
    UINT32 outputLength;
    PVOID outputBuffer;
    PVOID inputBuffer;
    POVS_VPORT_ENTRY vport;
    BOOLEAN hvSwitchPort;
    BOOLEAN hvDelete;
    BOOLEAN ovsDelete;
} OVS_TUNFLT_INIT_CONTEXT, *POVS_TUNFLT_INIT_CONTEXT;


extern POVS_SWITCH_CONTEXT gOvsSwitchContext;

static VOID OvsInitVportWithPortParam(POVS_VPORT_ENTRY vport,
                PNDIS_SWITCH_PORT_PARAMETERS portParam);
static VOID OvsInitVportWithNicParam(POVS_SWITCH_CONTEXT switchContext,
                POVS_VPORT_ENTRY vport, PNDIS_SWITCH_NIC_PARAMETERS nicParam);
static VOID OvsCopyPortParamsFromVport(POVS_VPORT_ENTRY vport,
                                       PNDIS_SWITCH_PORT_PARAMETERS portParam);
static __inline VOID OvsWaitActivate(POVS_SWITCH_CONTEXT switchContext,
                                     ULONG sleepMicroSec);
static NTSTATUS OvsGetExtInfoIoctl(POVS_VPORT_GET vportGet,
                                   POVS_VPORT_EXT_INFO extInfo);
static NTSTATUS CreateNetlinkMesgForNetdev(POVS_VPORT_EXT_INFO info,
                                           POVS_MESSAGE msgIn,
                                           PVOID outBuffer,
                                           UINT32 outBufLen,
                                           int dpIfIndex);
static VOID UpdateSwitchCtxWithVport(POVS_SWITCH_CONTEXT switchContext,
                                     POVS_VPORT_ENTRY vport, BOOLEAN newPort);
static NTSTATUS OvsRemoveTunnelVport(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                     POVS_SWITCH_CONTEXT switchContext,
                                     POVS_VPORT_ENTRY vport,
                                     BOOLEAN hvDelete,
                                     BOOLEAN ovsDelete);
static VOID OvsTunnelVportPendingInit(PVOID context,
                                      NTSTATUS status,
                                      UINT32 *replyLen);
static VOID OvsTunnelVportPendingRemove(PVOID context,
                                        NTSTATUS status,
                                        UINT32 *replyLen);
static NTSTATUS GetNICAlias(PNDIS_SWITCH_NIC_PARAMETERS nicParam,
                            IF_COUNTED_STRING *portFriendlyName);
static NTSTATUS OvsConvertIfCountedStrToAnsiStr(PIF_COUNTED_STRING wStr,
                                                CHAR *str,
                                                UINT16 maxStrLen);

/*
 * --------------------------------------------------------------------------
 *  Creates a Vport entry for a Hyper-V switch port. 'nicIndex' is typically
 *  associated with a NIC than a port. We use it here for the special case
 *  where we need to create a Vport for an external NIC with NicIndex > 0.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
HvCreatePort(POVS_SWITCH_CONTEXT switchContext,
             PNDIS_SWITCH_PORT_PARAMETERS portParam,
             NDIS_SWITCH_NIC_INDEX nicIndex)
{
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    BOOLEAN newPort = FALSE;

    VPORT_PORT_ENTER(portParam);

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    /* Lookup by port ID. */
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            portParam->PortId, nicIndex);
    if (vport != NULL) {
        OVS_LOG_ERROR("Port add failed due to duplicate port name, "
                      "port Id: %u", portParam->PortId);
        status = STATUS_DATA_NOT_ACCEPTED;
        goto create_port_done;
    }

    /*
     * Lookup by port name to see if this port with this name had been added
     * (and deleted) previously.
     */
    vport = OvsFindVportByHvNameW(gOvsSwitchContext,
                                  portParam->PortFriendlyName.String,
                                  portParam->PortFriendlyName.Length);
    if (vport && vport->isAbsentOnHv == FALSE) {
        OVS_LOG_ERROR("Port add failed since a port already exists on "
                      "the specified port Id: %u, ovsName: %s",
                      portParam->PortId, vport->ovsName);
        status = STATUS_DATA_NOT_ACCEPTED;
        goto create_port_done;
    }

    if (vport != NULL) {
        ASSERT(vport->isAbsentOnHv);
        ASSERT(vport->portNo != OVS_DPPORT_NUMBER_INVALID);

        /*
         * It should be possible to simply just mark this port as "not deleted"
         * given that the port Id and the name are the same and also provided
         * that the other properties that we cache have not changed.
         */
        if (vport->portType != portParam->PortType) {
            OVS_LOG_INFO("Port add failed due to PortType change, port Id: %u"
                         " old: %u, new: %u", portParam->PortId,
                         vport->portType, portParam->PortType);
            status = STATUS_DATA_NOT_ACCEPTED;
            goto create_port_done;
        }
        vport->isAbsentOnHv = FALSE;
    } else {
        vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
        if (vport == NULL) {
            status = NDIS_STATUS_RESOURCES;
            goto create_port_done;
        }
        newPort = TRUE;
    }
    OvsInitVportWithPortParam(vport, portParam);
    vport->nicIndex = nicIndex;
    UpdateSwitchCtxWithVport(switchContext, vport, newPort);

create_port_done:
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    VPORT_PORT_EXIT(portParam);
    return status;
}


/*
 * --------------------------------------------------------------------------
 * Function to process updates to a port on the Hyper-Vs witch.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
HvUpdatePort(POVS_SWITCH_CONTEXT switchContext,
             PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;
    OVS_VPORT_STATE ovsState;
    NDIS_SWITCH_NIC_STATE nicState;

    VPORT_PORT_ENTER(portParam);

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            portParam->PortId, 0);
    /*
     * Update properties only for NETDEV ports for supprting PS script
     */
    if (vport == NULL) {
        goto update_port_done;
    }

    /* Store the nic and the OVS states as Nic Create won't be called */
    ovsState = vport->ovsState;
    nicState = vport->nicState;

    /*
     * Currently only the port friendly name is being updated
     * Make sure that no other properties are changed
     */
    ASSERT(portParam->PortId == vport->portId);
    ASSERT(portParam->PortState == vport->portState);
    ASSERT(portParam->PortType == vport->portType);

    /*
     * Call the set parameters function the handle all properties
     * change in a single place in case future version supports change of
     * other properties
     */
    OvsInitVportWithPortParam(vport, portParam);
    /* Retore the nic and OVS states */
    vport->nicState = nicState;
    vport->ovsState = ovsState;

update_port_done:
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    VPORT_PORT_EXIT(portParam);

    /* Must always return success */
    return NDIS_STATUS_SUCCESS;
}


/*
 * --------------------------------------------------------------------------
 * Function to process teardown of a port on the Hyper-V switch.
 * --------------------------------------------------------------------------
 */
VOID
HvTeardownPort(POVS_SWITCH_CONTEXT switchContext,
               PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;

    VPORT_PORT_ENTER(portParam);

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            portParam->PortId, 0);
    if (vport) {
        /* add assertion here */
        vport->portState = NdisSwitchPortStateTeardown;
        vport->ovsState = OVS_STATE_PORT_TEAR_DOWN;
    } else {
        OVS_LOG_WARN("Vport not present.");
    }
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

    VPORT_PORT_EXIT(portParam);
}

/*
 * --------------------------------------------------------------------------
 * Function to process deletion of a port on the Hyper-V switch.
 * --------------------------------------------------------------------------
 */
VOID
HvDeletePort(POVS_SWITCH_CONTEXT switchContext,
             PNDIS_SWITCH_PORT_PARAMETERS portParams)
{
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;

    VPORT_PORT_ENTER(portParams);

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            portParams->PortId, 0);

    /*
     * XXX: we can only destroy and remove the port if its datapath port
     * counterpart was deleted. If the datapath port counterpart is present,
     * we only mark the vport for deletion, so that a netlink command vport
     * delete will delete the vport.
    */
    if (vport) {
        OVS_VPORT_EVENT_ENTRY event;

        event.portNo = vport->portNo;
        event.ovsType = vport->ovsType;
        event.upcallPid = vport->upcallPid;
        RtlCopyMemory(&event.ovsName, &vport->ovsName, sizeof event.ovsName);
        event.type = OVS_EVENT_LINK_DOWN;
        OvsRemoveAndDeleteVport(NULL, switchContext, vport, TRUE, FALSE);
        OvsPostVportEvent(&event);
    } else {
        OVS_LOG_WARN("Vport not present.");
    }
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

    VPORT_PORT_EXIT(portParams);
}


/*
 * --------------------------------------------------------------------------
 * Function to process addition of a NIC connection on the Hyper-V switch.
 * XXX: Posting an event to DPIF is incorrect here. However, it might be useful
 * to post an event to netdev-windows.c.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
HvCreateNic(POVS_SWITCH_CONTEXT switchContext,
            PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    POVS_VPORT_ENTRY vport;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    IF_COUNTED_STRING portFriendlyName = {0};
    LOCK_STATE_EX lockState;

    VPORT_NIC_ENTER(nicParam);

    /* Wait for lists to be initialized. */
    OvsWaitActivate(switchContext, OVS_VPORT_DEFAULT_WAIT_TIME_MICROSEC);

    if (!switchContext->isActivated) {
        OVS_LOG_WARN("Switch is not activated yet.");
        /* Veto the creation of nic */
        status = NDIS_STATUS_NOT_SUPPORTED;
        goto done;
    }

    if (OvsIsInternalNIC(nicParam->NicType) ||
        OvsIsRealExternalNIC(nicParam->NicType, nicParam->NicIndex)) {
        GetNICAlias(nicParam, &portFriendlyName);
    }

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    /*
     * There can be one or more NICs for the external port. We create a vport
     * structure for each such NIC, and each NIC inherits a lot of properties
     * from the parent external port.
     */
    if (OvsIsRealExternalNIC(nicParam->NicType, nicParam->NicIndex)) {
        /* The VPORT can be bound to OVS datapath already. Search for it
         * using its friendly name and if not found allocate a new port
         */
        ASSERT(OvsFindVportByPortIdAndNicIndex(switchContext,
                                               nicParam->PortId,
                                               nicParam->NicIndex) == NULL);
        char convertString[256];
        RtlZeroMemory(convertString, 256);
        NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
        status = OvsConvertIfCountedStrToAnsiStr(&portFriendlyName,
                                                 convertString,
                                                 OVS_MAX_PORT_NAME_LENGTH);
        NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
        if (status != NDIS_STATUS_SUCCESS) {
            goto add_nic_done;
        }
        POVS_VPORT_ENTRY ovsVport = OvsFindVportByOvsName(switchContext,
                                                          convertString);
        if (ovsVport != NULL) {
            UpdateSwitchCtxWithVport(switchContext, ovsVport, FALSE);
        } else {
            NDIS_SWITCH_PORT_PARAMETERS portParam;
            POVS_VPORT_ENTRY virtExtVport =
                (POVS_VPORT_ENTRY)switchContext->virtualExternalVport;

            ASSERT(virtExtVport);
            OvsCopyPortParamsFromVport(virtExtVport, &portParam);
            NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
            status = HvCreatePort(switchContext, &portParam,
                                  nicParam->NicIndex);
            NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
            if (status != NDIS_STATUS_SUCCESS) {
                goto add_nic_done;
            }
        }
    }

    vport = OvsFindVportByPortIdAndNicIndex(switchContext, nicParam->PortId,
                                            nicParam->NicIndex);

    if (vport == NULL) {
        OVS_LOG_ERROR("Create NIC without Switch Port,"
                      " PortId: %x, NicIndex: %d",
                      nicParam->PortId, nicParam->NicIndex);
        status = NDIS_STATUS_INVALID_PARAMETER;
        goto add_nic_done;
    }
    OvsInitVportWithNicParam(switchContext, vport, nicParam);
    if (OvsIsInternalNIC(nicParam->NicType) ||
        OvsIsRealExternalNIC(nicParam->NicType, nicParam->NicIndex)) {
        RtlCopyMemory(&vport->portFriendlyName, &portFriendlyName,
                      sizeof portFriendlyName);
    }

add_nic_done:
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

done:
    VPORT_NIC_EXIT(nicParam);
    OVS_LOG_TRACE("Exit: status %8x.\n", status);

    return status;
}

/*
 * --------------------------------------------------------------------------
 * Function to process connection event of a NIC on the Hyper-V switch.
 * --------------------------------------------------------------------------
 */
VOID
HvConnectNic(POVS_SWITCH_CONTEXT switchContext,
             PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    LOCK_STATE_EX lockState;
    POVS_VPORT_ENTRY vport;

    VPORT_NIC_ENTER(nicParam);

    /* Wait for lists to be initialized. */
    OvsWaitActivate(switchContext, OVS_VPORT_DEFAULT_WAIT_TIME_MICROSEC);

    if (!switchContext->isActivated) {
        OVS_LOG_WARN("Switch is not activated yet.");
        goto done;
    }

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            nicParam->PortId,
                                            nicParam->NicIndex);

    if (!vport) {
        OVS_LOG_WARN("Vport not present.");
        NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
        ASSERT(0);
        goto done;
    }

    vport->ovsState = OVS_STATE_CONNECTED;
    vport->nicState = NdisSwitchNicStateConnected;

    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

    if (nicParam->NicType == NdisSwitchNicTypeInternal) {
        OvsInternalAdapterUp(vport->portNo, &vport->netCfgInstanceId);
    }

done:
    VPORT_NIC_EXIT(nicParam);
}


/*
 * --------------------------------------------------------------------------
 * Function to process updates to a NIC on the Hyper-V switch.
 * --------------------------------------------------------------------------
 */
VOID
HvUpdateNic(POVS_SWITCH_CONTEXT switchContext,
            PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;
    UINT32 event = 0;
    IF_COUNTED_STRING portFriendlyName = {0};
    BOOLEAN nameChanged = FALSE;
    BOOLEAN aliasLookup = FALSE;

    VPORT_NIC_ENTER(nicParam);

    /* Wait for lists to be initialized. */
    OvsWaitActivate(switchContext, OVS_VPORT_DEFAULT_WAIT_TIME_MICROSEC);

    if (!switchContext->isActivated) {
        OVS_LOG_WARN("Switch is not activated yet.");
        goto update_nic_done;
    }

    /* GetNICAlias() must be called outside of a lock. */
    if (nicParam->NicType == NdisSwitchNicTypeInternal ||
        OvsIsRealExternalNIC(nicParam->NicType, nicParam->NicIndex)) {
        GetNICAlias(nicParam, &portFriendlyName);
        aliasLookup = TRUE;
    }

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            nicParam->PortId,
                                            nicParam->NicIndex);
    if (vport == NULL) {
        NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
        OVS_LOG_WARN("Vport search failed.");
        goto update_nic_done;
    }
    switch (nicParam->NicType) {
    case NdisSwitchNicTypeExternal:
    case NdisSwitchNicTypeInternal:
        RtlCopyMemory(&vport->netCfgInstanceId, &nicParam->NetCfgInstanceId,
                      sizeof (GUID));
        if (aliasLookup) {
            if (RtlCompareMemory(&vport->portFriendlyName,
                    &portFriendlyName, vport->portFriendlyName.Length) !=
                    vport->portFriendlyName.Length) {
                RtlCopyMemory(&vport->portFriendlyName, &portFriendlyName,
                    sizeof portFriendlyName);
                nameChanged = TRUE;
            }
        }
        break;
    case NdisSwitchNicTypeSynthetic:
    case NdisSwitchNicTypeEmulated:
        if (!RtlEqualMemory(vport->vmMacAddress, nicParam->VMMacAddress,
                           sizeof (vport->vmMacAddress))) {
            event |= OVS_EVENT_MAC_CHANGE;
            RtlCopyMemory(vport->vmMacAddress, nicParam->VMMacAddress,
                          sizeof (vport->vmMacAddress));
        }
        break;
    default:
        ASSERT(0);
    }
    if (!RtlEqualMemory(vport->permMacAddress, nicParam->PermanentMacAddress,
                        sizeof (vport->permMacAddress))) {
        RtlCopyMemory(vport->permMacAddress, nicParam->PermanentMacAddress,
                      sizeof (vport->permMacAddress));
        event |= OVS_EVENT_MAC_CHANGE;
    }
    if (!RtlEqualMemory(vport->currMacAddress, nicParam->CurrentMacAddress,
                        sizeof (vport->currMacAddress))) {
        RtlCopyMemory(vport->currMacAddress, nicParam->CurrentMacAddress,
                      sizeof (vport->currMacAddress));
        event |= OVS_EVENT_MAC_CHANGE;
    }

    if (vport->mtu != nicParam->MTU) {
        vport->mtu = nicParam->MTU;
        event |= OVS_EVENT_MTU_CHANGE;
    }
    vport->numaNodeId = nicParam->NumaNodeId;

    if (nameChanged) {
        OVS_VPORT_EVENT_ENTRY evt;
        evt.portNo = vport->portNo;
        evt.ovsType = vport->ovsType;
        evt.upcallPid = vport->upcallPid;
        RtlCopyMemory(&evt.ovsName, &vport->ovsName, sizeof evt.ovsName);
        evt.type = OVS_EVENT_LINK_DOWN;
        OvsRemoveAndDeleteVport(NULL, switchContext, vport, FALSE, TRUE);
        OvsPostVportEvent(&evt);
    }

    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

    /*
     * XXX: Not sure what kind of event to post here. DPIF is not interested in
     * changes to MAC address. Netdev-windows might be intrested, though.
     * That said, if the name chagnes, not clear what kind of event to be
     * posted. We might have to delete the vport, and have userspace recreate
     * it.
     */

update_nic_done:
    VPORT_NIC_EXIT(nicParam);
}

/*
 * --------------------------------------------------------------------------
 * Function to process disconnect event of a NIC on the Hyper-V switch.
 * --------------------------------------------------------------------------
 */
VOID
HvDisconnectNic(POVS_SWITCH_CONTEXT switchContext,
                PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;
    BOOLEAN isInternalPort = FALSE;
    OVS_VPORT_EVENT_ENTRY event;

    VPORT_NIC_ENTER(nicParam);

    /* Wait for lists to be initialized. */
    OvsWaitActivate(switchContext, OVS_VPORT_DEFAULT_WAIT_TIME_MICROSEC);

    if (!switchContext->isActivated) {
        OVS_LOG_WARN("Switch is not activated yet.");
        goto done;
    }

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            nicParam->PortId,
                                            nicParam->NicIndex);

    if (!vport) {
        OVS_LOG_WARN("Vport not present.");
        NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
        goto done;
    }

    vport->nicState = NdisSwitchNicStateDisconnected;
    vport->ovsState = OVS_STATE_NIC_CREATED;

    if (vport->ovsType == OVS_VPORT_TYPE_INTERNAL) {
        isInternalPort = TRUE;
    }

    event.portNo = vport->portNo;
    event.ovsType = vport->ovsType;
    event.upcallPid = vport->upcallPid;
    RtlCopyMemory(&event.ovsName, &vport->ovsName, sizeof event.ovsName);
    event.type = OVS_EVENT_LINK_DOWN;

    /*
     * Delete the port from the hash tables accessible to userspace. After this
     * point, userspace should not be able to access this port.
     */
    if (OvsIsRealExternalVport(vport)) {
        OvsRemoveAndDeleteVport(NULL, switchContext, vport, FALSE, TRUE);
        OvsPostVportEvent(&event);
    }
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

    if (isInternalPort) {
        OvsInternalAdapterDown(vport->portNo, vport->netCfgInstanceId);
        OvsRemoveAndDeleteVport(NULL, switchContext, vport, TRUE, TRUE);
        OvsPostVportEvent(&event);
    }

done:
    VPORT_NIC_EXIT(nicParam);
}

/*
 * --------------------------------------------------------------------------
 * Function to process delete event of a NIC on the Hyper-V switch.
 * --------------------------------------------------------------------------
 */
VOID
HvDeleteNic(POVS_SWITCH_CONTEXT switchContext,
            PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    LOCK_STATE_EX lockState;
    POVS_VPORT_ENTRY vport;

    VPORT_NIC_ENTER(nicParam);
    /* Wait for lists to be initialized. */
    OvsWaitActivate(switchContext, OVS_VPORT_DEFAULT_WAIT_TIME_MICROSEC);

    if (!switchContext->isActivated) {
        OVS_LOG_WARN("Switch is not activated yet.");
        goto done;
    }

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            nicParam->PortId,
                                            nicParam->NicIndex);

    if (!vport) {
        OVS_LOG_WARN("Vport not present.");
        NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
        goto done;
    }

    vport->nicState = NdisSwitchNicStateUnknown;
    vport->ovsState = OVS_STATE_PORT_CREATED;

    if (OvsIsRealExternalVport(vport)) {
        /* This vport was created in HvCreateNic(). */
        OvsRemoveAndDeleteVport(NULL, switchContext, vport, TRUE, FALSE);
    }

    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

done:
    VPORT_NIC_EXIT(nicParam);
}

/*
 * OVS Vport related functionality.
 */
POVS_VPORT_ENTRY
OvsFindVportByPortNo(POVS_SWITCH_CONTEXT switchContext,
                     UINT32 portNo)
{
    POVS_VPORT_ENTRY vport;
    PLIST_ENTRY head, link;
    UINT32 hash = OvsJhashBytes((const VOID *)&portNo, sizeof(portNo),
                                OVS_HASH_BASIS);
    head = &(switchContext->portNoHashArray[hash & OVS_VPORT_MASK]);
    LIST_FORALL(head, link) {
        vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, portNoLink);
        if (vport->portNo == portNo) {
            return vport;
        }
    }
    return NULL;
}


POVS_VPORT_ENTRY
OvsFindTunnelVportByDstPortAndType(POVS_SWITCH_CONTEXT switchContext,
                                   UINT16 dstPort,
                                   OVS_VPORT_TYPE ovsPortType)
{
    POVS_VPORT_ENTRY vport;
    PLIST_ENTRY head, link;
    UINT32 hash = OvsJhashBytes((const VOID *)&dstPort, sizeof(dstPort),
                                OVS_HASH_BASIS);
    head = &(switchContext->tunnelVportsArray[hash & OVS_VPORT_MASK]);
    LIST_FORALL(head, link) {
        vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, tunnelVportLink);
        if (GetPortFromPriv(vport) == dstPort &&
            vport->ovsType == ovsPortType) {
            return vport;
        }
    }
    return NULL;
}

POVS_VPORT_ENTRY
OvsFindTunnelVportByDstPortAndNWProto(POVS_SWITCH_CONTEXT switchContext,
                                      UINT16 dstPort,
                                      UINT8 nwProto)
{
    POVS_VPORT_ENTRY vport;
    PLIST_ENTRY head, link;
    UINT32 hash = OvsJhashBytes((const VOID *)&dstPort, sizeof(dstPort),
                                OVS_HASH_BASIS);
    head = &(switchContext->tunnelVportsArray[hash & OVS_VPORT_MASK]);
    LIST_FORALL(head, link) {
        vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, tunnelVportLink);
        if (GetPortFromPriv(vport) == dstPort) {
            switch (nwProto) {
            case IPPROTO_UDP:
                if (vport->ovsType != OVS_VPORT_TYPE_GENEVE &&
                    vport->ovsType != OVS_VPORT_TYPE_VXLAN) {
                    continue;
                }
                break;
            case IPPROTO_TCP:
                if (vport->ovsType != OVS_VPORT_TYPE_STT) {
                    continue;
                }
                break;
            case IPPROTO_GRE:
                break;
            default:
                continue;
            }
            return vport;
        }
    }
    return NULL;
}

POVS_VPORT_ENTRY
OvsFindTunnelVportByPortType(POVS_SWITCH_CONTEXT switchContext,
                             OVS_VPORT_TYPE ovsPortType)
{
    POVS_VPORT_ENTRY vport;
    PLIST_ENTRY head, link;
    UINT16 dstPort = 0;
    UINT32 hash = OvsJhashBytes((const VOID *)&dstPort, sizeof(dstPort),
                                OVS_HASH_BASIS);
    head = &(switchContext->tunnelVportsArray[hash & OVS_VPORT_MASK]);
    LIST_FORALL(head, link) {
        vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, tunnelVportLink);
        if (vport->ovsType == ovsPortType) {
            return vport;
        }
    }
    return NULL;
}

POVS_VPORT_ENTRY
OvsFindVportByOvsName(POVS_SWITCH_CONTEXT switchContext,
                      PSTR name)
{
    POVS_VPORT_ENTRY vport;
    PLIST_ENTRY head, link;
    UINT32 hash;
    SIZE_T length = strlen(name) + 1;

    hash = OvsJhashBytes((const VOID *)name, length, OVS_HASH_BASIS);
    head = &(switchContext->ovsPortNameHashArray[hash & OVS_VPORT_MASK]);

    LIST_FORALL(head, link) {
        vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, ovsNameLink);
        if (!strcmp(name, vport->ovsName)) {
            return vport;
        }
    }

    return NULL;
}

/* OvsFindVportByHvName: "name" is assumed to be null-terminated */
POVS_VPORT_ENTRY
OvsFindVportByHvNameW(POVS_SWITCH_CONTEXT switchContext,
                      PWSTR wsName, SIZE_T wstrSize)
{
    POVS_VPORT_ENTRY vport = NULL;
    PLIST_ENTRY head, link;
    UINT i;

    for (i = 0; i < OVS_MAX_VPORT_ARRAY_SIZE; i++) {
        head = &(switchContext->portIdHashArray[i]);
        LIST_FORALL(head, link) {
            vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, portIdLink);

            /*
             * NOTE about portFriendlyName:
             * If the string is NULL-terminated, the Length member does not
             * include the terminating NULL character.
             */
            if (vport->portFriendlyName.Length == wstrSize &&
                RtlEqualMemory(wsName, vport->portFriendlyName.String,
                               vport->portFriendlyName.Length)) {
                goto Cleanup;
            }

            vport = NULL;
        }
    }

    /*
     * Look in the list of ports that were added from the Hyper-V switch and
     * deleted.
     */
    if (vport == NULL) {
        for (i = 0; i < OVS_MAX_VPORT_ARRAY_SIZE; i++) {
            head = &(switchContext->portNoHashArray[i]);
            LIST_FORALL(head, link) {
                vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, portNoLink);
                if (vport->portFriendlyName.Length == wstrSize &&
                    RtlEqualMemory(wsName, vport->portFriendlyName.String,
                                   vport->portFriendlyName.Length)) {
                    goto Cleanup;
                }

                vport = NULL;
            }
        }
    }

Cleanup:
    return vport;
}

POVS_VPORT_ENTRY
OvsFindVportByHvNameA(POVS_SWITCH_CONTEXT switchContext,
                      PSTR name)
{
    POVS_VPORT_ENTRY vport = NULL;
    /* 'portFriendlyName' is not NUL-terminated. */
    SIZE_T length = strlen(name);
    SIZE_T wstrSize = length * sizeof(WCHAR);
    UINT i;

    PWSTR wsName = OvsAllocateMemoryWithTag(wstrSize, OVS_VPORT_POOL_TAG);
    if (!wsName) {
        return NULL;
    }
    for (i = 0; i < length; i++) {
        wsName[i] = name[i];
    }
    vport = OvsFindVportByHvNameW(switchContext, wsName, wstrSize);
    OvsFreeMemoryWithTag(wsName, OVS_VPORT_POOL_TAG);
    return vport;
}

POVS_VPORT_ENTRY
OvsFindVportByPortIdAndNicIndex(POVS_SWITCH_CONTEXT switchContext,
                                NDIS_SWITCH_PORT_ID portId,
                                NDIS_SWITCH_NIC_INDEX index)
{
    if (switchContext->virtualExternalVport &&
            portId == switchContext->virtualExternalPortId &&
            index == switchContext->virtualExternalVport->nicIndex) {
        return (POVS_VPORT_ENTRY)switchContext->virtualExternalVport;
    } else {
        PLIST_ENTRY head, link;
        POVS_VPORT_ENTRY vport;
        UINT32 hash;
        hash = OvsJhashWords((UINT32 *)&portId, 1, OVS_HASH_BASIS);
        head = &(switchContext->portIdHashArray[hash & OVS_VPORT_MASK]);
        LIST_FORALL(head, link) {
            vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, portIdLink);
            if (portId == vport->portId && index == vport->nicIndex) {
                return vport;
            }
        }
        return NULL;
    }
}

BOOLEAN OvsIsExternalVportByPortId(POVS_SWITCH_CONTEXT switchContext,
                                   NDIS_SWITCH_PORT_ID portId)
{
    return (portId == switchContext->virtualExternalPortId);
}

POVS_VPORT_ENTRY
OvsAllocateVport(VOID)
{
    POVS_VPORT_ENTRY vport;
    vport = (POVS_VPORT_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(OVS_VPORT_ENTRY), OVS_VPORT_POOL_TAG);
    if (vport == NULL) {
        return NULL;
    }
    RtlZeroMemory(vport, sizeof (OVS_VPORT_ENTRY));
    vport->ovsState = OVS_STATE_UNKNOWN;
    vport->isAbsentOnHv = FALSE;
    vport->portNo = OVS_DPPORT_NUMBER_INVALID;

    InitializeListHead(&vport->ovsNameLink);
    InitializeListHead(&vport->portIdLink);
    InitializeListHead(&vport->portNoLink);

    return vport;
}

static VOID
OvsInitVportWithPortParam(POVS_VPORT_ENTRY vport,
                          PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    vport->portType = portParam->PortType;
    vport->portState = portParam->PortState;
    vport->portId = portParam->PortId;
    vport->nicState = NdisSwitchNicStateUnknown;
    vport->isExternal = FALSE;

    switch (vport->portType) {
    case NdisSwitchPortTypeExternal:
        vport->isExternal = TRUE;
        vport->ovsType = OVS_VPORT_TYPE_NETDEV;
        break;
    case NdisSwitchPortTypeInternal:
        vport->ovsType = OVS_VPORT_TYPE_INTERNAL;
        break;
    case NdisSwitchPortTypeSynthetic:
    case NdisSwitchPortTypeEmulated:
        vport->ovsType = OVS_VPORT_TYPE_NETDEV;
        break;
    }
    RtlCopyMemory(&vport->hvPortName, &portParam->PortName,
                  sizeof (NDIS_SWITCH_PORT_NAME));
    /* For external and internal ports, 'portFriendlyName' is overwritten
     * later. */
    RtlCopyMemory(&vport->portFriendlyName, &portParam->PortFriendlyName,
                  sizeof(NDIS_SWITCH_PORT_FRIENDLYNAME));

    switch (vport->portState) {
    case NdisSwitchPortStateCreated:
        vport->ovsState = OVS_STATE_PORT_CREATED;
        break;
    case NdisSwitchPortStateTeardown:
        vport->ovsState = OVS_STATE_PORT_TEAR_DOWN;
        break;
    case NdisSwitchPortStateDeleted:
        vport->ovsState = OVS_STATE_PORT_DELETED;
        break;
    }
}


static VOID
OvsInitVportWithNicParam(POVS_SWITCH_CONTEXT switchContext,
                         POVS_VPORT_ENTRY vport,
                         PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    ASSERT(vport->portId == nicParam->PortId);

    UNREFERENCED_PARAMETER(switchContext);

    RtlCopyMemory(vport->permMacAddress, nicParam->PermanentMacAddress,
                  sizeof (vport->permMacAddress));
    RtlCopyMemory(vport->currMacAddress, nicParam->CurrentMacAddress,
                  sizeof (vport->currMacAddress));

    if (nicParam->NicType == NdisSwitchNicTypeSynthetic ||
        nicParam->NicType == NdisSwitchNicTypeEmulated) {
        RtlCopyMemory(vport->vmMacAddress, nicParam->VMMacAddress,
                      sizeof (vport->vmMacAddress));
        RtlCopyMemory(&vport->vmName, &nicParam->VmName,
                      sizeof (nicParam->VmName));
    } else {
        RtlCopyMemory(&vport->netCfgInstanceId, &nicParam->NetCfgInstanceId,
                      sizeof (nicParam->NetCfgInstanceId));
        RtlCopyMemory(&vport->nicFriendlyName, &nicParam->NicFriendlyName,
                      sizeof (nicParam->NicFriendlyName));
    }
    RtlCopyMemory(&vport->nicName, &nicParam->NicName,
                  sizeof (nicParam->NicName));
    vport->mtu = nicParam->MTU;
    vport->nicState = nicParam->NicState;
    vport->nicIndex = nicParam->NicIndex;
    vport->nicType = nicParam->NicType;
    vport->numaNodeId = nicParam->NumaNodeId;

    switch (vport->nicState) {
    case NdisSwitchNicStateCreated:
        vport->ovsState = OVS_STATE_NIC_CREATED;
        break;
    case NdisSwitchNicStateConnected:
        vport->ovsState = OVS_STATE_CONNECTED;
        break;
    case NdisSwitchNicStateDisconnected:
        vport->ovsState = OVS_STATE_NIC_CREATED;
        break;
    case NdisSwitchNicStateDeleted:
        vport->ovsState = OVS_STATE_PORT_CREATED;
        break;
    }
}

/*
 * --------------------------------------------------------------------------
 * Populates 'portParam' based on 'vport'.
 * --------------------------------------------------------------------------
 */
static VOID
OvsCopyPortParamsFromVport(POVS_VPORT_ENTRY vport,
                           PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    portParam->Flags = 0;
    portParam->PortId = vport->portId;
    RtlCopyMemory(&portParam->PortName, &vport->hvPortName,
                  sizeof (NDIS_SWITCH_PORT_NAME));
    RtlCopyMemory(&portParam->PortFriendlyName,
                  &vport->portFriendlyName,
                  sizeof(NDIS_SWITCH_PORT_FRIENDLYNAME));
    portParam->PortType = vport->portType;
    portParam->IsValidationPort = FALSE;
    portParam->PortState = vport->portState;
}

/*
 * --------------------------------------------------------------------------
 * Initializes a tunnel vport.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsInitTunnelVport(PVOID userContext,
                   POVS_VPORT_ENTRY vport,
                   OVS_VPORT_TYPE ovsType,
                   UINT16 dstPort)
{
    NTSTATUS status = STATUS_SUCCESS;
    POVS_USER_PARAMS_CONTEXT usrParamsCtx =
        (POVS_USER_PARAMS_CONTEXT)userContext;

    vport->ovsType = ovsType;
    vport->ovsState = OVS_STATE_PORT_CREATED;
    switch (ovsType) {
    case OVS_VPORT_TYPE_GRE:
        status = OvsInitGreTunnel(vport);
        break;
    case OVS_VPORT_TYPE_VXLAN:
    {
        POVS_TUNFLT_INIT_CONTEXT tunnelContext = NULL;

        tunnelContext = OvsAllocateMemoryWithTag(sizeof(*tunnelContext),
                                                 OVS_VPORT_POOL_TAG);
        if (tunnelContext == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        tunnelContext->inputBuffer = usrParamsCtx->inputBuffer;
        tunnelContext->outputBuffer = usrParamsCtx->outputBuffer;
        tunnelContext->outputLength = usrParamsCtx->outputLength;
        tunnelContext->vport = vport;

        status = OvsInitVxlanTunnel(usrParamsCtx->irp,
                                    vport,
                                    dstPort,
                                    OvsTunnelVportPendingInit,
                                    (PVOID)tunnelContext);
        if (status != STATUS_PENDING) {
            OvsFreeMemoryWithTag(tunnelContext, OVS_VPORT_POOL_TAG);
            tunnelContext = NULL;
        }
        break;
    }
    case OVS_VPORT_TYPE_STT:
        status = OvsInitSttTunnel(vport, dstPort);
        break;
    case OVS_VPORT_TYPE_GENEVE:
        status = OvsInitGeneveTunnel(vport, dstPort);
        break;
    default:
        ASSERT(0);
    }
    return status;
}

/*
 * --------------------------------------------------------------------------
 * For external and internal vports 'portFriendlyName' parameter, provided by
  * Hyper-V, is overwritten with the interface alias name and NIC friendly name
  * equivalent.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
GetNICAlias(PNDIS_SWITCH_NIC_PARAMETERS nicParam,
            IF_COUNTED_STRING *portFriendlyName)
{
    NTSTATUS status = STATUS_SUCCESS;
    WCHAR interfaceName[IF_MAX_STRING_SIZE + 1];
    NET_LUID interfaceLuid;
    size_t len;

    if (nicParam->NicType == NdisSwitchNicTypeInternal) {
        RtlCopyMemory(portFriendlyName, &nicParam->NicFriendlyName,
                      sizeof nicParam->NicFriendlyName);
    return status;
    }

    status = ConvertInterfaceGuidToLuid(&nicParam->NetCfgInstanceId,
                                        &interfaceLuid);
    if (status == STATUS_SUCCESS) {
        /*
         * Must be called from PASSIVE_LEVEL. Resulted in a
         * STATUS_INVALID_DEVICE_REQUEST if not.
         */
        status = ConvertInterfaceLuidToAlias(&interfaceLuid, interfaceName,
                                             IF_MAX_STRING_SIZE + 1);
        if (status == STATUS_SUCCESS) {
            RtlStringCbPrintfW(portFriendlyName->String,
                               IF_MAX_STRING_SIZE, L"%s", interfaceName);
            RtlStringCbLengthW(portFriendlyName->String, IF_MAX_STRING_SIZE,
                               &len);
            portFriendlyName->Length = (USHORT)len;
        } else {
            OVS_LOG_ERROR("Fail to convert interface LUID to alias, status: %x",
                status);
        }
    } else {
        OVS_LOG_ERROR("Fail to convert interface GUID to LUID, status: %x",
                      status);
    }

    return status;
}


/*
 * --------------------------------------------------------------------------
 * Functionality common to any port on the Hyper-V switch. This function is not
 * to be called for a port that is not on the Hyper-V switch.
 *
 * Inserts the port into 'portIdHashArray' and caches the pointer in the
 * 'switchContext' if needed.
 * --------------------------------------------------------------------------
 */
static VOID
UpdateSwitchCtxWithVport(POVS_SWITCH_CONTEXT switchContext,
                         POVS_VPORT_ENTRY vport,
                         BOOLEAN newPort)
{
    UINT32 hash;

    switch (vport->portType) {
    case NdisSwitchPortTypeExternal:
        if (vport->nicIndex == 0) {
            switchContext->virtualExternalPortId = vport->portId;
            switchContext->virtualExternalVport = vport;
        } else if (newPort == TRUE) {
            switchContext->numPhysicalNics++;
        }
        break;
    case NdisSwitchPortTypeInternal:
        switchContext->countInternalVports++;
        break;
    case NdisSwitchPortTypeSynthetic:
    case NdisSwitchPortTypeEmulated:
        break;
    }

    /*
     * It is important to not insert vport corresponding to virtual external
     * port into the 'portIdHashArray' since the port should not be exposed to
     * OVS userspace.
     */
    if (vport->portType == NdisSwitchPortTypeExternal &&
        vport->nicIndex == 0) {
        return;
    }

    /*
     * NOTE: OvsJhashWords has portId as "1" word. This should be ok, even
     * though sizeof(NDIS_SWITCH_PORT_ID) = 4, not 2, because the
     * hyper-v switch seems to use only 2 bytes out of 4.
     */
    hash = OvsJhashWords(&vport->portId, 1, OVS_HASH_BASIS);
    InsertHeadList(&switchContext->portIdHashArray[hash & OVS_VPORT_MASK],
                   &vport->portIdLink);
    if (newPort) {
        switchContext->numHvVports++;
    }
    return;
}

/*
 * --------------------------------------------------------------------------
 * Functionality common to any port added from OVS userspace.
 *
 * Inserts the port into 'portNoHashArray', 'ovsPortNameHashArray' and in
 * 'tunnelVportsArray' if appropriate.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
InitOvsVportCommon(POVS_SWITCH_CONTEXT switchContext,
                   POVS_VPORT_ENTRY vport)
{
    UINT32 hash;

    switch(vport->ovsType) {
    case OVS_VPORT_TYPE_GRE:
    case OVS_VPORT_TYPE_VXLAN:
    case OVS_VPORT_TYPE_STT:
    case OVS_VPORT_TYPE_GENEVE:
    {
        UINT16 dstPort = GetPortFromPriv(vport);
        hash = OvsJhashBytes(&dstPort,
                             sizeof(dstPort),
                             OVS_HASH_BASIS);
        InsertHeadList(
            &gOvsSwitchContext->tunnelVportsArray[hash & OVS_VPORT_MASK],
            &vport->tunnelVportLink);
        switchContext->numNonHvVports++;
        break;
    }
    default:
        break;
    }

    /*
     * Insert the port into the hash array of ports: by port number and ovs
     * and ovs (datapath) port name.
     * NOTE: OvsJhashWords has portNo as "1" word. This is ok, because the
     * portNo is stored in 2 bytes only (max port number = MAXUINT16).
     */
    hash = OvsJhashWords(&vport->portNo, 1, OVS_HASH_BASIS);
    InsertHeadList(&gOvsSwitchContext->portNoHashArray[hash & OVS_VPORT_MASK],
                   &vport->portNoLink);

    hash = OvsJhashBytes(vport->ovsName, strlen(vport->ovsName) + 1,
                         OVS_HASH_BASIS);
    InsertHeadList(
        &gOvsSwitchContext->ovsPortNameHashArray[hash & OVS_VPORT_MASK],
        &vport->ovsNameLink);

    return STATUS_SUCCESS;
}


/*
 * --------------------------------------------------------------------------
 * Provides functionality that is partly complementatry to
 * InitOvsVportCommon()/UpdateSwitchCtxWithVport().
 *
 * 'hvDelete' indicates if caller is removing the vport as a result of the
 * port being removed on the Hyper-V switch.
 * 'ovsDelete' indicates if caller is removing the vport as a result of the
 * port being removed from OVS userspace.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsRemoveAndDeleteVport(PVOID usrParamsContext,
                        POVS_SWITCH_CONTEXT switchContext,
                        POVS_VPORT_ENTRY vport,
                        BOOLEAN hvDelete,
                        BOOLEAN ovsDelete)
{
    POVS_USER_PARAMS_CONTEXT usrParamsCtx =
        (POVS_USER_PARAMS_CONTEXT)usrParamsContext;
    BOOLEAN hvSwitchPort = FALSE;
    BOOLEAN deletedOnOvs = FALSE;
    BOOLEAN deletedOnHv = FALSE;

    switch (vport->ovsType) {
    case OVS_VPORT_TYPE_INTERNAL:
        if (hvDelete && vport->isAbsentOnHv == FALSE) {
            switchContext->countInternalVports--;
            ASSERT(switchContext->countInternalVports >= 0);
            OvsInternalAdapterDown(vport->portNo, vport->netCfgInstanceId);
        }
        hvSwitchPort = TRUE;
        break;
    case OVS_VPORT_TYPE_VXLAN:
    {
        NTSTATUS status;
        status = OvsRemoveTunnelVport(usrParamsCtx, switchContext, vport,
                                      hvDelete, ovsDelete);
        if (status != STATUS_SUCCESS) {
            return status;
        }
    }
    case OVS_VPORT_TYPE_GENEVE:
        OvsCleanupGeneveTunnel(vport);
        break;
    case OVS_VPORT_TYPE_STT:
        OvsCleanupSttTunnel(vport);
        break;
    case OVS_VPORT_TYPE_GRE:
        OvsCleanupGreTunnel(vport);
        break;
    case OVS_VPORT_TYPE_NETDEV:
        if (vport->isExternal) {
            if (vport->nicIndex == 0) {
                /* Such a vport is not part of any of the hash tables, since it
                 * is not exposed to userspace. See Vport.h for explanation. */
                ASSERT(hvDelete == TRUE);
                ASSERT(switchContext->numPhysicalNics == 0);
                switchContext->virtualExternalPortId = 0;
                switchContext->virtualExternalVport = NULL;
                OvsFreeMemoryWithTag(vport, OVS_VPORT_POOL_TAG);
                return STATUS_SUCCESS;
            }
        }
        hvSwitchPort = TRUE;
    default:
        break;
    }

    /*
     * 'hvDelete' == TRUE indicates that the port should be removed from the
     * 'portIdHashArray', while 'ovsDelete' == TRUE indicates that the port
     * should be removed from 'portNoHashArray' and the 'ovsPortNameHashArray'.
     *
     * Both 'hvDelete' and 'ovsDelete' can be set to TRUE by the caller.
     */
    if (vport->isAbsentOnHv == TRUE) {
        deletedOnHv = TRUE;
    }
    if (vport->portNo == OVS_DPPORT_NUMBER_INVALID) {
        deletedOnOvs = TRUE;
    }

    if (hvDelete && !deletedOnHv) {
        vport->isAbsentOnHv = TRUE;

        if (vport->isExternal) {
            ASSERT(vport->nicIndex != 0);
            ASSERT(switchContext->numPhysicalNics);
            switchContext->numPhysicalNics--;
        }

        /* Remove the port from the relevant lists. */
        RemoveEntryList(&vport->portIdLink);
        InitializeListHead(&vport->portIdLink);
        deletedOnHv = TRUE;
    }
    if (ovsDelete && !deletedOnOvs) {
        vport->portNo = OVS_DPPORT_NUMBER_INVALID;
        vport->ovsName[0] = '\0';

        /* Remove the port from the relevant lists. */
        RemoveEntryList(&vport->ovsNameLink);
        InitializeListHead(&vport->ovsNameLink);
        RemoveEntryList(&vport->portNoLink);
        InitializeListHead(&vport->portNoLink);
        if (OvsIsTunnelVportType(vport->ovsType)) {
            RemoveEntryList(&vport->tunnelVportLink);
            InitializeListHead(&vport->tunnelVportLink);
        }

        deletedOnOvs = TRUE;
    }

    /*
     * Deallocate the port if it has been deleted on the Hyper-V switch as well
     * as OVS userspace.
     */
    if (deletedOnHv && deletedOnOvs) {
        if (hvSwitchPort) {
            switchContext->numHvVports--;
        } else {
            switchContext->numNonHvVports--;
        }
        OvsFreeMemoryWithTag(vport, OVS_VPORT_POOL_TAG);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
OvsRemoveTunnelVport(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                     POVS_SWITCH_CONTEXT switchContext,
                     POVS_VPORT_ENTRY vport,
                     BOOLEAN hvDelete,
                     BOOLEAN ovsDelete)
{
    POVS_TUNFLT_INIT_CONTEXT tunnelContext = NULL;
    PIRP irp = NULL;

    tunnelContext = OvsAllocateMemoryWithTag(sizeof(*tunnelContext),
                                             OVS_VPORT_POOL_TAG);
    if (tunnelContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(tunnelContext, sizeof(*tunnelContext));

    tunnelContext->switchContext = switchContext;
    tunnelContext->hvSwitchPort = FALSE;
    tunnelContext->hvDelete = hvDelete;
    tunnelContext->ovsDelete = ovsDelete;
    tunnelContext->vport = vport;

    if (usrParamsCtx) {
        tunnelContext->inputBuffer = usrParamsCtx->inputBuffer;
        tunnelContext->outputBuffer = usrParamsCtx->outputBuffer;
        tunnelContext->outputLength = usrParamsCtx->outputLength;
        irp = usrParamsCtx->irp;
    }

    return OvsCleanupVxlanTunnel(irp, vport, OvsTunnelVportPendingRemove,
                                 tunnelContext);
}

/*
 * --------------------------------------------------------------------------
 * Enumerates the ports on the Hyper-V switch.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsAddConfiguredSwitchPorts(POVS_SWITCH_CONTEXT switchContext)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    ULONG arrIndex;
    PNDIS_SWITCH_PORT_PARAMETERS portParam;
    PNDIS_SWITCH_PORT_ARRAY portArray = NULL;

    OVS_LOG_TRACE("Enter: switchContext:%p", switchContext);

    status = OvsGetPortsOnSwitch(switchContext, &portArray);
    if (status != NDIS_STATUS_SUCCESS) {
        goto cleanup;
    }

    for (arrIndex = 0; arrIndex < portArray->NumElements; arrIndex++) {
         portParam = NDIS_SWITCH_PORT_AT_ARRAY_INDEX(portArray, arrIndex);

         if (portParam->IsValidationPort) {
             continue;
         }

         status = HvCreatePort(switchContext, portParam, 0);
         if (status != STATUS_SUCCESS && status != STATUS_DATA_NOT_ACCEPTED) {
             break;
         }
    }

cleanup:
    if (status != NDIS_STATUS_SUCCESS) {
        OvsClearAllSwitchVports(switchContext);
    }

    OvsFreeSwitchPortsArray(portArray);

    OVS_LOG_TRACE("Exit: status: %x", status);

    return status;
}

/*
 * --------------------------------------------------------------------------
 * Enumerates the NICs on the Hyper-V switch.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsInitConfiguredSwitchNics(POVS_SWITCH_CONTEXT switchContext)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PNDIS_SWITCH_NIC_ARRAY nicArray = NULL;
    ULONG arrIndex;
    PNDIS_SWITCH_NIC_PARAMETERS nicParam;

    OVS_LOG_TRACE("Enter: switchContext: %p", switchContext);
    /*
     * Now, get NIC list.
     */
    status = OvsGetNicsOnSwitch(switchContext, &nicArray);
    if (status != NDIS_STATUS_SUCCESS) {
        goto cleanup;
    }
    for (arrIndex = 0; arrIndex < nicArray->NumElements; ++arrIndex) {
        nicParam = NDIS_SWITCH_NIC_AT_ARRAY_INDEX(nicArray, arrIndex);

        /*
         * XXX: Check if the port is configured with a VLAN. Disallow such a
         * configuration, since we don't support tag-in-tag.
         * XXX: Check if the port is connected to a VF. Disconnect the VF in
         * such a case.
         */

        status = HvCreateNic(switchContext, nicParam);
        if (status == NDIS_STATUS_SUCCESS) {
            HvConnectNic(switchContext, nicParam);
        }
    }
cleanup:

    OvsFreeSwitchNicsArray(nicArray);

    OVS_LOG_TRACE("Exit: status: %x", status);
    return status;
}

/*
 * --------------------------------------------------------------------------
 * Deletes ports added from the Hyper-V switch as well as OVS usersapce. The
 * function deletes ports in 'portIdHashArray'. This will delete most of the
 * ports that are in the 'portNoHashArray' as well. Any remaining ports
 * are deleted by walking the 'portNoHashArray'.
 * --------------------------------------------------------------------------
 */
VOID
OvsClearAllSwitchVports(POVS_SWITCH_CONTEXT switchContext)
{
    for (UINT hash = 0; hash < OVS_MAX_VPORT_ARRAY_SIZE; hash++) {
        PLIST_ENTRY head, link, next;

        head = &(switchContext->portIdHashArray[hash & OVS_VPORT_MASK]);
        LIST_FORALL_SAFE(head, link, next) {
            POVS_VPORT_ENTRY vport;
            vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, portIdLink);
            OvsRemoveAndDeleteVport(NULL, switchContext, vport, TRUE, TRUE);
        }
    }

    /*
     * Remove 'virtualExternalVport' as well. This port is not part of the
     * 'portIdHashArray'.
     */
    if (switchContext->virtualExternalVport) {
        OvsRemoveAndDeleteVport(NULL, switchContext,
            (POVS_VPORT_ENTRY)switchContext->virtualExternalVport, TRUE, TRUE);
    }


    for (UINT hash = 0; hash < OVS_MAX_VPORT_ARRAY_SIZE; hash++) {
        PLIST_ENTRY head, link, next;
        head = &(switchContext->portNoHashArray[hash & OVS_VPORT_MASK]);
        LIST_FORALL_SAFE(head, link, next) {
            POVS_VPORT_ENTRY vport;
            vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, portNoLink);
            ASSERT(OvsIsTunnelVportType(vport->ovsType) ||
                   vport->isAbsentOnHv == TRUE);
            OvsRemoveAndDeleteVport(NULL, switchContext, vport, TRUE, TRUE);
        }
    }

    ASSERT(switchContext->virtualExternalVport == NULL);
    ASSERT(switchContext->countInternalVports == 0);
}


NTSTATUS
OvsConvertIfCountedStrToAnsiStr(PIF_COUNTED_STRING wStr,
                                CHAR *str,
                                UINT16 maxStrLen)
{
    ANSI_STRING astr;
    UNICODE_STRING ustr;
    NTSTATUS status;
    UINT32 size;

    ustr.Buffer = wStr->String;
    ustr.Length = wStr->Length;
    ustr.MaximumLength = IF_MAX_STRING_SIZE;

    astr.Buffer = str;
    astr.MaximumLength = maxStrLen;
    astr.Length = 0;

    size = RtlUnicodeStringToAnsiSize(&ustr);
    if (size > maxStrLen) {
        return STATUS_BUFFER_OVERFLOW;
    }

    status = RtlUnicodeStringToAnsiString(&astr, &ustr, FALSE);

    ASSERT(status == STATUS_SUCCESS);
    if (status != STATUS_SUCCESS) {
        return status;
    }
    ASSERT(astr.Length <= maxStrLen);
    str[astr.Length] = 0;
    return STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * Utility function that populates a 'OVS_VPORT_EXT_INFO' structure for the
 * specified vport.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsGetExtInfoIoctl(POVS_VPORT_GET vportGet,
                   POVS_VPORT_EXT_INFO extInfo)
{
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN doConvert = FALSE;

    RtlZeroMemory(extInfo, sizeof (POVS_VPORT_EXT_INFO));
    NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState, 0);
    if (vportGet->portNo == 0) {
        vport = OvsFindVportByHvNameA(gOvsSwitchContext, vportGet->name);
        if (vport == NULL) {
            /* If the port is not a Hyper-V port and it has been added earlier,
             * we'll find it in 'ovsPortNameHashArray'. */
            vport = OvsFindVportByOvsName(gOvsSwitchContext, vportGet->name);
        }
    } else {
        vport = OvsFindVportByPortNo(gOvsSwitchContext, vportGet->portNo);
    }
    if (vport == NULL || (vport->ovsState != OVS_STATE_CONNECTED &&
                          vport->ovsState != OVS_STATE_NIC_CREATED)) {
        NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
        if (vportGet->portNo) {
            OVS_LOG_WARN("vport %u does not exist any more", vportGet->portNo);
        } else {
            OVS_LOG_WARN("vport %s does not exist any more", vportGet->name);
        }
        status = STATUS_DEVICE_DOES_NOT_EXIST;
        goto ext_info_done;
    }
    extInfo->dpNo = vportGet->dpNo;
    extInfo->portNo = vport->portNo;
    RtlCopyMemory(extInfo->macAddress, vport->currMacAddress,
                  sizeof (vport->currMacAddress));
    RtlCopyMemory(extInfo->permMACAddress, vport->permMacAddress,
                  sizeof (vport->permMacAddress));
    if (vport->ovsType == OVS_VPORT_TYPE_NETDEV) {
        RtlCopyMemory(extInfo->vmMACAddress, vport->vmMacAddress,
                      sizeof (vport->vmMacAddress));
    }
    extInfo->nicIndex = vport->nicIndex;
    extInfo->portId = vport->portId;
    extInfo->type = vport->ovsType;
    extInfo->mtu = vport->mtu;
    /*
     * TO be revisit XXX
     */
    if (vport->ovsState == OVS_STATE_NIC_CREATED) {
       extInfo->status = OVS_EVENT_CONNECT | OVS_EVENT_LINK_DOWN;
    } else if (vport->ovsState == OVS_STATE_CONNECTED) {
       extInfo->status = OVS_EVENT_CONNECT | OVS_EVENT_LINK_UP;
    } else {
       extInfo->status = OVS_EVENT_DISCONNECT;
    }
    if (extInfo->type == OVS_VPORT_TYPE_NETDEV &&
        (vport->ovsState == OVS_STATE_NIC_CREATED  ||
         vport->ovsState == OVS_STATE_CONNECTED)) {
        doConvert = TRUE;
    } else {
        extInfo->vmUUID[0] = 0;
        extInfo->vifUUID[0] = 0;
    }
    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
    if (doConvert) {
        status = OvsConvertIfCountedStrToAnsiStr(&vport->portFriendlyName,
                                                 extInfo->name,
                                                 OVS_MAX_PORT_NAME_LENGTH);
        if (status != STATUS_SUCCESS) {
            OVS_LOG_INFO("Fail to convert NIC name.");
            extInfo->name[0] = 0;
        }

        status = OvsConvertIfCountedStrToAnsiStr(&vport->vmName,
                                                 extInfo->vmUUID,
                                                 OVS_MAX_VM_UUID_LEN);
        if (status != STATUS_SUCCESS) {
            OVS_LOG_INFO("Fail to convert VM name.");
            extInfo->vmUUID[0] = 0;
        }

        status = OvsConvertIfCountedStrToAnsiStr(&vport->nicName,
                                                 extInfo->vifUUID,
                                                 OVS_MAX_VIF_UUID_LEN);
        if (status != STATUS_SUCCESS) {
            OVS_LOG_INFO("Fail to convert nic UUID");
            extInfo->vifUUID[0] = 0;
        }
        /*
         * for now ignore status
         */
        status = STATUS_SUCCESS;
    }

ext_info_done:
    return status;
}

/*
 * --------------------------------------------------------------------------
 *  Command Handler for 'OVS_WIN_NETDEV_CMD_GET'.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsGetNetdevCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                       UINT32 *replyLen)
{
    NTSTATUS status = STATUS_SUCCESS;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
    NL_ERROR nlError = NL_ERROR_SUCCESS;
    OVS_VPORT_GET vportGet;
    OVS_VPORT_EXT_INFO info;

    static const NL_POLICY ovsNetdevPolicy[] = {
        [OVS_WIN_NETDEV_ATTR_NAME] = { .type = NL_A_STRING,
                                       .minLen = 2,
                                       .maxLen = IFNAMSIZ },
    };
    PNL_ATTR netdevAttrs[ARRAY_SIZE(ovsNetdevPolicy)];

    /* input buffer has been validated while validating transaction dev op. */
    ASSERT(usrParamsCtx->inputBuffer != NULL &&
           usrParamsCtx->inputLength > sizeof *msgIn);

    if (msgOut == NULL || usrParamsCtx->outputLength < sizeof *msgOut) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (!NlAttrParse((PNL_MSG_HDR)msgIn,
        NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN,
        NlMsgAttrsLen((PNL_MSG_HDR)msgIn),
        ovsNetdevPolicy, ARRAY_SIZE(ovsNetdevPolicy),
        netdevAttrs, ARRAY_SIZE(netdevAttrs))) {
        return STATUS_INVALID_PARAMETER;
    }

    vportGet.portNo = 0;
    RtlCopyMemory(&vportGet.name, NlAttrGet(netdevAttrs[OVS_VPORT_ATTR_NAME]),
                  NlAttrGetSize(netdevAttrs[OVS_VPORT_ATTR_NAME]));

    status = OvsGetExtInfoIoctl(&vportGet, &info);
    if (status == STATUS_DEVICE_DOES_NOT_EXIST) {
        nlError = NL_ERROR_NODEV;
        goto cleanup;
    }

    status = CreateNetlinkMesgForNetdev(&info, msgIn,
                 usrParamsCtx->outputBuffer, usrParamsCtx->outputLength,
                 gOvsSwitchContext->dpNo);
    if (status == STATUS_SUCCESS) {
        *replyLen = msgOut->nlMsg.nlmsgLen;
    }

cleanup:
    if (nlError != NL_ERROR_SUCCESS) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
            usrParamsCtx->outputBuffer;

        ASSERT(msgError);
        NlBuildErrorMsg(msgIn, msgError, nlError, replyLen);
        ASSERT(*replyLen != 0);
    }

    return STATUS_SUCCESS;
}


/*
 * --------------------------------------------------------------------------
 *  Utility function to construct an OVS_MESSAGE for the specified vport. The
 *  OVS_MESSAGE contains the output of a netdev command.
 * --------------------------------------------------------------------------
 */
static NTSTATUS
CreateNetlinkMesgForNetdev(POVS_VPORT_EXT_INFO info,
                           POVS_MESSAGE msgIn,
                           PVOID outBuffer,
                           UINT32 outBufLen,
                           int dpIfIndex)
{
    NL_BUFFER nlBuffer;
    BOOLEAN ok;
    PNL_MSG_HDR nlMsg;
    UINT32 netdevFlags = 0;

    NlBufInit(&nlBuffer, outBuffer, outBufLen);

    ok = NlFillOvsMsg(&nlBuffer, msgIn->nlMsg.nlmsgType, NLM_F_MULTI,
                      msgIn->nlMsg.nlmsgSeq, msgIn->nlMsg.nlmsgPid,
                      msgIn->genlMsg.cmd, msgIn->genlMsg.version,
                      dpIfIndex);
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    ok = NlMsgPutTailU32(&nlBuffer, OVS_WIN_NETDEV_ATTR_PORT_NO,
                         info->portNo);
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    ok = NlMsgPutTailU32(&nlBuffer, OVS_WIN_NETDEV_ATTR_TYPE, info->type);
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    ok = NlMsgPutTailString(&nlBuffer, OVS_WIN_NETDEV_ATTR_NAME,
                            info->name);
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    ok = NlMsgPutTailUnspec(&nlBuffer, OVS_WIN_NETDEV_ATTR_MAC_ADDR,
             (PCHAR)info->macAddress, sizeof (info->macAddress));
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    ok = NlMsgPutTailU32(&nlBuffer, OVS_WIN_NETDEV_ATTR_MTU, info->mtu);
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (info->status != OVS_EVENT_CONNECT) {
        netdevFlags = OVS_WIN_NETDEV_IFF_UP;
    }
    ok = NlMsgPutTailU32(&nlBuffer, OVS_WIN_NETDEV_ATTR_IF_FLAGS,
                         netdevFlags);
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    /*
     * XXX: add netdev_stats when we have the definition available in the
     * kernel.
     */

    nlMsg = (PNL_MSG_HDR)NlBufAt(&nlBuffer, 0, 0);
    nlMsg->nlmsgLen = NlBufSize(&nlBuffer);

    return STATUS_SUCCESS;
}

static __inline VOID
OvsWaitActivate(POVS_SWITCH_CONTEXT switchContext, ULONG sleepMicroSec)
{
    while ((!switchContext->isActivated) &&
          (!switchContext->isActivateFailed)) {
        /* Wait for the switch to be active and
         * the list of ports in OVS to be initialized. */
        NdisMSleep(sleepMicroSec);
    }
}

static NTSTATUS
OvsCreateMsgFromVport(POVS_VPORT_ENTRY vport,
                      POVS_MESSAGE msgIn,
                      PVOID outBuffer,
                      UINT32 outBufLen,
                      int dpIfIndex)
{
    NL_BUFFER nlBuffer;
    OVS_VPORT_FULL_STATS vportStats;
    BOOLEAN ok;
    PNL_MSG_HDR nlMsg;

    NlBufInit(&nlBuffer, outBuffer, outBufLen);

    ok = NlFillOvsMsg(&nlBuffer, msgIn->nlMsg.nlmsgType, NLM_F_MULTI,
                      msgIn->nlMsg.nlmsgSeq, msgIn->nlMsg.nlmsgPid,
                      msgIn->genlMsg.cmd, msgIn->genlMsg.version,
                      dpIfIndex);
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    ok = NlMsgPutTailU32(&nlBuffer, OVS_VPORT_ATTR_PORT_NO, vport->portNo);
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    ok = NlMsgPutTailU32(&nlBuffer, OVS_VPORT_ATTR_TYPE, vport->ovsType);
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    ok = NlMsgPutTailString(&nlBuffer, OVS_VPORT_ATTR_NAME, vport->ovsName);
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    /*
     * XXX: when we implement OVS_DP_ATTR_USER_FEATURES in datapath,
     * we'll need to check the OVS_DP_F_VPORT_PIDS flag: if it is set,
     * it means we have an array of pids, instead of a single pid.
     * ATM we assume we have one pid only.
    */

    ok = NlMsgPutTailU32(&nlBuffer, OVS_VPORT_ATTR_UPCALL_PID,
                         vport->upcallPid);
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    /*stats*/
    vportStats.rxPackets = vport->stats.rxPackets;
    vportStats.rxBytes = vport->stats.rxBytes;
    vportStats.txPackets = vport->stats.txPackets;
    vportStats.txBytes = vport->stats.txBytes;
    vportStats.rxErrors = vport->errStats.rxErrors;
    vportStats.txErrors = vport->errStats.txErrors;
    vportStats.rxDropped = vport->errStats.rxDropped;
    vportStats.txDropped = vport->errStats.txDropped;

    ok = NlMsgPutTailUnspec(&nlBuffer, OVS_VPORT_ATTR_STATS,
                            (PCHAR)&vportStats,
                            sizeof(OVS_VPORT_FULL_STATS));
    if (!ok) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    /*
     * XXX: when vxlan udp dest port becomes configurable, we will also need
     * to add vport options
    */

    nlMsg = (PNL_MSG_HDR)NlBufAt(&nlBuffer, 0, 0);
    nlMsg->nlmsgLen = NlBufSize(&nlBuffer);

    return STATUS_SUCCESS;
}

static NTSTATUS
OvsGetVportDumpNext(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                    UINT32 *replyLen)
{
    POVS_MESSAGE msgIn;
    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;
    LOCK_STATE_EX lockState;
    UINT32 i = OVS_MAX_VPORT_ARRAY_SIZE;

    /*
     * XXX: this function shares some code with other dump command(s).
     * In the future, we will need to refactor the dump functions
    */

    ASSERT(usrParamsCtx->devOp == OVS_READ_DEV_OP);

    if (instance->dumpState.ovsMsg == NULL) {
        ASSERT(FALSE);
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* Output buffer has been validated while validating read dev op. */
    ASSERT(usrParamsCtx->outputBuffer != NULL);

    msgIn = instance->dumpState.ovsMsg;

    /*
     * XXX: when we implement OVS_DP_ATTR_USER_FEATURES in datapath,
     * we'll need to check the OVS_DP_F_VPORT_PIDS flag: if it is set,
     * it means we have an array of pids, instead of a single pid.
     * ATM we assume we have one pid only.
    */
    NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState, 0);

    if (gOvsSwitchContext->numHvVports > 0 ||
            gOvsSwitchContext->numNonHvVports > 0) {
        /* inBucket: the bucket, used for lookup */
        UINT32 inBucket = instance->dumpState.index[0];
        /* inIndex: index within the given bucket, used for lookup */
        UINT32 inIndex = instance->dumpState.index[1];
        /* the bucket to be used for the next dump operation */
        UINT32 outBucket = 0;
        /* the index within the outBucket to be used for the next dump */
        UINT32 outIndex = 0;

        for (i = inBucket; i < OVS_MAX_VPORT_ARRAY_SIZE; i++) {
            PLIST_ENTRY head, link;
            head = &(gOvsSwitchContext->portNoHashArray[i]);
            POVS_VPORT_ENTRY vport = NULL;

            outIndex = 0;
            LIST_FORALL(head, link) {

                /*
                 * if one or more dumps were previously done on this same bucket,
                 * inIndex will be > 0, so we'll need to reply with the
                 * inIndex + 1 vport from the bucket.
                */
                if (outIndex >= inIndex) {
                    vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, portNoLink);

                    ASSERT(vport->portNo != OVS_DPPORT_NUMBER_INVALID);
                    OvsCreateMsgFromVport(vport, msgIn,
                                          usrParamsCtx->outputBuffer,
                                          usrParamsCtx->outputLength,
                                          gOvsSwitchContext->dpNo);
                    ++outIndex;
                    break;
                }

                ++outIndex;
            }

            if (vport) {
                break;
            }

            /*
             * if no vport was found above, check the next bucket, beginning
             * with the first (i.e. index 0) elem from within that bucket
            */
            inIndex = 0;
        }

        outBucket = i;

        /* XXX: what about NLMSG_DONE (as msg type)? */
        instance->dumpState.index[0] = outBucket;
        instance->dumpState.index[1] = outIndex;
    }

    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);

    /* if i < OVS_MAX_VPORT_ARRAY_SIZE => vport was found */
    if (i < OVS_MAX_VPORT_ARRAY_SIZE) {
        POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
        *replyLen = msgOut->nlMsg.nlmsgLen;
    } else {
        /*
         * if i >= OVS_MAX_VPORT_ARRAY_SIZE => vport was not found =>
         * it's dump done
         */
        *replyLen = 0;
        /* Free up the dump state, since there's no more data to continue. */
        FreeUserDumpState(instance);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
OvsGetVport(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
            UINT32 *replyLen)
{
    NTSTATUS status = STATUS_SUCCESS;
    LOCK_STATE_EX lockState;

    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
    POVS_VPORT_ENTRY vport = NULL;
    NL_ERROR nlError = NL_ERROR_SUCCESS;
    PCHAR portName = NULL;
    UINT32 portNameLen = 0;
    UINT32 portNumber = OVS_DPPORT_NUMBER_INVALID;

    static const NL_POLICY ovsVportPolicy[] = {
        [OVS_VPORT_ATTR_PORT_NO] = { .type = NL_A_U32, .optional = TRUE },
        [OVS_VPORT_ATTR_NAME] = { .type = NL_A_STRING,
                                  .minLen = 2,
                                  .maxLen = IFNAMSIZ,
                                  .optional = TRUE},
    };
    PNL_ATTR vportAttrs[ARRAY_SIZE(ovsVportPolicy)];

    /* input buffer has been validated while validating write dev op. */
    ASSERT(usrParamsCtx->inputBuffer != NULL);

    if (!NlAttrParse((PNL_MSG_HDR)msgIn,
        NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN,
        NlMsgAttrsLen((PNL_MSG_HDR)msgIn),
        ovsVportPolicy, ARRAY_SIZE(ovsVportPolicy),
        vportAttrs, ARRAY_SIZE(vportAttrs))) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Output buffer has been validated while validating transact dev op. */
    ASSERT(msgOut != NULL && usrParamsCtx->outputLength >= sizeof *msgOut);

    NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState, 0);
    if (vportAttrs[OVS_VPORT_ATTR_NAME] != NULL) {
        portName = NlAttrGet(vportAttrs[OVS_VPORT_ATTR_NAME]);
        portNameLen = NlAttrGetSize(vportAttrs[OVS_VPORT_ATTR_NAME]);

        /* the port name is expected to be null-terminated */
        ASSERT(portName[portNameLen - 1] == '\0');

        vport = OvsFindVportByOvsName(gOvsSwitchContext, portName);
    } else if (vportAttrs[OVS_VPORT_ATTR_PORT_NO] != NULL) {
        portNumber = NlAttrGetU32(vportAttrs[OVS_VPORT_ATTR_PORT_NO]);

        vport = OvsFindVportByPortNo(gOvsSwitchContext, portNumber);
    } else {
        nlError = NL_ERROR_INVAL;
        NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
        goto Cleanup;
    }

    if (!vport) {
        nlError = NL_ERROR_NODEV;
        NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
        goto Cleanup;
    }

    status = OvsCreateMsgFromVport(vport, msgIn, usrParamsCtx->outputBuffer,
                                   usrParamsCtx->outputLength,
                                   gOvsSwitchContext->dpNo);
    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);

    *replyLen = msgOut->nlMsg.nlmsgLen;

Cleanup:
    if (nlError != NL_ERROR_SUCCESS) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
            usrParamsCtx->outputBuffer;

        ASSERT(msgError);
        NlBuildErrorMsg(msgIn, msgError, nlError, replyLen);
        ASSERT(*replyLen != 0);
    }

    return STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 *  Command Handler for 'OVS_VPORT_CMD_GET'.
 *
 *  The function handles the initial call to setup the dump state, as well as
 *  subsequent calls to continue dumping data.
 * --------------------------------------------------------------------------
*/
NTSTATUS
OvsGetVportCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                      UINT32 *replyLen)
{
    *replyLen = 0;

    switch (usrParamsCtx->devOp) {
    case OVS_WRITE_DEV_OP:
        return OvsSetupDumpStart(usrParamsCtx);

    case OVS_READ_DEV_OP:
        return OvsGetVportDumpNext(usrParamsCtx, replyLen);

    case OVS_TRANSACTION_DEV_OP:
        return OvsGetVport(usrParamsCtx, replyLen);

    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }

}

static UINT32
OvsComputeVportNo(POVS_SWITCH_CONTEXT switchContext)
{
    /* we are not allowed to create the port OVS_DPPORT_NUMBER_LOCAL */
    for (ULONG i = OVS_DPPORT_NUMBER_LOCAL + 1; i < MAXUINT16; ++i) {
        POVS_VPORT_ENTRY vport;

        vport = OvsFindVportByPortNo(switchContext, i);
        if (!vport) {
            return i;
        }
    }

    return OVS_DPPORT_NUMBER_INVALID;
}

/*
 * --------------------------------------------------------------------------
 *  Command Handler for 'OVS_VPORT_CMD_NEW'.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsNewVportCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                      UINT32 *replyLen)
{
    NDIS_STATUS status = STATUS_SUCCESS;
    LOCK_STATE_EX lockState;

    NL_ERROR nlError = NL_ERROR_SUCCESS;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
    POVS_VPORT_ENTRY vport = NULL;
    PCHAR portName;
    ULONG portNameLen;
    UINT32 portType;
    BOOLEAN vportAllocated = FALSE, vportInitialized = FALSE;

    static const NL_POLICY ovsVportPolicy[] = {
        [OVS_VPORT_ATTR_PORT_NO] = { .type = NL_A_U32, .optional = TRUE },
        [OVS_VPORT_ATTR_TYPE] = { .type = NL_A_U32, .optional = FALSE },
        [OVS_VPORT_ATTR_NAME] = { .type = NL_A_STRING, .maxLen = IFNAMSIZ,
                                  .optional = FALSE},
        [OVS_VPORT_ATTR_UPCALL_PID] = { .type = NL_A_UNSPEC,
                                        .optional = FALSE },
        [OVS_VPORT_ATTR_OPTIONS] = { .type = NL_A_NESTED, .optional = TRUE },
    };

    PNL_ATTR vportAttrs[ARRAY_SIZE(ovsVportPolicy)];

    /* input buffer has been validated while validating write dev op. */
    ASSERT(usrParamsCtx->inputBuffer != NULL);

    /* Output buffer has been validated while validating transact dev op. */
    ASSERT(msgOut != NULL && usrParamsCtx->outputLength >= sizeof *msgOut);

    if (!NlAttrParse((PNL_MSG_HDR)msgIn,
        NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN,
        NlMsgAttrsLen((PNL_MSG_HDR)msgIn),
        ovsVportPolicy, ARRAY_SIZE(ovsVportPolicy),
        vportAttrs, ARRAY_SIZE(vportAttrs))) {
        return STATUS_INVALID_PARAMETER;
    }

    portName = NlAttrGet(vportAttrs[OVS_VPORT_ATTR_NAME]);
    portNameLen = NlAttrGetSize(vportAttrs[OVS_VPORT_ATTR_NAME]);
    portType = NlAttrGetU32(vportAttrs[OVS_VPORT_ATTR_TYPE]);

    /* we are expecting null terminated strings to be passed */
    ASSERT(portName[portNameLen - 1] == '\0');

    NdisAcquireRWLockWrite(gOvsSwitchContext->dispatchLock, &lockState, 0);

    vport = OvsFindVportByOvsName(gOvsSwitchContext, portName);
    if (vport) {
        nlError = NL_ERROR_EXIST;
        goto Cleanup;
    }

    if (portType == OVS_VPORT_TYPE_NETDEV ||
        portType == OVS_VPORT_TYPE_INTERNAL) {
        /* External and internal ports can also be looked up like VIF ports. */
        vport = OvsFindVportByHvNameA(gOvsSwitchContext, portName);
    } else {
        ASSERT(OvsIsTunnelVportType(portType));

        vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
        if (vport == NULL) {
            nlError = NL_ERROR_NOMEM;
            goto Cleanup;
        }
        vportAllocated = TRUE;

        if (OvsIsTunnelVportType(portType)) {
            UINT16 transportPortDest = 0;
            UINT8 nwProto = IPPROTO_NONE;
            POVS_VPORT_ENTRY dupVport;

            switch (portType) {
            case OVS_VPORT_TYPE_GRE:
                nwProto = IPPROTO_GRE;
                break;
            case OVS_VPORT_TYPE_VXLAN:
                transportPortDest = VXLAN_UDP_PORT;
                nwProto = IPPROTO_UDP;
                break;
            case OVS_VPORT_TYPE_GENEVE:
                transportPortDest = GENEVE_UDP_PORT;
                break;
            case OVS_VPORT_TYPE_STT:
                transportPortDest = STT_TCP_PORT;
                nwProto = IPPROTO_TCP;
                break;
            default:
                nlError = NL_ERROR_INVAL;
                goto Cleanup;
            }

            if (vportAttrs[OVS_VPORT_ATTR_OPTIONS]) {
                PNL_ATTR attr = NlAttrFindNested(vportAttrs[OVS_VPORT_ATTR_OPTIONS],
                                                 OVS_TUNNEL_ATTR_DST_PORT);
                if (attr) {
                    transportPortDest = NlAttrGetU16(attr);
                }
            }

            /*
             * We don't allow two tunnel ports on identical N/W protocol and
             * L4 port number. This is applicable even if the two ports are of
             * different tunneling types.
             */
            dupVport =
                OvsFindTunnelVportByDstPortAndNWProto(gOvsSwitchContext,
                                                      transportPortDest,
                                                      nwProto);
            if (dupVport) {
                OVS_LOG_ERROR("Vport for N/W proto and port already exists,"
                    " type: %u, dst port: %u, name: %s", dupVport->ovsType,
                    transportPortDest, dupVport->ovsName);
                goto Cleanup;
            }

            status = OvsInitTunnelVport(usrParamsCtx,
                                        vport,
                                        portType,
                                        transportPortDest);

            nlError = NlMapStatusToNlErr(status);
        }

        vportInitialized = TRUE;

        if (nlError == NL_ERROR_SUCCESS) {
            vport->ovsState = OVS_STATE_CONNECTED;
            vport->nicState = NdisSwitchNicStateConnected;

            /*
             * Allow the vport to be deleted, because there is no
             * corresponding hyper-v switch part.
             */
            vport->isAbsentOnHv = TRUE;
        } else {
            goto Cleanup;
        }
    }

    if (!vport) {
        nlError = NL_ERROR_INVAL;
        goto Cleanup;
    }
    if (vport->portNo != OVS_DPPORT_NUMBER_INVALID) {
        nlError = NL_ERROR_EXIST;
        goto Cleanup;
    }

    if (vportAttrs[OVS_VPORT_ATTR_PORT_NO] != NULL) {
        /*
         * XXX: when we implement the limit for ovs port number to be
         * MAXUINT16, we'll need to check the port number received from the
         * userspace.
         */
        vport->portNo = NlAttrGetU32(vportAttrs[OVS_VPORT_ATTR_PORT_NO]);
    } else {
        vport->portNo = OvsComputeVportNo(gOvsSwitchContext);
        if (vport->portNo == OVS_DPPORT_NUMBER_INVALID) {
            nlError = NL_ERROR_NOMEM;
            goto Cleanup;
        }
    }

    /* The ovs port name must be uninitialized. */
    ASSERT(vport->ovsName[0] == '\0');
    ASSERT(portNameLen <= OVS_MAX_PORT_NAME_LENGTH);

    RtlCopyMemory(vport->ovsName, portName, portNameLen);
    /* if we don't have options, then vport->portOptions will be NULL */
    vport->portOptions = vportAttrs[OVS_VPORT_ATTR_OPTIONS];

    /*
     * XXX: when we implement OVS_DP_ATTR_USER_FEATURES in datapath,
     * we'll need to check the OVS_DP_F_VPORT_PIDS flag: if it is set,
     * it means we have an array of pids, instead of a single pid.
     * ATM we assume we have one pid only.
     */
    vport->upcallPid = NlAttrGetU32(vportAttrs[OVS_VPORT_ATTR_UPCALL_PID]);

    status = InitOvsVportCommon(gOvsSwitchContext, vport);
    ASSERT(status == STATUS_SUCCESS);

    status = OvsCreateMsgFromVport(vport, msgIn, usrParamsCtx->outputBuffer,
                                   usrParamsCtx->outputLength,
                                   gOvsSwitchContext->dpNo);

    *replyLen = msgOut->nlMsg.nlmsgLen;
    OVS_LOG_INFO("Created new vport, name: %s, type: %u", vport->ovsName,
                 vport->ovsType);

Cleanup:
    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);

    if ((nlError != NL_ERROR_SUCCESS) && (nlError != NL_ERROR_PENDING)) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
            usrParamsCtx->outputBuffer;

        if (vport && vportAllocated == TRUE) {
            if (vportInitialized == TRUE) {
                if (OvsIsTunnelVportType(portType)) {
                    switch (vport->ovsType) {
                    case OVS_VPORT_TYPE_VXLAN:
                        OvsCleanupVxlanTunnel(NULL, vport, NULL, NULL);
                        break;
                    case OVS_VPORT_TYPE_STT:
                        OvsCleanupSttTunnel(vport);
                        break;
                    case OVS_VPORT_TYPE_GENEVE:
                        OvsCleanupGeneveTunnel(vport);
                        break;
                    default:
                        ASSERT(!"Invalid tunnel port type");
                    }
                }
            }
            OvsFreeMemoryWithTag(vport, OVS_VPORT_POOL_TAG);
        }

        ASSERT(msgError);
        NlBuildErrorMsg(msgIn, msgError, nlError, replyLen);
        ASSERT(*replyLen != 0);
    }

    return (status == STATUS_PENDING) ? STATUS_PENDING : STATUS_SUCCESS;
}


/*
 * --------------------------------------------------------------------------
 *  Command Handler for 'OVS_VPORT_CMD_SET'.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsSetVportCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                      UINT32 *replyLen)
{
    NDIS_STATUS status = STATUS_SUCCESS;
    LOCK_STATE_EX lockState;

    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
    POVS_VPORT_ENTRY vport = NULL;
    NL_ERROR nlError = NL_ERROR_SUCCESS;

    static const NL_POLICY ovsVportPolicy[] = {
        [OVS_VPORT_ATTR_PORT_NO] = { .type = NL_A_U32, .optional = TRUE },
        [OVS_VPORT_ATTR_TYPE] = { .type = NL_A_U32, .optional = TRUE },
        [OVS_VPORT_ATTR_NAME] = { .type = NL_A_STRING, .maxLen = IFNAMSIZ,
                                  .optional = TRUE },
        [OVS_VPORT_ATTR_UPCALL_PID] = { .type = NL_A_UNSPEC,
                                        .optional = TRUE },
        [OVS_VPORT_ATTR_STATS] = { .type = NL_A_UNSPEC,
                                   .minLen = sizeof(OVS_VPORT_FULL_STATS),
                                   .maxLen = sizeof(OVS_VPORT_FULL_STATS),
                                   .optional = TRUE },
        [OVS_VPORT_ATTR_OPTIONS] = { .type = NL_A_NESTED, .optional = TRUE },
    };
    PNL_ATTR vportAttrs[ARRAY_SIZE(ovsVportPolicy)];

    ASSERT(usrParamsCtx->inputBuffer != NULL);

    if (!NlAttrParse((PNL_MSG_HDR)msgIn,
        NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN,
        NlMsgAttrsLen((PNL_MSG_HDR)msgIn),
        ovsVportPolicy, ARRAY_SIZE(ovsVportPolicy),
        vportAttrs, ARRAY_SIZE(vportAttrs))) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Output buffer has been validated while validating transact dev op. */
    ASSERT(msgOut != NULL && usrParamsCtx->outputLength >= sizeof *msgOut);

    NdisAcquireRWLockWrite(gOvsSwitchContext->dispatchLock, &lockState, 0);
    if (vportAttrs[OVS_VPORT_ATTR_NAME] != NULL) {
        PSTR portName = NlAttrGet(vportAttrs[OVS_VPORT_ATTR_NAME]);
#ifdef DBG
        UINT32 portNameLen = NlAttrGetSize(vportAttrs[OVS_VPORT_ATTR_NAME]);
#endif
        /* the port name is expected to be null-terminated */
        ASSERT(portName[portNameLen - 1] == '\0');

        vport = OvsFindVportByOvsName(gOvsSwitchContext, portName);
    } else if (vportAttrs[OVS_VPORT_ATTR_PORT_NO] != NULL) {
        vport = OvsFindVportByPortNo(gOvsSwitchContext,
                    NlAttrGetU32(vportAttrs[OVS_VPORT_ATTR_PORT_NO]));
    }

    if (!vport) {
        nlError = NL_ERROR_NODEV;
        goto Cleanup;
    }

    /*
     * XXX: when we implement OVS_DP_ATTR_USER_FEATURES in datapath,
     * we'll need to check the OVS_DP_F_VPORT_PIDS flag: if it is set,
     * it means we have an array of pids, instead of a single pid.
     * Currently, we support only one pid.
     */
    if (vportAttrs[OVS_VPORT_ATTR_UPCALL_PID]) {
        vport->upcallPid = NlAttrGetU32(vportAttrs[OVS_VPORT_ATTR_UPCALL_PID]);
    }

    if (vportAttrs[OVS_VPORT_ATTR_TYPE]) {
        OVS_VPORT_TYPE type = NlAttrGetU32(vportAttrs[OVS_VPORT_ATTR_TYPE]);
        if (type != vport->ovsType) {
            nlError = NL_ERROR_INVAL;
            goto Cleanup;
        }
    }

    if (vportAttrs[OVS_VPORT_ATTR_OPTIONS]) {
        OVS_LOG_ERROR("Vport options not supported");
        nlError = NL_ERROR_NOTSUPP;
        goto Cleanup;
    }

    status = OvsCreateMsgFromVport(vport, msgIn, usrParamsCtx->outputBuffer,
                                   usrParamsCtx->outputLength,
                                   gOvsSwitchContext->dpNo);

    *replyLen = msgOut->nlMsg.nlmsgLen;

Cleanup:
    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);

    if (nlError != NL_ERROR_SUCCESS) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
            usrParamsCtx->outputBuffer;

        ASSERT(msgError);
        NlBuildErrorMsg(msgIn, msgError, nlError, replyLen);
        ASSERT(*replyLen != 0);
    }

    return STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 *  Command Handler for 'OVS_VPORT_CMD_DEL'.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsDeleteVportCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                         UINT32 *replyLen)
{
    NDIS_STATUS status = STATUS_SUCCESS;
    LOCK_STATE_EX lockState;

    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
    POVS_VPORT_ENTRY vport = NULL;
    NL_ERROR nlError = NL_ERROR_SUCCESS;
    PSTR portName = NULL;
    UINT32 portNameLen = 0;

    static const NL_POLICY ovsVportPolicy[] = {
        [OVS_VPORT_ATTR_PORT_NO] = { .type = NL_A_U32, .optional = TRUE },
        [OVS_VPORT_ATTR_NAME] = { .type = NL_A_STRING, .maxLen = IFNAMSIZ,
                                  .optional = TRUE },
    };
    PNL_ATTR vportAttrs[ARRAY_SIZE(ovsVportPolicy)];

    ASSERT(usrParamsCtx->inputBuffer != NULL);

    if (!NlAttrParse((PNL_MSG_HDR)msgIn,
        NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN,
        NlMsgAttrsLen((PNL_MSG_HDR)msgIn),
        ovsVportPolicy, ARRAY_SIZE(ovsVportPolicy),
        vportAttrs, ARRAY_SIZE(vportAttrs))) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Output buffer has been validated while validating transact dev op. */
    ASSERT(msgOut != NULL && usrParamsCtx->outputLength >= sizeof *msgOut);

    NdisAcquireRWLockWrite(gOvsSwitchContext->dispatchLock, &lockState, 0);
    if (vportAttrs[OVS_VPORT_ATTR_NAME] != NULL) {
        portName = NlAttrGet(vportAttrs[OVS_VPORT_ATTR_NAME]);
        portNameLen = NlAttrGetSize(vportAttrs[OVS_VPORT_ATTR_NAME]);

        /* the port name is expected to be null-terminated */
        ASSERT(portName[portNameLen - 1] == '\0');

        vport = OvsFindVportByOvsName(gOvsSwitchContext, portName);
    }
    else if (vportAttrs[OVS_VPORT_ATTR_PORT_NO] != NULL) {
        vport = OvsFindVportByPortNo(gOvsSwitchContext,
            NlAttrGetU32(vportAttrs[OVS_VPORT_ATTR_PORT_NO]));
    }

    if (!vport) {
        nlError = NL_ERROR_NODEV;
        goto Cleanup;
    }

    status = OvsCreateMsgFromVport(vport, msgIn, usrParamsCtx->outputBuffer,
                                   usrParamsCtx->outputLength,
                                   gOvsSwitchContext->dpNo);

    *replyLen = msgOut->nlMsg.nlmsgLen;

    /*
     * Mark the port as deleted from OVS userspace. If the port does not exist
     * on the Hyper-V switch, it gets deallocated. Otherwise, it stays.
     */
    status = OvsRemoveAndDeleteVport(usrParamsCtx,
                                     gOvsSwitchContext,
                                     vport,
                                     FALSE,
                                     TRUE);
    if (status) {
        nlError = NlMapStatusToNlErr(status);
    }

Cleanup:
    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);

    if ((nlError != NL_ERROR_SUCCESS) && (nlError != NL_ERROR_PENDING)) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
            usrParamsCtx->outputBuffer;

        ASSERT(msgError);
        NlBuildErrorMsg(msgIn, msgError, nlError, replyLen);
        ASSERT(*replyLen != 0);
    }

    return (status == STATUS_PENDING) ? STATUS_PENDING : STATUS_SUCCESS;
}

static VOID
OvsTunnelVportPendingRemove(PVOID context,
                            NTSTATUS status,
                            UINT32 *replyLen)
{
    POVS_TUNFLT_INIT_CONTEXT tunnelContext =
        (POVS_TUNFLT_INIT_CONTEXT) context;
    POVS_SWITCH_CONTEXT switchContext = tunnelContext->switchContext;
    POVS_VPORT_ENTRY vport = tunnelContext->vport;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)tunnelContext->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)tunnelContext->outputBuffer;
    NL_ERROR nlError = NlMapStatusToNlErr(status);
    LOCK_STATE_EX lockState;

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);

    if (msgIn && msgOut) {
        /* Check the received status to reply to the caller. */
        if (STATUS_SUCCESS == status) {
            OvsCreateMsgFromVport(vport,
                                  msgIn,
                                  msgOut,
                                  tunnelContext->outputLength,
                                  switchContext->dpNo);

            *replyLen = msgOut->nlMsg.nlmsgLen;
        } else {
            POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)msgOut;
            ASSERT(msgError);
            NlBuildErrorMsg(msgIn, msgError, nlError, replyLen);
            ASSERT(*replyLen != 0);
        }
    }

    ASSERT(vport->isAbsentOnHv == TRUE);
    ASSERT(vport->portNo != OVS_DPPORT_NUMBER_INVALID);

    /* Remove the port from the relevant lists. */
    switchContext->numNonHvVports--;
    RemoveEntryList(&vport->ovsNameLink);
    RemoveEntryList(&vport->portNoLink);
    RemoveEntryList(&vport->tunnelVportLink);

    if (vport->priv) {
        OvsFreeMemoryWithTag(vport->priv, OVS_VXLAN_POOL_TAG);
        vport->priv = NULL;
    }

    OvsFreeMemoryWithTag(vport, OVS_VPORT_POOL_TAG);

    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
}

static VOID
OvsTunnelVportPendingInit(PVOID context,
                          NTSTATUS status,
                          UINT32 *replyLen)
{
    POVS_TUNFLT_INIT_CONTEXT tunnelContext =
        (POVS_TUNFLT_INIT_CONTEXT) context;
    POVS_VPORT_ENTRY vport = tunnelContext->vport;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)tunnelContext->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)tunnelContext->outputBuffer;
    PCHAR portName;
    ULONG portNameLen = 0;
    UINT32 portType = 0;
    NL_ERROR nlError = NL_ERROR_SUCCESS;
    BOOLEAN error = TRUE;

    do {
        if (!NT_SUCCESS(status)) {
            nlError = NlMapStatusToNlErr(status);
            break;
        }

        static const NL_POLICY ovsVportPolicy[] = {
            [OVS_VPORT_ATTR_PORT_NO] = { .type = NL_A_U32, .optional = TRUE },
            [OVS_VPORT_ATTR_TYPE] = { .type = NL_A_U32, .optional = FALSE },
            [OVS_VPORT_ATTR_NAME] = { .type = NL_A_STRING, .maxLen = IFNAMSIZ,
            .optional = FALSE },
            [OVS_VPORT_ATTR_UPCALL_PID] = { .type = NL_A_UNSPEC,
            .optional = FALSE },
            [OVS_VPORT_ATTR_OPTIONS] = { .type = NL_A_NESTED, .optional = TRUE },
        };

        PNL_ATTR vportAttrs[ARRAY_SIZE(ovsVportPolicy)];

        /* input buffer has been validated while validating write dev op. */
        ASSERT(msgIn != NULL);

        /* Output buffer has been validated while validating transact dev op. */
        ASSERT(msgOut != NULL && tunnelContext->outputLength >= sizeof *msgOut);

        if (!NlAttrParse((PNL_MSG_HDR)msgIn,
            NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN,
            NlMsgAttrsLen((PNL_MSG_HDR)msgIn),
            ovsVportPolicy, ARRAY_SIZE(ovsVportPolicy),
            vportAttrs, ARRAY_SIZE(vportAttrs))) {
            nlError = NL_ERROR_INVAL;
            break;
        }

        portName = NlAttrGet(vportAttrs[OVS_VPORT_ATTR_NAME]);
        portNameLen = NlAttrGetSize(vportAttrs[OVS_VPORT_ATTR_NAME]);
        portType = NlAttrGetU32(vportAttrs[OVS_VPORT_ATTR_TYPE]);

        if (vport->portNo != OVS_DPPORT_NUMBER_INVALID) {
            nlError = NL_ERROR_EXIST;
            break;
        }

        vport->ovsState = OVS_STATE_CONNECTED;
        vport->nicState = NdisSwitchNicStateConnected;

        /*
         * Allow the vport to be deleted, because there is no
         * corresponding hyper-v switch part.
         */
        vport->isAbsentOnHv = TRUE;

        if (vportAttrs[OVS_VPORT_ATTR_PORT_NO] != NULL) {
            /*
             * XXX: when we implement the limit for OVS port number to be
             * MAXUINT16, we'll need to check the port number received from the
             * userspace.
             */
            vport->portNo =
                NlAttrGetU32(vportAttrs[OVS_VPORT_ATTR_PORT_NO]);
        } else {
            vport->portNo =
                OvsComputeVportNo(gOvsSwitchContext);
            if (vport->portNo == OVS_DPPORT_NUMBER_INVALID) {
                nlError = NL_ERROR_NOMEM;
                break;
            }
        }

        /* The ovs port name must be uninitialized. */
        ASSERT(vport->ovsName[0] == '\0');
        ASSERT(portNameLen <= OVS_MAX_PORT_NAME_LENGTH);

        RtlCopyMemory(vport->ovsName, portName, portNameLen);
        /* if we don't have options, then vport->portOptions will be NULL */
        vport->portOptions = vportAttrs[OVS_VPORT_ATTR_OPTIONS];

        /*
         * XXX: when we implement OVS_DP_ATTR_USER_FEATURES in datapath,
         * we'll need to check the OVS_DP_F_VPORT_PIDS flag: if it is set,
         * it means we have an array of pids, instead of a single pid.
         * ATM we assume we have one pid only.
         */
        vport->upcallPid =
            NlAttrGetU32(vportAttrs[OVS_VPORT_ATTR_UPCALL_PID]);

        status = InitOvsVportCommon(gOvsSwitchContext, vport);
        ASSERT(status == STATUS_SUCCESS);

        OvsCreateMsgFromVport(vport,
                              msgIn,
                              msgOut,
                              tunnelContext->outputLength,
                              gOvsSwitchContext->dpNo);

        *replyLen = msgOut->nlMsg.nlmsgLen;

        error = FALSE;
    } while (error);

    if (error) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)msgOut;

        OvsCleanupVxlanTunnel(NULL, vport, NULL, NULL);
        OvsFreeMemory(vport);

        ASSERT(msgError);
        NlBuildErrorMsg(msgIn, msgError, nlError, replyLen);
        ASSERT(*replyLen != 0);
    }
}
