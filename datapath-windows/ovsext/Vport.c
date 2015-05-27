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
#include "Jhash.h"
#include "Switch.h"
#include "Vport.h"
#include "Event.h"
#include "User.h"
#include "Vxlan.h"
#include "IpHelper.h"
#include "Oid.h"
#include "Datapath.h"

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
static VOID OvsInitPhysNicVport(POVS_VPORT_ENTRY physExtVPort,
                POVS_VPORT_ENTRY virtExtVport, UINT32 nicIndex);
static __inline VOID OvsWaitActivate(POVS_SWITCH_CONTEXT switchContext,
                                     ULONG sleepMicroSec);
static NTSTATUS OvsGetExtInfoIoctl(POVS_VPORT_GET vportGet,
                                   POVS_VPORT_EXT_INFO extInfo);
static NTSTATUS CreateNetlinkMesgForNetdev(POVS_VPORT_EXT_INFO info,
                                           POVS_MESSAGE msgIn,
                                           PVOID outBuffer,
                                           UINT32 outBufLen,
                                           int dpIfIndex);
static POVS_VPORT_ENTRY OvsFindVportByHvNameW(POVS_SWITCH_CONTEXT switchContext,
                                              PWSTR wsName, SIZE_T wstrSize);
static NDIS_STATUS InitHvVportCommon(POVS_SWITCH_CONTEXT switchContext,
                                     POVS_VPORT_ENTRY vport,
                                     BOOLEAN newPort);
static VOID OvsCleanupVportCommon(POVS_SWITCH_CONTEXT switchContext,
                                  POVS_VPORT_ENTRY vport,
                                  BOOLEAN hvSwitchPort,
                                  BOOLEAN hvDelete,
                                  BOOLEAN ovsDelete);
static VOID OvsTunnelVportPendingInit(PVOID context,
                                      NTSTATUS status,
                                      UINT32 *replyLen);
static VOID OvsTunnelVportPendingUninit(PVOID context,
                                        NTSTATUS status,
                                        UINT32 *replyLen);


/*
 * Functions implemented in relaton to NDIS port manipulation.
 */
NDIS_STATUS
HvCreatePort(POVS_SWITCH_CONTEXT switchContext,
             PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    BOOLEAN newPort = FALSE;

    VPORT_PORT_ENTER(portParam);

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    /* Lookup by port ID. */
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            portParam->PortId, 0);
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
    if (vport && vport->isPresentOnHv == FALSE) {
        OVS_LOG_ERROR("Port add failed since a port already exists on "
                      "the specified port Id: %u, ovsName: %s",
                      portParam->PortId, vport->ovsName);
        status = STATUS_DATA_NOT_ACCEPTED;
        goto create_port_done;
    }

    if (vport != NULL) {
        ASSERT(vport->isPresentOnHv);
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
        vport->isPresentOnHv = FALSE;
    } else {
        vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
        if (vport == NULL) {
            status = NDIS_STATUS_RESOURCES;
            goto create_port_done;
        }
        newPort = TRUE;
    }
    OvsInitVportWithPortParam(vport, portParam);
    InitHvVportCommon(switchContext, vport, newPort);

create_port_done:
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    VPORT_PORT_EXIT(portParam);
    return status;
}


/*
 * Function updating the port properties
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
     * We don't allow changing the names of the internal or external ports
     */
    if (vport == NULL || (( vport->portType != NdisSwitchPortTypeSynthetic) &&
        ( vport->portType != NdisSwitchPortTypeEmulated))) {
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
        OvsRemoveAndDeleteVport(NULL, switchContext, vport, TRUE, FALSE);
    } else {
        OVS_LOG_WARN("Vport not present.");
    }
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

    VPORT_PORT_EXIT(portParams);
}


/*
 * Functions implemented in relaton to NDIS NIC manipulation.
 */
NDIS_STATUS
HvCreateNic(POVS_SWITCH_CONTEXT switchContext,
            PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    POVS_VPORT_ENTRY vport;
    UINT32 portNo = 0;
    UINT32 event = 0;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

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

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext, nicParam->PortId, 0);
    if (vport == NULL) {
        OVS_LOG_ERROR("Create NIC without Switch Port,"
                      " PortId: %x, NicIndex: %d",
                      nicParam->PortId, nicParam->NicIndex);
        status = NDIS_STATUS_INVALID_PARAMETER;
        goto add_nic_done;
    }

    if (nicParam->NicType == NdisSwitchNicTypeExternal &&
        nicParam->NicIndex != 0) {
        POVS_VPORT_ENTRY virtExtVport =
            (POVS_VPORT_ENTRY)switchContext->virtualExternalVport;

        vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
        if (vport == NULL) {
            status = NDIS_STATUS_RESOURCES;
            goto add_nic_done;
        }
        OvsInitPhysNicVport(vport, virtExtVport, nicParam->NicIndex);
        status = InitHvVportCommon(switchContext, vport, TRUE);
        if (status != NDIS_STATUS_SUCCESS) {
            OvsFreeMemoryWithTag(vport, OVS_VPORT_POOL_TAG);
            goto add_nic_done;
        }
    }
    OvsInitVportWithNicParam(switchContext, vport, nicParam);
    portNo = vport->portNo;
    if (vport->ovsState == OVS_STATE_CONNECTED) {
        event = OVS_EVENT_CONNECT | OVS_EVENT_LINK_UP;
    } else if (vport->ovsState == OVS_STATE_NIC_CREATED) {
        event = OVS_EVENT_CONNECT;
    }

add_nic_done:
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    if (portNo != OVS_DPPORT_NUMBER_INVALID && event) {
        OvsPostEvent(portNo, event);
    }

done:
    VPORT_NIC_EXIT(nicParam);
    OVS_LOG_TRACE("Exit: status %8x.\n", status);

    return status;
}


/* Mark already created NIC as connected. */
VOID
HvConnectNic(POVS_SWITCH_CONTEXT switchContext,
             PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    LOCK_STATE_EX lockState;
    POVS_VPORT_ENTRY vport;
    UINT32 portNo = 0;

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
    portNo = vport->portNo;

    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

    /* XXX only if portNo != INVALID or always? */
    OvsPostEvent(portNo, OVS_EVENT_LINK_UP);

    if (nicParam->NicType == NdisSwitchNicTypeInternal) {
        OvsInternalAdapterUp(portNo, &nicParam->NetCfgInstanceId);
    }

done:
    VPORT_NIC_EXIT(nicParam);
}

VOID
HvUpdateNic(POVS_SWITCH_CONTEXT switchContext,
            PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;

    UINT32 status = 0, portNo = 0;

    VPORT_NIC_ENTER(nicParam);

    /* Wait for lists to be initialized. */
    OvsWaitActivate(switchContext, OVS_VPORT_DEFAULT_WAIT_TIME_MICROSEC);

    if (!switchContext->isActivated) {
        OVS_LOG_WARN("Switch is not activated yet.");
        goto update_nic_done;
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
        break;
    case NdisSwitchNicTypeSynthetic:
    case NdisSwitchNicTypeEmulated:
        if (!RtlEqualMemory(vport->vmMacAddress, nicParam->VMMacAddress,
                           sizeof (vport->vmMacAddress))) {
            status |= OVS_EVENT_MAC_CHANGE;
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
        status |= OVS_EVENT_MAC_CHANGE;
    }
    if (!RtlEqualMemory(vport->currMacAddress, nicParam->CurrentMacAddress,
                        sizeof (vport->currMacAddress))) {
        RtlCopyMemory(vport->currMacAddress, nicParam->CurrentMacAddress,
                      sizeof (vport->currMacAddress));
        status |= OVS_EVENT_MAC_CHANGE;
    }

    if (vport->mtu != nicParam->MTU) {
        vport->mtu = nicParam->MTU;
        status |= OVS_EVENT_MTU_CHANGE;
    }
    vport->numaNodeId = nicParam->NumaNodeId;
    portNo = vport->portNo;

    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    if (status && portNo) {
        OvsPostEvent(portNo, status);
    }
update_nic_done:
    VPORT_NIC_EXIT(nicParam);
}


VOID
HvDisconnectNic(POVS_SWITCH_CONTEXT switchContext,
                PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    POVS_VPORT_ENTRY vport;
    UINT32 portNo = 0;
    LOCK_STATE_EX lockState;
    BOOLEAN isInternalPort = FALSE;

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
    portNo = vport->portNo;

    if (vport->ovsType == OVS_VPORT_TYPE_INTERNAL) {
        isInternalPort = TRUE;
    }

    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

    /* XXX if portNo != INVALID or always? */
    OvsPostEvent(portNo, OVS_EVENT_LINK_DOWN);

    if (isInternalPort) {
        OvsInternalAdapterDown();
    }

done:
    VPORT_NIC_EXIT(nicParam);
}


VOID
HvDeleteNic(POVS_SWITCH_CONTEXT switchContext,
            PNDIS_SWITCH_NIC_PARAMETERS nicParam)
{
    LOCK_STATE_EX lockState;
    POVS_VPORT_ENTRY vport;
    UINT32 portNo = 0;

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

    portNo = vport->portNo;
    if (vport->portType == NdisSwitchPortTypeExternal &&
        vport->nicIndex != 0) {
        OvsRemoveAndDeleteVport(NULL, switchContext, vport, TRUE, FALSE);
    }

    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    /* XXX if portNo != INVALID or always? */
    OvsPostEvent(portNo, OVS_EVENT_DISCONNECT);

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
OvsFindTunnelVportByDstPort(POVS_SWITCH_CONTEXT switchContext,
                            UINT16 dstPort)
{
    POVS_VPORT_ENTRY vport;
    PLIST_ENTRY head, link;
    UINT32 hash = OvsJhashBytes((const VOID *)&dstPort, sizeof(dstPort),
                                OVS_HASH_BASIS);
    head = &(switchContext->tunnelVportsArray[hash & OVS_VPORT_MASK]);
    LIST_FORALL(head, link) {
        vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, tunnelVportLink);
        if (((POVS_VXLAN_VPORT)vport->priv)->dstPort == dstPort) {
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
    } else if (switchContext->internalVport &&
               portId == switchContext->internalPortId &&
               index == switchContext->internalVport->nicIndex) {
        return (POVS_VPORT_ENTRY)switchContext->internalVport;
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
    vport->isPresentOnHv = FALSE;
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
    vport->isBridgeInternal = FALSE;

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
    ASSERT(vport->ovsState == OVS_STATE_PORT_CREATED);

    UNREFERENCED_PARAMETER(switchContext);

    RtlCopyMemory(vport->permMacAddress, nicParam->PermanentMacAddress,
                  sizeof (nicParam->PermanentMacAddress));
    RtlCopyMemory(vport->currMacAddress, nicParam->CurrentMacAddress,
                  sizeof (nicParam->CurrentMacAddress));

    if (nicParam->NicType == NdisSwitchNicTypeSynthetic ||
        nicParam->NicType == NdisSwitchNicTypeEmulated) {
        RtlCopyMemory(vport->vmMacAddress, nicParam->VMMacAddress,
                      sizeof (nicParam->VMMacAddress));
        RtlCopyMemory(&vport->vmName, &nicParam->VmName,
                      sizeof (nicParam->VmName));
    } else {
        RtlCopyMemory(&vport->netCfgInstanceId, &nicParam->NetCfgInstanceId,
                      sizeof (nicParam->NetCfgInstanceId));
    }
    RtlCopyMemory(&vport->nicName, &nicParam->NicName,
                  sizeof (nicParam->NicName));
    vport->mtu = nicParam->MTU;
    vport->nicState = nicParam->NicState;
    vport->nicIndex = nicParam->NicIndex;
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
 * Copies the relevant NDIS port properties from a virtual (pseudo) external
 * NIC to a physical (real) external NIC.
 * --------------------------------------------------------------------------
 */
static VOID
OvsInitPhysNicVport(POVS_VPORT_ENTRY physExtVport,
                    POVS_VPORT_ENTRY virtExtVport,
                    UINT32 physNicIndex)
{
    physExtVport->portType = virtExtVport->portType;
    physExtVport->portState = virtExtVport->portState;
    physExtVport->portId = virtExtVport->portId;
    physExtVport->nicState = NdisSwitchNicStateUnknown;
    physExtVport->ovsType = OVS_VPORT_TYPE_NETDEV;
    physExtVport->isExternal = TRUE;
    physExtVport->isBridgeInternal = FALSE;
    physExtVport->nicIndex = (NDIS_SWITCH_NIC_INDEX)physNicIndex;

    RtlCopyMemory(&physExtVport->hvPortName, &virtExtVport->hvPortName,
                  sizeof (NDIS_SWITCH_PORT_NAME));

    /* 'portFriendlyName' is overwritten later. */
    RtlCopyMemory(&physExtVport->portFriendlyName,
                  &virtExtVport->portFriendlyName,
                  sizeof(NDIS_SWITCH_PORT_FRIENDLYNAME));

    physExtVport->ovsState = OVS_STATE_PORT_CREATED;
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

    vport->isBridgeInternal = FALSE;
    vport->ovsType = ovsType;
    vport->ovsState = OVS_STATE_PORT_CREATED;
    switch (ovsType) {
    case OVS_VPORT_TYPE_GRE:
        break;
    case OVS_VPORT_TYPE_GRE64:
        break;
    case OVS_VPORT_TYPE_VXLAN:
    {
        POVS_TUNFLT_INIT_CONTEXT tunnelContext = NULL;

        tunnelContext = OvsAllocateMemory(sizeof(*tunnelContext));
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
        break;
    }
    default:
        ASSERT(0);
    }
    return status;
}

/*
 * --------------------------------------------------------------------------
 * Initializes a bridge internal vport ie. a port of type
 * OVS_VPORT_TYPE_INTERNAL but not present on the Hyper-V switch.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsInitBridgeInternalVport(POVS_VPORT_ENTRY vport)
{
    vport->isBridgeInternal = TRUE;
    vport->ovsType = OVS_VPORT_TYPE_INTERNAL;
    /* Mark the status to be connected, since there is no other initialization
     * for this port. */
    vport->ovsState = OVS_STATE_CONNECTED;
    return STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * For external vports 'portFriendlyName' provided by Hyper-V is over-written
 * by synthetic names.
 * --------------------------------------------------------------------------
 */
static VOID
AssignNicNameSpecial(POVS_VPORT_ENTRY vport)
{
    size_t len;

    if (vport->portType == NdisSwitchPortTypeExternal) {
        if (vport->nicIndex == 0) {
            ASSERT(vport->nicIndex == 0);
            RtlStringCbPrintfW(vport->portFriendlyName.String,
                               IF_MAX_STRING_SIZE,
                               L"%s.virtualAdapter", OVS_DPPORT_EXTERNAL_NAME_W);
        } else {
            RtlStringCbPrintfW(vport->portFriendlyName.String,
                               IF_MAX_STRING_SIZE,
                               L"%s.%lu", OVS_DPPORT_EXTERNAL_NAME_W,
                               (UINT32)vport->nicIndex);
        }
    } else {
        RtlStringCbPrintfW(vport->portFriendlyName.String,
                           IF_MAX_STRING_SIZE,
                           L"%s", OVS_DPPORT_INTERNAL_NAME_W);
    }

    RtlStringCbLengthW(vport->portFriendlyName.String, IF_MAX_STRING_SIZE,
                       &len);
    vport->portFriendlyName.Length = (USHORT)len;
}


/*
 * --------------------------------------------------------------------------
 * Functionality common to any port on the Hyper-V switch. This function is not
 * to be called for a port that is not on the Hyper-V switch.
 *
 * Inserts the port into 'portIdHashArray' and caches the pointer in the
 * 'switchContext' if needed.
 *
 * For external NIC, assigns the name for the NIC.
 * --------------------------------------------------------------------------
 */
static NDIS_STATUS
InitHvVportCommon(POVS_SWITCH_CONTEXT switchContext,
                  POVS_VPORT_ENTRY vport,
                  BOOLEAN newPort)
{
    UINT32 hash;

    switch (vport->portType) {
    case NdisSwitchPortTypeExternal:
        /*
         * Overwrite the 'portFriendlyName' of this external vport. The reason
         * for having this in common code is to be able to call it from the NDIS
         * Port callback as well as the NDIS NIC callback.
         */
        AssignNicNameSpecial(vport);

        if (vport->nicIndex == 0) {
            switchContext->virtualExternalPortId = vport->portId;
            switchContext->virtualExternalVport = vport;
        } else {
            switchContext->numPhysicalNics++;
        }
        break;
    case NdisSwitchPortTypeInternal:
        ASSERT(vport->isBridgeInternal == FALSE);

        /* Overwrite the 'portFriendlyName' of the internal vport. */
        AssignNicNameSpecial(vport);
        switchContext->internalPortId = vport->portId;
        switchContext->internalVport = vport;
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
        return NDIS_STATUS_SUCCESS;
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
    return NDIS_STATUS_SUCCESS;
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
    case OVS_VPORT_TYPE_VXLAN:
    {
        POVS_VXLAN_VPORT vxlanVport = (POVS_VXLAN_VPORT)vport->priv;
        hash = OvsJhashBytes(&vxlanVport->dstPort,
                             sizeof(vxlanVport->dstPort),
                             OVS_HASH_BASIS);
        InsertHeadList(
            &gOvsSwitchContext->tunnelVportsArray[hash & OVS_VPORT_MASK],
            &vport->tunnelVportLink);
        switchContext->numNonHvVports++;
        break;
    }
    case OVS_VPORT_TYPE_INTERNAL:
        if (vport->isBridgeInternal) {
            switchContext->numNonHvVports++;
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

static VOID
OvsCleanupVportCommon(POVS_SWITCH_CONTEXT switchContext,
                      POVS_VPORT_ENTRY vport,
                      BOOLEAN hvSwitchPort,
                      BOOLEAN hvDelete,
                      BOOLEAN ovsDelete)
{
    BOOLEAN deletedOnOvs = FALSE;
    BOOLEAN deletedOnHv = FALSE;

    /*
     * 'hvDelete' == TRUE indicates that the port should be removed from the
     * 'portIdHashArray', while 'ovsDelete' == TRUE indicates that the port
     * should be removed from 'portNoHashArray' and the 'ovsPortNameHashArray'.
     *
     * Both 'hvDelete' and 'ovsDelete' can be set to TRUE by the caller.
     */
    if (vport->isPresentOnHv == TRUE) {
        deletedOnHv = TRUE;
    }
    if (vport->portNo == OVS_DPPORT_NUMBER_INVALID) {
        deletedOnOvs = TRUE;
    }

    if (hvDelete && !deletedOnHv) {
        vport->isPresentOnHv = TRUE;

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
        if (OVS_VPORT_TYPE_VXLAN == vport->ovsType) {
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
        }
        else {
            switchContext->numNonHvVports--;
        }
        OvsFreeMemoryWithTag(vport, OVS_VPORT_POOL_TAG);
    }
}

/*
 * --------------------------------------------------------------------------
 * Provides functionality that is partly complementatry to
 * InitOvsVportCommon()/InitHvVportCommon().
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
    NTSTATUS status = STATUS_SUCCESS;
    POVS_USER_PARAMS_CONTEXT usrParamsCtx =
        (POVS_USER_PARAMS_CONTEXT)usrParamsContext;
    BOOLEAN hvSwitchPort = FALSE;

    if (vport->isExternal) {
        if (vport->nicIndex == 0) {
            ASSERT(switchContext->numPhysicalNics == 0);
            switchContext->virtualExternalPortId = 0;
            switchContext->virtualExternalVport = NULL;
            OvsFreeMemoryWithTag(vport, OVS_VPORT_POOL_TAG);
            return STATUS_SUCCESS;
        } else {
            ASSERT(switchContext->numPhysicalNics);
            switchContext->numPhysicalNics--;
            hvSwitchPort = TRUE;
        }
    }

    switch (vport->ovsType) {
    case OVS_VPORT_TYPE_INTERNAL:
        if (!vport->isBridgeInternal) {
            switchContext->internalPortId = 0;
            switchContext->internalVport = NULL;
            OvsInternalAdapterDown();
            hvSwitchPort = TRUE;
        }
        break;
    case OVS_VPORT_TYPE_VXLAN:
    {
        POVS_TUNFLT_INIT_CONTEXT tunnelContext = NULL;
        PIRP irp = NULL;

        tunnelContext = OvsAllocateMemory(sizeof(*tunnelContext));
        if (tunnelContext == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        RtlZeroMemory(tunnelContext, sizeof(*tunnelContext));

        tunnelContext->switchContext = switchContext;
        tunnelContext->hvSwitchPort = hvSwitchPort;
        tunnelContext->hvDelete = hvDelete;
        tunnelContext->ovsDelete = ovsDelete;
        tunnelContext->vport = vport;

        if (usrParamsCtx) {
            tunnelContext->inputBuffer = usrParamsCtx->inputBuffer;
            tunnelContext->outputBuffer = usrParamsCtx->outputBuffer;
            tunnelContext->outputLength = usrParamsCtx->outputLength;
            irp = usrParamsCtx->irp;
        }

        status = OvsCleanupVxlanTunnel(irp,
                                       vport,
                                       OvsTunnelVportPendingUninit,
                                       tunnelContext);
        break;
    }
    case OVS_VPORT_TYPE_GRE:
    case OVS_VPORT_TYPE_GRE64:
        break;
    case OVS_VPORT_TYPE_NETDEV:
        hvSwitchPort = TRUE;
    default:
        break;
    }

    if (STATUS_SUCCESS == status) {
        OvsCleanupVportCommon(switchContext,
                              vport,
                              hvSwitchPort,
                              hvDelete,
                              ovsDelete);
    }

    return status;
}

NDIS_STATUS
OvsAddConfiguredSwitchPorts(POVS_SWITCH_CONTEXT switchContext)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    ULONG arrIndex;
    PNDIS_SWITCH_PORT_PARAMETERS portParam;
    PNDIS_SWITCH_PORT_ARRAY portArray = NULL;
    POVS_VPORT_ENTRY vport;

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

         vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
         if (vport == NULL) {
             status = NDIS_STATUS_RESOURCES;
             goto cleanup;
         }
         OvsInitVportWithPortParam(vport, portParam);
         status = InitHvVportCommon(switchContext, vport, TRUE);
         if (status != NDIS_STATUS_SUCCESS) {
             OvsFreeMemoryWithTag(vport, OVS_VPORT_POOL_TAG);
             goto cleanup;
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


NDIS_STATUS
OvsInitConfiguredSwitchNics(POVS_SWITCH_CONTEXT switchContext)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PNDIS_SWITCH_NIC_ARRAY nicArray = NULL;
    ULONG arrIndex;
    PNDIS_SWITCH_NIC_PARAMETERS nicParam;
    POVS_VPORT_ENTRY vport;

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
         */

        /*
         * XXX: Check if the port is connected to a VF. Disconnect the VF in
         * such a case.
         */

        if (nicParam->NicType == NdisSwitchNicTypeExternal &&
            nicParam->NicIndex != 0) {
            POVS_VPORT_ENTRY virtExtVport =
                   (POVS_VPORT_ENTRY)switchContext->virtualExternalVport;

            vport = OvsAllocateVport();
            if (vport) {
                OvsInitPhysNicVport(vport, virtExtVport,
                                    nicParam->NicIndex);
                status = InitHvVportCommon(switchContext, vport, TRUE);
                if (status != NDIS_STATUS_SUCCESS) {
                    OvsFreeMemoryWithTag(vport, OVS_VPORT_POOL_TAG);
                    vport = NULL;
                }
            }
        } else {
            vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                                    nicParam->PortId,
                                                    nicParam->NicIndex);
        }
        if (vport == NULL) {
            OVS_LOG_ERROR("Fail to allocate vport");
            continue;
        }
        OvsInitVportWithNicParam(switchContext, vport, nicParam);
        if (nicParam->NicType == NdisSwitchNicTypeInternal) {
            OvsInternalAdapterUp(vport->portNo, &nicParam->NetCfgInstanceId);
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
 * are deleted by walking the the 'portNoHashArray'.
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
                   (vport->ovsType == OVS_VPORT_TYPE_INTERNAL &&
                    vport->isBridgeInternal) || vport->isPresentOnHv == TRUE);
            OvsRemoveAndDeleteVport(NULL, switchContext, vport, TRUE, TRUE);
        }
    }

    ASSERT(switchContext->virtualExternalVport == NULL);
    ASSERT(switchContext->internalVport == NULL);
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
    size_t len;
    LOCK_STATE_EX lockState;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN doConvert = FALSE;

    RtlZeroMemory(extInfo, sizeof (POVS_VPORT_EXT_INFO));
    NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState, 0);
    if (vportGet->portNo == 0) {
        StringCbLengthA(vportGet->name, OVS_MAX_PORT_NAME_LENGTH - 1, &len);
        vport = OvsFindVportByHvNameA(gOvsSwitchContext, vportGet->name);
        if (vport != NULL) {
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
            extInfo->vmUUID[0] = 0;
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
        ovsNetdevPolicy, netdevAttrs, ARRAY_SIZE(netdevAttrs))) {
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

        NlBuildErrorMsg(msgIn, msgError, nlError);
        *replyLen = msgError->nlMsg.nlmsgLen;
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
        ovsVportPolicy, vportAttrs, ARRAY_SIZE(vportAttrs))) {
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

        NlBuildErrorMsg(msgIn, msgError, nlError);
        *replyLen = msgError->nlMsg.nlmsgLen;
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
    BOOLEAN isBridgeInternal = FALSE;
    BOOLEAN vportAllocated = FALSE, vportInitialized = FALSE;
    BOOLEAN addInternalPortAsNetdev = FALSE;

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
        ovsVportPolicy, vportAttrs, ARRAY_SIZE(vportAttrs))) {
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

    if (portName && portType == OVS_VPORT_TYPE_NETDEV &&
        !strcmp(OVS_DPPORT_INTERNAL_NAME_A, portName)) {
        addInternalPortAsNetdev = TRUE;
    }

    if (portName && portType == OVS_VPORT_TYPE_INTERNAL &&
        strcmp(OVS_DPPORT_INTERNAL_NAME_A, portName)) {
        isBridgeInternal = TRUE;
    }

    if (portType == OVS_VPORT_TYPE_INTERNAL && !isBridgeInternal) {
        vport = gOvsSwitchContext->internalVport;
    } else if (portType == OVS_VPORT_TYPE_NETDEV) {
        /* External ports can also be looked up like VIF ports. */
        vport = OvsFindVportByHvNameA(gOvsSwitchContext, portName);
    } else {
        ASSERT(OvsIsTunnelVportType(portType) ||
               (portType == OVS_VPORT_TYPE_INTERNAL && isBridgeInternal));

        vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
        if (vport == NULL) {
            nlError = NL_ERROR_NOMEM;
            goto Cleanup;
        }
        vportAllocated = TRUE;

        if (OvsIsTunnelVportType(portType)) {
            UINT16 udpPortDest = VXLAN_UDP_PORT;
            PNL_ATTR attr = NlAttrFindNested(vportAttrs[OVS_VPORT_ATTR_OPTIONS],
                                             OVS_TUNNEL_ATTR_DST_PORT);
            if (attr) {
                udpPortDest = NlAttrGetU16(attr);
            }

            status = OvsInitTunnelVport(usrParamsCtx,
                                        vport,
                                        portType,
                                        udpPortDest);

            nlError = NlMapStatusToNlErr(status);
        } else {
            OvsInitBridgeInternalVport(vport);
        }

        vportInitialized = TRUE;

        if (nlError == NL_ERROR_SUCCESS) {
            vport->ovsState = OVS_STATE_CONNECTED;
            vport->nicState = NdisSwitchNicStateConnected;

            /*
             * Allow the vport to be deleted, because there is no
             * corresponding hyper-v switch part.
             */
            vport->isPresentOnHv = TRUE;
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

    /* Initialize the vport with OVS specific properties. */
    if (addInternalPortAsNetdev != TRUE) {
        vport->ovsType = portType;
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

Cleanup:
    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);

    if ((nlError != NL_ERROR_SUCCESS) && (nlError != NL_ERROR_PENDING)) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
            usrParamsCtx->outputBuffer;

        if (vport && vportAllocated == TRUE) {
            if (vportInitialized == TRUE) {
                if (OvsIsTunnelVportType(portType)) {
                    OvsCleanupVxlanTunnel(NULL, vport, NULL, NULL);
                }
            }
            OvsFreeMemoryWithTag(vport, OVS_VPORT_POOL_TAG);
        }

        NlBuildErrorMsg(msgIn, msgError, nlError);
        *replyLen = msgError->nlMsg.nlmsgLen;
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
        ovsVportPolicy, vportAttrs, ARRAY_SIZE(vportAttrs))) {
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

        NlBuildErrorMsg(msgIn, msgError, nlError);
        *replyLen = msgError->nlMsg.nlmsgLen;
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
        ovsVportPolicy, vportAttrs, ARRAY_SIZE(vportAttrs))) {
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

        NlBuildErrorMsg(msgIn, msgError, nlError);
        *replyLen = msgError->nlMsg.nlmsgLen;
    }

    return (status == STATUS_PENDING) ? STATUS_PENDING : STATUS_SUCCESS;
}

static VOID
OvsTunnelVportPendingUninit(PVOID context,
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

            NlBuildErrorMsg(msgIn, msgError, nlError);
            *replyLen = msgError->nlMsg.nlmsgLen;
        }
    }

    OvsCleanupVportCommon(switchContext,
                          vport,
                          tunnelContext->hvSwitchPort,
                          tunnelContext->hvDelete,
                          tunnelContext->ovsDelete);

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
            ovsVportPolicy, vportAttrs, ARRAY_SIZE(vportAttrs))) {
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
        vport->isPresentOnHv = TRUE;

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
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR) msgOut;

        OvsCleanupVxlanTunnel(NULL, vport, NULL, NULL);
        OvsFreeMemory(vport);

        NlBuildErrorMsg(msgIn, msgError, nlError);
        *replyLen = msgError->nlMsg.nlmsgLen;
    }
}
