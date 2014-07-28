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
#include "OvsVxlan.h"
#include "OvsIpHelper.h"
#include "OvsOid.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_VPORT
#include "OvsDebug.h"

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

extern POVS_SWITCH_CONTEXT gOvsSwitchContext;
extern PNDIS_SPIN_LOCK gOvsCtrlLock;

static UINT32 OvsGetVportNo(POVS_SWITCH_CONTEXT switchContext, UINT32 nicIndex,
                            OVS_VPORT_TYPE ovsType);
static POVS_VPORT_ENTRY OvsAllocateVport(VOID);
static VOID OvsInitVportWithPortParam(POVS_VPORT_ENTRY vport,
                PNDIS_SWITCH_PORT_PARAMETERS portParam);
static VOID OvsInitVportWithNicParam(POVS_SWITCH_CONTEXT switchContext,
                POVS_VPORT_ENTRY vport, PNDIS_SWITCH_NIC_PARAMETERS nicParam);
static VOID OvsInitPhysNicVport(POVS_VPORT_ENTRY vport, POVS_VPORT_ENTRY
                virtVport, UINT32 nicIndex);
static VOID OvsInitPhysNicVport(POVS_VPORT_ENTRY vport, POVS_VPORT_ENTRY
                virtVport, UINT32 nicIndex);
static NDIS_STATUS OvsInitVportCommon(POVS_SWITCH_CONTEXT switchContext,
                POVS_VPORT_ENTRY vport);
static VOID OvsRemoveAndDeleteVport(POVS_SWITCH_CONTEXT switchContext,
                POVS_VPORT_ENTRY vport);
static __inline VOID OvsWaitActivate(POVS_SWITCH_CONTEXT switchContext,
                                     ULONG sleepMicroSec);

/*
 * Functions implemented in relaton to NDIS port manipulation.
 */
NDIS_STATUS
OvsCreatePort(POVS_SWITCH_CONTEXT switchContext,
              PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    VPORT_PORT_ENTER(portParam);

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            portParam->PortId, 0);
    if (vport != NULL) {
        status = STATUS_DATA_NOT_ACCEPTED;
        goto create_port_done;
    }
    vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
    if (vport == NULL) {
        status = NDIS_STATUS_RESOURCES;
        goto create_port_done;
    }
    OvsInitVportWithPortParam(vport, portParam);
    OvsInitVportCommon(switchContext, vport);

create_port_done:
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
    VPORT_PORT_EXIT(portParam);
    return status;
}

VOID
OvsTeardownPort(POVS_SWITCH_CONTEXT switchContext,
                PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;

    VPORT_PORT_ENTER(portParam);

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            portParam->PortId, 0);
    if (vport) {
        /* add assertion here
         */
        vport->portState = NdisSwitchPortStateTeardown;
        vport->ovsState = OVS_STATE_PORT_TEAR_DOWN;
    } else {
        OVS_LOG_WARN("Vport not present.");
    }
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

    VPORT_PORT_EXIT(portParam);
}



VOID
OvsDeletePort(POVS_SWITCH_CONTEXT switchContext,
              PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;

    VPORT_PORT_ENTER(portParam);

    NdisAcquireRWLockWrite(switchContext->dispatchLock, &lockState, 0);
    vport = OvsFindVportByPortIdAndNicIndex(switchContext,
                                            portParam->PortId, 0);
    if (vport) {
        OvsRemoveAndDeleteVport(switchContext, vport);
    } else {
        OVS_LOG_WARN("Vport not present.");
    }
    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

    VPORT_PORT_EXIT(portParam);
}


/*
 * Functions implemented in relaton to NDIS NIC manipulation.
 */
NDIS_STATUS
OvsCreateNic(POVS_SWITCH_CONTEXT switchContext,
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
        POVS_VPORT_ENTRY virtVport =
            (POVS_VPORT_ENTRY)switchContext->externalVport;
        vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
        if (vport == NULL) {
            status = NDIS_STATUS_RESOURCES;
            goto add_nic_done;
        }
        OvsInitPhysNicVport(vport, virtVport, nicParam->NicIndex);
        status = OvsInitVportCommon(switchContext, vport);
        if (status != NDIS_STATUS_SUCCESS) {
            OvsFreeMemory(vport);
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
    if (portNo && event) {
        OvsPostEvent(portNo, event);
    }

done:
    VPORT_NIC_EXIT(nicParam);
    OVS_LOG_TRACE("Exit: status %8x.\n", status);

    return status;
}


/* Mark already created NIC as connected. */
VOID
OvsConnectNic(POVS_SWITCH_CONTEXT switchContext,
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

    OvsPostEvent(portNo, OVS_EVENT_LINK_UP);

    if (nicParam->NicType == NdisSwitchNicTypeInternal) {
        OvsInternalAdapterUp(portNo, &nicParam->NetCfgInstanceId);
    }

done:
    VPORT_NIC_EXIT(nicParam);
}

VOID
OvsUpdateNic(POVS_SWITCH_CONTEXT switchContext,
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
OvsDisconnectNic(POVS_SWITCH_CONTEXT switchContext,
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

    if (vport->ovsType == OVSWIN_VPORT_TYPE_INTERNAL) {
        isInternalPort = TRUE;
    }

    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);

    OvsPostEvent(portNo, OVS_EVENT_LINK_DOWN);

    if (isInternalPort) {
        OvsInternalAdapterDown();
    }

done:
    VPORT_NIC_EXIT(nicParam);
}


VOID
OvsDeleteNic(POVS_SWITCH_CONTEXT switchContext,
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

    portNo = vport->portNo;
    if (vport->portType == NdisSwitchPortTypeExternal &&
        vport->nicIndex != 0) {
        OvsRemoveAndDeleteVport(switchContext, vport);
    }
    vport->nicState = NdisSwitchNicStateUnknown;
    vport->ovsState = OVS_STATE_PORT_CREATED;

    NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
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
    if (OVS_VPORT_INDEX(portNo) < OVS_MAX_VPORT_ARRAY_SIZE) {
        if (OVS_IS_VPORT_ENTRY_NULL(switchContext, OVS_VPORT_INDEX(portNo))) {
            return NULL;
        } else {
            POVS_VPORT_ENTRY vport;
            vport = (POVS_VPORT_ENTRY)
                     switchContext->vportArray[OVS_VPORT_INDEX(portNo)];
            return vport->portNo == portNo ? vport : NULL;
        }
    }
    return NULL;
}


POVS_VPORT_ENTRY
OvsFindVportByOvsName(POVS_SWITCH_CONTEXT switchContext,
                      CHAR *name,
                      UINT32 length)
{
    POVS_VPORT_ENTRY vport;
    PLIST_ENTRY head, link;
    UINT32 hash = OvsJhashBytes((const VOID *)name, length, OVS_HASH_BASIS);
    head = &(switchContext->nameHashArray[hash & OVS_VPORT_MASK]);
    LIST_FORALL(head, link) {
        vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, nameLink);
        if (vport->ovsNameLen == length &&
            RtlEqualMemory(name, vport->ovsName, length)) {
            return vport;
        }
    }
    return NULL;
}

POVS_VPORT_ENTRY
OvsFindVportByPortIdAndNicIndex(POVS_SWITCH_CONTEXT switchContext,
                                NDIS_SWITCH_PORT_ID portId,
                                NDIS_SWITCH_NIC_INDEX index)
{
    if (portId == switchContext->externalPortId) {
        if (index == 0) {
            return (POVS_VPORT_ENTRY)switchContext->externalVport;
        } else if (index > OVS_MAX_PHYS_ADAPTERS) {
            return NULL;
        }
        if (OVS_IS_VPORT_ENTRY_NULL(switchContext,
                                    index + OVS_EXTERNAL_VPORT_START)) {
           return NULL;
        } else {
           return (POVS_VPORT_ENTRY)switchContext->vportArray[
                            index + OVS_EXTERNAL_VPORT_START];
        }
    } else if (switchContext->internalPortId == portId) {
        return (POVS_VPORT_ENTRY)switchContext->internalVport;
    } else {
        PLIST_ENTRY head, link;
        POVS_VPORT_ENTRY vport;
        UINT32 hash;
        hash = OvsJhashWords((UINT32 *)&portId, 1, OVS_HASH_BASIS);
        head = &(switchContext->portHashArray[hash & OVS_VPORT_MASK]);
        LIST_FORALL(head, link) {
            vport = CONTAINING_RECORD(link, OVS_VPORT_ENTRY, portLink);
            if (portId == vport->portId && index == vport->nicIndex) {
                return vport;
            }
        }
        return NULL;
    }
}

static UINT32
OvsGetVportNo(POVS_SWITCH_CONTEXT switchContext,
              UINT32 nicIndex,
              OVS_VPORT_TYPE ovsType)
{
    UINT32 index = 0xffffff, i = 0;
    UINT64 gen;

    switch (ovsType) {
    case OVSWIN_VPORT_TYPE_EXTERNAL:
        if (nicIndex == 0) {
            return 0;  // not a valid portNo
        } else if (nicIndex > OVS_MAX_PHYS_ADAPTERS) {
            return 0;
        } else {
            index = nicIndex + OVS_EXTERNAL_VPORT_START;
        }
        break;
    case OVSWIN_VPORT_TYPE_INTERNAL:
        index = OVS_INTERNAL_VPORT_DEFAULT_INDEX;
        break;
    case OVSWIN_VPORT_TYPE_SYNTHETIC:
    case OVSWIN_VPORT_TYPE_EMULATED:
        index = switchContext->lastPortIndex + 1;
        if (index == OVS_MAX_VPORT_ARRAY_SIZE) {
            index = OVS_VM_VPORT_START;
        }
        while (!OVS_IS_VPORT_ENTRY_NULL(switchContext, index) &&
               i < (OVS_MAX_VPORT_ARRAY_SIZE - OVS_VM_VPORT_START)) {
            index++;
            i++;
            if (index == OVS_MAX_VPORT_ARRAY_SIZE) {
                index = OVS_VM_VPORT_START;
            }
        }
        if (i == (OVS_MAX_VPORT_ARRAY_SIZE - OVS_VM_VPORT_START)) {
            return 0; // not available
        }
        switchContext->lastPortIndex = index;
        break;
    case OVSWIN_VPORT_TYPE_GRE:
        index = OVS_GRE_VPORT_INDEX;
        break;
    case OVSWIN_VPORT_TYPE_GRE64:
        index = OVS_GRE64_VPORT_INDEX;
        break;
    case OVSWIN_VPORT_TYPE_VXLAN:
        index = OVS_VXLAN_VPORT_INDEX;
        break;
    case OVSWIN_VPORT_TYPE_LOCAL:
    default:
        ASSERT(0);
    }
    if (index > OVS_MAX_VPORT_ARRAY_SIZE) {
        return 0;
    }
    gen = (UINT64)switchContext->vportArray[index];
    if (gen > 0xff) {
        return 0;
    } else if (gen == 0) {
        gen++;
    }
    return OVS_VPORT_PORT_NO(index, (UINT32)gen);
}


static POVS_VPORT_ENTRY
OvsAllocateVport(VOID)
{
    POVS_VPORT_ENTRY vport;
    vport = (POVS_VPORT_ENTRY)OvsAllocateMemory(sizeof (OVS_VPORT_ENTRY));
    if (vport == NULL) {
        return NULL;
    }
    RtlZeroMemory(vport, sizeof (OVS_VPORT_ENTRY));
    vport->ovsState = OVS_STATE_UNKNOWN;
    return vport;
}

static VOID
OvsInitVportWithPortParam(POVS_VPORT_ENTRY vport,
                          PNDIS_SWITCH_PORT_PARAMETERS portParam)
{
    vport->isValidationPort = portParam->IsValidationPort;
    vport->portType = portParam->PortType;
    vport->portState = portParam->PortState;
    vport->portId = portParam->PortId;
    vport->nicState = NdisSwitchNicStateUnknown;

    switch (vport->portType) {
    case NdisSwitchPortTypeExternal:
        vport->ovsType = OVSWIN_VPORT_TYPE_EXTERNAL;
        break;
    case NdisSwitchPortTypeInternal:
        vport->ovsType = OVSWIN_VPORT_TYPE_INTERNAL;
        break;
    case NdisSwitchPortTypeSynthetic:
        vport->ovsType = OVSWIN_VPORT_TYPE_SYNTHETIC;
        break;
    case NdisSwitchPortTypeEmulated:
        vport->ovsType = OVSWIN_VPORT_TYPE_EMULATED;
        break;
    }
    RtlCopyMemory(&vport->portName, &portParam->PortName,
                  sizeof (NDIS_SWITCH_PORT_NAME));
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

static VOID
OvsInitPhysNicVport(POVS_VPORT_ENTRY vport,
                    POVS_VPORT_ENTRY virtVport,
                    UINT32 nicIndex)
{
    vport->isValidationPort = virtVport->isValidationPort;
    vport->portType = virtVport->portType;
    vport->portState = virtVport->portState;
    vport->portId = virtVport->portId;
    vport->nicState = NdisSwitchNicStateUnknown;
    vport->ovsType = OVSWIN_VPORT_TYPE_EXTERNAL;
    vport->nicIndex = (NDIS_SWITCH_NIC_INDEX)nicIndex;
    RtlCopyMemory(&vport->portName, &virtVport->portName,
                  sizeof (NDIS_SWITCH_PORT_NAME));
    vport->ovsState = OVS_STATE_PORT_CREATED;
}
static NDIS_STATUS
OvsInitVportCommon(POVS_SWITCH_CONTEXT switchContext,
POVS_VPORT_ENTRY vport)
{
    UINT32 hash;
    size_t len;
    if (vport->portType != NdisSwitchPortTypeExternal ||
        vport->nicIndex != 0) {
        vport->portNo = OvsGetVportNo(switchContext, vport->nicIndex,
            vport->ovsType);
        if (vport->portNo == 0) {
            return NDIS_STATUS_RESOURCES;
        }
        ASSERT(OVS_IS_VPORT_ENTRY_NULL(switchContext,
            OVS_VPORT_INDEX(vport->portNo)));

        switchContext->vportArray[OVS_VPORT_INDEX(vport->portNo)] = vport;
    }
    switch (vport->portType) {
    case NdisSwitchPortTypeExternal:
        if (vport->nicIndex == 0) {
            switchContext->externalPortId = vport->portId;
            switchContext->externalVport = vport;
            RtlStringCbPrintfA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1,
                "external.virtualAdapter");
        }
        else {
            switchContext->numPhysicalNics++;
            RtlStringCbPrintfA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1,
                "external.%lu", (UINT32)vport->nicIndex);
        }
        break;
    case NdisSwitchPortTypeInternal:
        switchContext->internalPortId = vport->portId;
        switchContext->internalVport = vport;
        RtlStringCbPrintfA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1,
            "internal");
        break;
    case NdisSwitchPortTypeSynthetic:
        RtlStringCbPrintfA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1,
            "vmNICSyn.%lx", vport->portNo);
        break;
    case NdisSwitchPortTypeEmulated:
        RtlStringCbPrintfA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1,
            "vmNICEmu.%lx", vport->portNo);
        break;
    }
    StringCbLengthA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1, &len);
    vport->ovsNameLen = (UINT32)len;
    if (vport->portType == NdisSwitchPortTypeExternal &&
        vport->nicIndex == 0) {
        return NDIS_STATUS_SUCCESS;
    }
    hash = OvsJhashBytes(vport->ovsName, vport->ovsNameLen, OVS_HASH_BASIS);
    InsertHeadList(&switchContext->nameHashArray[hash & OVS_VPORT_MASK],
        &vport->nameLink);
    hash = OvsJhashWords(&vport->portId, 1, OVS_HASH_BASIS);
    InsertHeadList(&switchContext->portHashArray[hash & OVS_VPORT_MASK],
        &vport->portLink);
    switchContext->numVports++;
    return NDIS_STATUS_SUCCESS;
}


static VOID
OvsRemoveAndDeleteVport(POVS_SWITCH_CONTEXT switchContext,
                        POVS_VPORT_ENTRY vport)
{
    UINT64 gen = vport->portNo >> 24;
    switch (vport->ovsType) {
    case OVSWIN_VPORT_TYPE_EXTERNAL:
        if (vport->nicIndex == 0) {
            ASSERT(switchContext->numPhysicalNics == 0);
            switchContext->externalPortId = 0;
            switchContext->externalVport = NULL;
            OvsFreeMemory(vport);
            return;
        } else {
            ASSERT(switchContext->numPhysicalNics);
            switchContext->numPhysicalNics--;
        }
        break;
    case OVSWIN_VPORT_TYPE_INTERNAL:
        switchContext->internalPortId = 0;
        switchContext->internalVport = NULL;
        OvsInternalAdapterDown();
        break;
    case OVSWIN_VPORT_TYPE_VXLAN:
        OvsCleanupVxlanTunnel(vport);
        break;
    case OVSWIN_VPORT_TYPE_GRE:
    case OVSWIN_VPORT_TYPE_GRE64:
        break;
    case OVSWIN_VPORT_TYPE_EMULATED:
    case OVSWIN_VPORT_TYPE_SYNTHETIC:
    default:
        break;
    }

    RemoveEntryList(&vport->nameLink);
    RemoveEntryList(&vport->portLink);
    gen = (gen + 1) & 0xff;
    switchContext->vportArray[OVS_VPORT_INDEX(vport->portNo)] =
                     (PVOID)(UINT64)gen;
    switchContext->numVports--;
    OvsFreeMemory(vport);
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
         vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
         if (vport == NULL) {
             status = NDIS_STATUS_RESOURCES;
             goto cleanup;
         }
         OvsInitVportWithPortParam(vport, portParam);
         status = OvsInitVportCommon(switchContext, vport);
         if (status != NDIS_STATUS_SUCCESS) {
             OvsFreeMemory(vport);
             goto cleanup;
         }
    }
cleanup:
    if (status != NDIS_STATUS_SUCCESS) {
        OvsClearAllSwitchVports(switchContext);
    }

    if (portArray != NULL) {
        OvsFreeMemory(portArray);
    }
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
            POVS_VPORT_ENTRY virtVport =
                   (POVS_VPORT_ENTRY)switchContext->externalVport;
            vport = OvsAllocateVport();
            if (vport) {
                OvsInitPhysNicVport(vport, virtVport, nicParam->NicIndex);
                status = OvsInitVportCommon(switchContext, vport);
                if (status != NDIS_STATUS_SUCCESS) {
                    OvsFreeMemory(vport);
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

    if (nicArray != NULL) {
        OvsFreeMemory(nicArray);
    }
    OVS_LOG_TRACE("Exit: status: %x", status);
    return status;
}

VOID
OvsClearAllSwitchVports(POVS_SWITCH_CONTEXT switchContext)
{
    UINT32 i;

    for (i = 0; i < OVS_MAX_VPORT_ARRAY_SIZE; i++) {
        if (!OVS_IS_VPORT_ENTRY_NULL(switchContext, i)) {
            OvsRemoveAndDeleteVport(switchContext,
                       (POVS_VPORT_ENTRY)switchContext->vportArray[i]);
        }
    }
    if (switchContext->externalVport) {
        OvsRemoveAndDeleteVport(switchContext,
                        (POVS_VPORT_ENTRY)switchContext->externalVport);
    }
}

NTSTATUS
OvsDumpVportIoctl(PVOID inputBuffer,
                  UINT32 inputLength,
                  PVOID outputBuffer,
                  UINT32 outputLength,
                  UINT32 *replyLen)
{
    UINT32 numVports, count;
    UINT32 dpNo, i;
    UINT32 *outPtr;
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;

    if (inputLength < sizeof (UINT32)) {
        return STATUS_INVALID_PARAMETER;
    }
    dpNo = *(UINT32 *)inputBuffer;

    NdisAcquireSpinLock(gOvsCtrlLock);
    if (gOvsSwitchContext == NULL ||
        gOvsSwitchContext->dpNo != dpNo) {
        NdisReleaseSpinLock(gOvsCtrlLock);
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * We should hold SwitchContext RW lock
     */

    NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState,
                          NDIS_RWL_AT_DISPATCH_LEVEL);
    numVports = outputLength/sizeof (UINT32);
    numVports = MIN(gOvsSwitchContext->numVports, numVports);
    outPtr = (UINT32 *)outputBuffer;
    for (i = 0, count = 0;
         i < OVS_MAX_VPORT_ARRAY_SIZE && count < numVports; i++) {
        vport = (POVS_VPORT_ENTRY)gOvsSwitchContext->vportArray[i];
        if (OVS_IS_VPORT_ENTRY_NULL(gOvsSwitchContext, i)) {
            continue;
        }
        if (vport->ovsState == OVS_STATE_CONNECTED ||
            vport->ovsState == OVS_STATE_NIC_CREATED) {
            *outPtr = vport->portNo;
            outPtr++;
            count++;
        }
    }
    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
    NdisReleaseSpinLock(gOvsCtrlLock);
    *replyLen = count * sizeof (UINT32);
    return STATUS_SUCCESS;
}


NTSTATUS
OvsGetVportIoctl(PVOID inputBuffer,
                 UINT32 inputLength,
                 PVOID outputBuffer,
                 UINT32 outputLength,
                 UINT32 *replyLen)
{
    UINT32 dpNo;
    POVS_VPORT_GET get;
    POVS_VPORT_INFO info;
    POVS_VPORT_ENTRY vport;
    size_t len;
    LOCK_STATE_EX lockState;

    if (inputLength < sizeof (OVS_VPORT_GET) ||
        outputLength < sizeof (OVS_VPORT_INFO)) {
        return STATUS_INVALID_PARAMETER;
    }
    get = (POVS_VPORT_GET)inputBuffer;
    dpNo = get->dpNo;
    info = (POVS_VPORT_INFO)outputBuffer;
    RtlZeroMemory(info, sizeof (POVS_VPORT_INFO));

    NdisAcquireSpinLock(gOvsCtrlLock);
    if (gOvsSwitchContext == NULL ||
        gOvsSwitchContext->dpNo != dpNo) {
        NdisReleaseSpinLock(gOvsCtrlLock);
        return STATUS_INVALID_PARAMETER;
    }

    NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState,
                          NDIS_RWL_AT_DISPATCH_LEVEL);
    if (get->portNo == 0) {
        StringCbLengthA(get->name, OVS_MAX_PORT_NAME_LENGTH - 1, &len);
        vport = OvsFindVportByOvsName(gOvsSwitchContext, get->name, (UINT32)len);
    } else {
        vport = OvsFindVportByPortNo(gOvsSwitchContext, get->portNo);
    }
    if (vport == NULL || (vport->ovsState != OVS_STATE_CONNECTED &&
                          vport->ovsState != OVS_STATE_NIC_CREATED)) {
        NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
        NdisReleaseSpinLock(gOvsCtrlLock);
        /*
         * XXX Change to NO DEVICE
         */
        return STATUS_DEVICE_DOES_NOT_EXIST;
    }
    info->dpNo = dpNo;
    info->portNo = vport->portNo;
    info->type = vport->ovsType;
    RtlCopyMemory(info->macAddress, vport->permMacAddress,
                  sizeof (vport->permMacAddress));
    RtlCopyMemory(info->name, vport->ovsName, vport->ovsNameLen + 1);

    info->rxPackets = vport->stats.rxPackets;
    info->rxBytes = vport->stats.rxBytes;
    info->txPackets = vport->stats.txPackets;
    info->txBytes = vport->stats.txBytes;
    info->rxErrors = vport->errStats.rxErrors;
    info->txErrors = vport->errStats.txErrors;
    info->rxDropped = vport->errStats.rxDropped;
    info->txDropped = vport->errStats.txDropped;

    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
    NdisReleaseSpinLock(gOvsCtrlLock);
    *replyLen = sizeof (OVS_VPORT_INFO);
    return STATUS_SUCCESS;
}


NTSTATUS
OvsInitTunnelVport(POVS_VPORT_ENTRY vport,
                   POVS_VPORT_ADD_REQUEST addReq)
{
    size_t len;
    NTSTATUS status = STATUS_SUCCESS;

    vport->isValidationPort = FALSE;
    vport->ovsType = addReq->type;
    vport->ovsState = OVS_STATE_PORT_CREATED;
    RtlCopyMemory(vport->ovsName, addReq->name, OVS_MAX_PORT_NAME_LENGTH);
    vport->ovsName[OVS_MAX_PORT_NAME_LENGTH - 1] = 0;
    StringCbLengthA(vport->ovsName, OVS_MAX_PORT_NAME_LENGTH - 1, &len);
    vport->ovsNameLen = (UINT32)len;
    switch (addReq->type) {
    case OVSWIN_VPORT_TYPE_GRE:
        break;
    case OVSWIN_VPORT_TYPE_GRE64:
        break;
    case OVSWIN_VPORT_TYPE_VXLAN:
        status = OvsInitVxlanTunnel(vport, addReq);
        break;
    default:
        ASSERT(0);
    }
    return status;
}

NTSTATUS
OvsAddVportIoctl(PVOID inputBuffer,
                 UINT32 inputLength,
                 PVOID outputBuffer,
                 UINT32 outputLength,
                 UINT32 *replyLen)
{
    NTSTATUS status = STATUS_SUCCESS;
    POVS_VPORT_INFO vportInfo;
    POVS_VPORT_ADD_REQUEST addReq;
    POVS_VPORT_ENTRY vport;
    LOCK_STATE_EX lockState;
    UINT32 index;
    UINT32 portNo;

    OVS_LOG_TRACE("Enter: inputLength: %u, outputLength: %u",
                  inputLength, outputLength);
    if (inputLength < sizeof (OVS_VPORT_ADD_REQUEST) ||
        outputLength < sizeof (OVS_VPORT_INFO)) {
        status = STATUS_INVALID_PARAMETER;
        goto vport_add_done;
    }
    addReq = (POVS_VPORT_ADD_REQUEST)inputBuffer;
    addReq->name[OVS_MAX_PORT_NAME_LENGTH - 1] = 0;

    switch (addReq->type) {
    case OVSWIN_VPORT_TYPE_GRE:
        index = OVS_GRE_VPORT_INDEX;
        break;
    case OVSWIN_VPORT_TYPE_GRE64:
        index = OVS_GRE64_VPORT_INDEX;
        break;
    case OVSWIN_VPORT_TYPE_VXLAN:
        index = OVS_VXLAN_VPORT_INDEX;
        break;
    default:
        status = STATUS_NOT_SUPPORTED;
        goto vport_add_done;
    }

    vport = (POVS_VPORT_ENTRY)OvsAllocateVport();
    if (vport == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto vport_add_done;
    }

    NdisAcquireSpinLock(gOvsCtrlLock);
    if (gOvsSwitchContext == NULL ||
        gOvsSwitchContext->dpNo != addReq->dpNo) {
        NdisReleaseSpinLock(gOvsCtrlLock);
        status = STATUS_INVALID_PARAMETER;
        OvsFreeMemory(vport);
        goto vport_add_done;
    }
    NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState,
                          NDIS_RWL_AT_DISPATCH_LEVEL);
    if (!OVS_IS_VPORT_ENTRY_NULL(gOvsSwitchContext, index)) {
        status = STATUS_DEVICE_BUSY;
        NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
        NdisReleaseSpinLock(gOvsCtrlLock);
        OvsFreeMemory(vport);
        goto vport_add_done;
    }

    status = OvsInitTunnelVport(vport, addReq);
    if (status != STATUS_SUCCESS) {
        NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
        NdisReleaseSpinLock(gOvsCtrlLock);
        OvsFreeMemory(vport);
        goto vport_add_done;
    }

    status = OvsInitVportCommon(gOvsSwitchContext, vport);
    ASSERT(status == NDIS_STATUS_SUCCESS);

    vport->ovsState = OVS_STATE_CONNECTED;
    vport->nicState = NdisSwitchNicStateConnected;

    vportInfo = (POVS_VPORT_INFO)outputBuffer;

    RtlZeroMemory(vportInfo, sizeof (POVS_VPORT_INFO));
    vportInfo->dpNo = gOvsSwitchContext->dpNo;
    vportInfo->portNo = vport->portNo;
    vportInfo->type = vport->ovsType;
    RtlCopyMemory(vportInfo->name, vport->ovsName, vport->ovsNameLen + 1);
    portNo = vport->portNo;

    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
    NdisReleaseSpinLock(gOvsCtrlLock);
    OvsPostEvent(portNo, OVS_EVENT_CONNECT | OVS_EVENT_LINK_UP);
    *replyLen = sizeof (OVS_VPORT_INFO);
    status = STATUS_SUCCESS;
vport_add_done:
    OVS_LOG_TRACE("Exit: byteReturned: %u, status: %x",
                  *replyLen, status);
    return status;
}

NTSTATUS
OvsDelVportIoctl(PVOID inputBuffer,
                 UINT32 inputLength,
                 UINT32 *replyLen)
{
    NTSTATUS status = STATUS_SUCCESS;
    POVS_VPORT_DELETE_REQUEST delReq;
    LOCK_STATE_EX lockState;
    POVS_VPORT_ENTRY vport;
    size_t len;
    UINT32 portNo = 0;

    OVS_LOG_TRACE("Enter: inputLength: %u", inputLength);

    if (inputLength < sizeof (OVS_VPORT_DELETE_REQUEST)) {
        status = STATUS_INVALID_PARAMETER;
        goto vport_del_done;
    }
    delReq = (POVS_VPORT_DELETE_REQUEST)inputBuffer;

    NdisAcquireSpinLock(gOvsCtrlLock);
    if (gOvsSwitchContext == NULL ||
        gOvsSwitchContext->dpNo != delReq->dpNo) {
        NdisReleaseSpinLock(gOvsCtrlLock);
        status = STATUS_INVALID_PARAMETER;
        goto vport_del_done;
    }
    NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState,
                          NDIS_RWL_AT_DISPATCH_LEVEL);
    if (delReq->portNo == 0) {
        StringCbLengthA(delReq->name, OVS_MAX_PORT_NAME_LENGTH - 1, &len);
        vport = OvsFindVportByOvsName(gOvsSwitchContext, delReq->name,
                                      (UINT32)len);
    } else {
        vport = OvsFindVportByPortNo(gOvsSwitchContext, delReq->portNo);
    }
    if (vport) {
        OVS_LOG_INFO("delete vport: %s, portNo: %x", vport->ovsName,
                     vport->portNo);
        portNo = vport->portNo;
        OvsRemoveAndDeleteVport(gOvsSwitchContext, vport);
    } else {
        status = STATUS_DEVICE_DOES_NOT_EXIST;
    }
    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
    NdisReleaseSpinLock(gOvsCtrlLock);
    if (vport) {
        OvsPostEvent(portNo, OVS_EVENT_DISCONNECT | OVS_EVENT_LINK_DOWN);
    }
vport_del_done:
    OVS_LOG_TRACE("Exit: byteReturned: %u, status: %x",
                  *replyLen, status);
    return status;
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


NTSTATUS
OvsGetExtInfoIoctl(PVOID inputBuffer,
                     UINT32 inputLength,
                     PVOID outputBuffer,
                     UINT32 outputLength,
                     UINT32 *replyLen)
{
    POVS_VPORT_GET get;
    POVS_VPORT_EXT_INFO info;
    POVS_VPORT_ENTRY vport;
    size_t len;
    LOCK_STATE_EX lockState;
    NTSTATUS status = STATUS_SUCCESS;
    NDIS_SWITCH_NIC_NAME nicName;
    NDIS_VM_NAME vmName;
    BOOLEAN doConvert = FALSE;

    OVS_LOG_TRACE("Enter: inputLength: %u, outputLength: %u",
                  inputLength, outputLength);

    if (inputLength < sizeof (OVS_VPORT_GET) ||
        outputLength < sizeof (OVS_VPORT_EXT_INFO)) {
        status = STATUS_INVALID_PARAMETER;
        goto ext_info_done;
    }
    get = (POVS_VPORT_GET)inputBuffer;
    info = (POVS_VPORT_EXT_INFO)outputBuffer;
    RtlZeroMemory(info, sizeof (POVS_VPORT_EXT_INFO));

    NdisAcquireSpinLock(gOvsCtrlLock);
    if (gOvsSwitchContext == NULL ||
        gOvsSwitchContext->dpNo != get->dpNo) {
        NdisReleaseSpinLock(gOvsCtrlLock);
        status = STATUS_INVALID_PARAMETER;
        goto ext_info_done;
    }
    NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState,
                          NDIS_RWL_AT_DISPATCH_LEVEL);
    if (get->portNo == 0) {
        StringCbLengthA(get->name, OVS_MAX_PORT_NAME_LENGTH - 1, &len);
        vport = OvsFindVportByOvsName(gOvsSwitchContext, get->name,
                                      (UINT32)len);
    } else {
        vport = OvsFindVportByPortNo(gOvsSwitchContext, get->portNo);
    }
    if (vport == NULL || (vport->ovsState != OVS_STATE_CONNECTED &&
                          vport->ovsState != OVS_STATE_NIC_CREATED)) {
        NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
        NdisReleaseSpinLock(gOvsCtrlLock);
        if (get->portNo) {
            OVS_LOG_WARN("vport %u does not exist any more", get->portNo);
        } else {
            OVS_LOG_WARN("vport %s does not exist any more", get->name);
        }
        status = STATUS_DEVICE_DOES_NOT_EXIST;
        goto ext_info_done;
    }
    info->dpNo = get->dpNo;
    info->portNo = vport->portNo;
    RtlCopyMemory(info->macAddress, vport->currMacAddress,
                  sizeof (vport->currMacAddress));
    RtlCopyMemory(info->permMACAddress, vport->permMacAddress,
                  sizeof (vport->permMacAddress));
    if (vport->ovsType == OVSWIN_VPORT_TYPE_SYNTHETIC ||
        vport->ovsType == OVSWIN_VPORT_TYPE_EMULATED) {
        RtlCopyMemory(info->vmMACAddress, vport->vmMacAddress,
                      sizeof (vport->vmMacAddress));
    }
    info->nicIndex = vport->nicIndex;
    info->portId = vport->portId;
    info->type = vport->ovsType;
    info->mtu = vport->mtu;
    /*
     * TO be revisit XXX
     */
    if (vport->ovsState == OVS_STATE_NIC_CREATED) {
       info->status = OVS_EVENT_CONNECT | OVS_EVENT_LINK_DOWN;
    } else if (vport->ovsState == OVS_STATE_CONNECTED) {
       info->status = OVS_EVENT_CONNECT | OVS_EVENT_LINK_UP;
    } else {
       info->status = OVS_EVENT_DISCONNECT;
    }
    if ((info->type == OVSWIN_VPORT_TYPE_SYNTHETIC ||
         info->type == OVSWIN_VPORT_TYPE_EMULATED) &&
        (vport->ovsState == OVS_STATE_NIC_CREATED  ||
         vport->ovsState == OVS_STATE_CONNECTED)) {
        RtlCopyMemory(&vmName, &vport->vmName, sizeof (NDIS_VM_NAME));
        RtlCopyMemory(&nicName, &vport->nicName, sizeof
                      (NDIS_SWITCH_NIC_NAME));
        doConvert = TRUE;
    } else {
        info->vmUUID[0] = 0;
        info->vifUUID[0] = 0;
    }

    RtlCopyMemory(info->name, vport->ovsName, vport->ovsNameLen + 1);
    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
    NdisReleaseSpinLock(gOvsCtrlLock);
    if (doConvert) {
        status = OvsConvertIfCountedStrToAnsiStr(&vmName,
                                                 info->vmUUID,
                                                 OVS_MAX_VM_UUID_LEN);
        if (status != STATUS_SUCCESS) {
            OVS_LOG_INFO("Fail to convert VM name.");
            info->vmUUID[0] = 0;
        }

        status = OvsConvertIfCountedStrToAnsiStr(&nicName,
                                                 info->vifUUID,
                                                 OVS_MAX_VIF_UUID_LEN);
        if (status != STATUS_SUCCESS) {
            OVS_LOG_INFO("Fail to convert nic name");
            info->vifUUID[0] = 0;
        }
        /*
         * for now ignore status
         */
        status = STATUS_SUCCESS;
    }
    *replyLen = sizeof (OVS_VPORT_EXT_INFO);

ext_info_done:
    OVS_LOG_TRACE("Exit: byteReturned: %u, status: %x",
                  *replyLen, status);
    return status;
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
