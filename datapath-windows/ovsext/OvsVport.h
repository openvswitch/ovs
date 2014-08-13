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

#ifndef __OVS_VPORT_H_
#define __OVS_VPORT_H_ 1

#include "OvsSwitch.h"

/*
 * A Vport, or Virtual Port, is a port on the OVS. It can be one of the
 * following types. Some of the Vports are "real" ports on the hyper-v switch,
 * and some are not:
 * - VIF port (VM's NIC)
 * - External Adapters (physical NIC)
 * - Internal Adapter (Virtual adapter exposed on the host).
 * - Tunnel ports created by OVS userspace.
 */

typedef enum {
    OVS_STATE_UNKNOWN,
    OVS_STATE_PORT_CREATED,
    OVS_STATE_NIC_CREATED,
    OVS_STATE_CONNECTED,
    OVS_STATE_PORT_TEAR_DOWN,
    OVS_STATE_PORT_DELETED,
} OVS_VPORT_STATE;

typedef struct _OVS_VPORT_STATS {
    UINT64 rxBytes;
    UINT64 rxPackets;
    UINT64 txBytes;
    UINT64 txPackets;
} OVS_VPORT_STATS;

typedef struct _OVS_VPORT_ERR_STATS {
    UINT64  rxErrors;
    UINT64  txErrors;
    UINT64  rxDropped;
    UINT64  txDropped;
} OVS_VPORT_ERR_STATS;
/*
 * Each internal, external adapter or vritual adapter has
 * one vport entry. In addition, we have one vport for each
 * tunnel type, such as vxlan, gre, gre64
 */
typedef struct _OVS_VPORT_ENTRY {
    LIST_ENTRY             nameLink;
    LIST_ENTRY             portLink;

    OVS_VPORT_STATE        ovsState;
    OVS_VPORT_TYPE         ovsType;
    OVS_VPORT_STATS        stats;
    OVS_VPORT_ERR_STATS    errStats;
    UINT32                 portNo;
    UINT32                 mtu;
    CHAR                   ovsName[OVS_MAX_PORT_NAME_LENGTH];
    UINT32                 ovsNameLen;

    PVOID                  priv;
    NDIS_SWITCH_PORT_ID    portId;
    NDIS_SWITCH_NIC_INDEX  nicIndex;
    UINT16                 numaNodeId;
    NDIS_SWITCH_PORT_STATE portState;
    NDIS_SWITCH_NIC_STATE  nicState;
    NDIS_SWITCH_PORT_TYPE  portType;
    BOOLEAN                isValidationPort;

    UINT8                  permMacAddress[MAC_ADDRESS_LEN];
    UINT8                  currMacAddress[MAC_ADDRESS_LEN];
    UINT8                  vmMacAddress[MAC_ADDRESS_LEN];

    NDIS_SWITCH_PORT_NAME  portName;
    NDIS_SWITCH_NIC_NAME   nicName;
    NDIS_VM_NAME           vmName;
    GUID                   netCfgInstanceId;
} OVS_VPORT_ENTRY, *POVS_VPORT_ENTRY;

struct _OVS_SWITCH_CONTEXT;

#define OVS_IS_VPORT_ENTRY_NULL(_SwitchContext, _i) \
   ((UINT64)(_SwitchContext)->vportArray[_i] <= 0xff)

POVS_VPORT_ENTRY
OvsFindVportByPortNo(struct _OVS_SWITCH_CONTEXT *switchContext,
                     UINT32 portNo);
POVS_VPORT_ENTRY
OvsFindVportByOvsName(struct _OVS_SWITCH_CONTEXT *switchContext,
                      CHAR *name, UINT32 length);
POVS_VPORT_ENTRY
OvsFindVportByPortIdAndNicIndex(struct _OVS_SWITCH_CONTEXT *switchContext,
                                NDIS_SWITCH_PORT_ID portId,
                                NDIS_SWITCH_NIC_INDEX index);

NDIS_STATUS OvsAddConfiguredSwitchPorts(struct _OVS_SWITCH_CONTEXT *switchContext);
NDIS_STATUS OvsInitConfiguredSwitchNics(struct _OVS_SWITCH_CONTEXT *switchContext);

VOID OvsClearAllSwitchVports(struct _OVS_SWITCH_CONTEXT *switchContext);

NTSTATUS OvsDumpVportIoctl(PVOID inputBuffer, UINT32 inputLength,
                           PVOID outputBuffer, UINT32 outputLength,
                           UINT32 *replyLen);
NTSTATUS OvsGetVportIoctl(PVOID inputBuffer, UINT32 inputLength,
                          PVOID outputBuffer, UINT32 outputLength,
                          UINT32 *replyLen);
NTSTATUS OvsAddVportIoctl(PVOID inputBuffer, UINT32 inputLength,
                          PVOID outputBuffer, UINT32 outputLength,
                          UINT32 *replyLen);
NTSTATUS OvsDelVportIoctl(PVOID inputBuffer, UINT32 inputLength,
                          UINT32 *replyLen);
NTSTATUS OvsGetExtInfoIoctl(PVOID inputBuffer, UINT32 inputLength,
                            PVOID outputBuffer, UINT32 outputLength,
                            UINT32 *replyLen);
NDIS_STATUS OvsCreateNic(POVS_SWITCH_CONTEXT switchContext,
                         PNDIS_SWITCH_NIC_PARAMETERS nicParam);
NDIS_STATUS OvsCreatePort(POVS_SWITCH_CONTEXT switchContext,
                          PNDIS_SWITCH_PORT_PARAMETERS portParam);
VOID OvsTeardownPort(POVS_SWITCH_CONTEXT switchContext,
                     PNDIS_SWITCH_PORT_PARAMETERS portParam);
VOID OvsDeletePort(POVS_SWITCH_CONTEXT switchContext,
                   PNDIS_SWITCH_PORT_PARAMETERS portParam);
VOID OvsConnectNic(POVS_SWITCH_CONTEXT switchContext,
                   PNDIS_SWITCH_NIC_PARAMETERS nicParam);
VOID OvsUpdateNic(POVS_SWITCH_CONTEXT switchContext,
                  PNDIS_SWITCH_NIC_PARAMETERS nicParam);
VOID OvsDeleteNic(POVS_SWITCH_CONTEXT switchContext,
                  PNDIS_SWITCH_NIC_PARAMETERS nicParam);
VOID OvsDisconnectNic(POVS_SWITCH_CONTEXT switchContext,
                      PNDIS_SWITCH_NIC_PARAMETERS nicParam);

static __inline BOOLEAN
OvsIsTunnelVportType(OVS_VPORT_TYPE ovsType)
{
    return ovsType == OVSWIN_VPORT_TYPE_VXLAN ||
           ovsType == OVSWIN_VPORT_TYPE_GRE ||
           ovsType == OVSWIN_VPORT_TYPE_GRE64;
}

static __inline BOOLEAN
OvsIsInternalVportType(OVS_VPORT_TYPE ovsType)
{
    return ovsType == OVSWIN_VPORT_TYPE_INTERNAL;
}

static __inline BOOLEAN
OvsIsTunnelVportNo(UINT32 portNo)
{
    UINT32 idx = OVS_VPORT_INDEX(portNo);
    return (idx >= OVS_TUNNEL_INDEX_START && idx <= OVS_TUNNEL_INDEX_END);
}

static __inline BOOLEAN
OvsIsVifVportNo(UINT32 portNo)
{
    UINT32 idx = OVS_VPORT_INDEX(portNo);
    return (idx >= OVS_VM_VPORT_START && idx <= OVS_VM_VPORT_MAX);
}

static __inline POVS_VPORT_ENTRY
OvsGetTunnelVport(OVS_VPORT_TYPE type)
{
    ASSERT(OvsIsTunnelVportType(type));
    switch(type) {
    case OVSWIN_VPORT_TYPE_VXLAN:
        return (POVS_VPORT_ENTRY) OvsGetVportFromIndex(OVS_VXLAN_VPORT_INDEX);
    default:
        ASSERT(! "OvsGetTunnelVport not implemented for this tunnel.");
    }

    return NULL;
}

static __inline PVOID
OvsGetVportPriv(OVS_VPORT_TYPE type)
{
    return OvsGetTunnelVport(type)->priv;
}

static __inline UINT32
OvsGetExternalMtu()
{
    return ((POVS_VPORT_ENTRY) OvsGetExternalVport())->mtu;
}

#endif /* __OVS_VPORT_H_ */
