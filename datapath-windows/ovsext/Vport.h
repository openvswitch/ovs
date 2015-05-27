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

#ifndef __VPORT_H_
#define __VPORT_H_ 1

#include "Switch.h"

#define OVS_MAX_DPPORTS             MAXUINT16
#define OVS_DPPORT_NUMBER_INVALID   OVS_MAX_DPPORTS
/*
 * The local port (0) is a reserved port, that is not allowed to be be
 * created by the netlink command vport add. On linux, this port is created
 * at netlink command datapath new. However, on windows, we do not need to
 * create it, and more, we shouldn't. The userspace attempts to create two
 * internal vports, the LOCAL port (0) and the internal port (with any other
 * port number). The non-LOCAL internal port is used in the userspace when it
 * requests the internal port.
 */
#define OVS_DPPORT_NUMBER_LOCAL    0

#define OVS_DPPORT_INTERNAL_NAME_A  "internal"
#define OVS_DPPORT_INTERNAL_NAME_W  L"internal"
#define OVS_DPPORT_EXTERNAL_NAME_A   "external"
#define OVS_DPPORT_EXTERNAL_NAME_W  L"external"

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
    UINT64 rxPackets;
    UINT64 txPackets;
    UINT64 rxBytes;
    UINT64 txBytes;
} OVS_VPORT_STATS;

typedef struct _OVS_VPORT_ERR_STATS {
    UINT64  rxErrors;
    UINT64  txErrors;
    UINT64  rxDropped;
    UINT64  txDropped;
} OVS_VPORT_ERR_STATS;

/* used for vport netlink commands. */
typedef struct _OVS_VPORT_FULL_STATS {
    OVS_VPORT_STATS;
    OVS_VPORT_ERR_STATS;
}OVS_VPORT_FULL_STATS;
/*
 * Each internal, external adapter or vritual adapter has
 * one vport entry. In addition, we have one vport for each
 * tunnel type, such as vxlan, gre, gre64
 */
typedef struct _OVS_VPORT_ENTRY {
    LIST_ENTRY             ovsNameLink;
    LIST_ENTRY             portIdLink;
    LIST_ENTRY             portNoLink;
    LIST_ENTRY             tunnelVportLink;

    OVS_VPORT_STATE        ovsState;
    OVS_VPORT_TYPE         ovsType;
    OVS_VPORT_STATS        stats;
    OVS_VPORT_ERR_STATS    errStats;
    UINT32                 portNo;
    UINT32                 mtu;
    /* ovsName is the ovs (datapath) port name - it is null terminated. */
    CHAR                   ovsName[OVS_MAX_PORT_NAME_LENGTH];

    PVOID                  priv;
    NDIS_SWITCH_PORT_ID    portId;
    NDIS_SWITCH_NIC_INDEX  nicIndex;
    UINT16                 numaNodeId;
    NDIS_SWITCH_PORT_STATE portState;
    NDIS_SWITCH_NIC_STATE  nicState;
    NDIS_SWITCH_PORT_TYPE  portType;

    UINT8                  permMacAddress[ETH_ADDR_LEN];
    UINT8                  currMacAddress[ETH_ADDR_LEN];
    UINT8                  vmMacAddress[ETH_ADDR_LEN];

    NDIS_SWITCH_PORT_NAME  hvPortName;
    IF_COUNTED_STRING      portFriendlyName;
    NDIS_SWITCH_NIC_NAME   nicName;
    NDIS_VM_NAME           vmName;
    GUID                   netCfgInstanceId;
    /*
     * OVS userpace has a notion of bridges which basically defines an
     * L2-domain. Each "bridge" has an "internal" port of type
     * OVS_VPORT_TYPE_INTERNAL. Such a port is connected to the OVS datapath in
     * one end, and the other end is a virtual adapter on the hypervisor host.
     * This is akin to the Hyper-V "internal" NIC. It is intuitive to map the
     * Hyper-V "internal" NIC to the OVS bridge's "internal" port, but there's
     * only one Hyper-V NIC but multiple bridges. To support multiple OVS bridge
     * "internal" ports, we use the flag 'isBridgeInternal' in each vport. We
     * support addition of multiple bridge-internal ports. A vport with
     * 'isBridgeInternal' == TRUE is a dummy port and has no backing currently.
     * If a flow actions specifies the output port to be a bridge-internal port,
     * the port is silently ignored.
     */
    BOOLEAN                isBridgeInternal;
    BOOLEAN                isExternal;
    UINT32                 upcallPid; /* netlink upcall port id */
    PNL_ATTR               portOptions;
    BOOLEAN                isPresentOnHv; /* Is this port present on the
                                             Hyper-V switch? */
} OVS_VPORT_ENTRY, *POVS_VPORT_ENTRY;

struct _OVS_SWITCH_CONTEXT;

POVS_VPORT_ENTRY OvsFindVportByPortNo(POVS_SWITCH_CONTEXT switchContext,
                                      UINT32 portNo);
/* "name" is null-terminated */
POVS_VPORT_ENTRY OvsFindVportByOvsName(POVS_SWITCH_CONTEXT switchContext,
                                       PSTR name);
POVS_VPORT_ENTRY OvsFindVportByHvNameA(POVS_SWITCH_CONTEXT switchContext,
                                       PSTR name);
POVS_VPORT_ENTRY OvsFindVportByPortIdAndNicIndex(POVS_SWITCH_CONTEXT switchContext,
                                                 NDIS_SWITCH_PORT_ID portId,
                                                 NDIS_SWITCH_NIC_INDEX index);
POVS_VPORT_ENTRY OvsFindTunnelVportByDstPort(POVS_SWITCH_CONTEXT switchContext,
                                             UINT16 dstPort);

NDIS_STATUS OvsAddConfiguredSwitchPorts(struct _OVS_SWITCH_CONTEXT *switchContext);
NDIS_STATUS OvsInitConfiguredSwitchNics(struct _OVS_SWITCH_CONTEXT *switchContext);

VOID OvsClearAllSwitchVports(struct _OVS_SWITCH_CONTEXT *switchContext);

NDIS_STATUS HvCreateNic(POVS_SWITCH_CONTEXT switchContext,
                        PNDIS_SWITCH_NIC_PARAMETERS nicParam);
NDIS_STATUS HvCreatePort(POVS_SWITCH_CONTEXT switchContext,
                         PNDIS_SWITCH_PORT_PARAMETERS portParam);
NDIS_STATUS HvUpdatePort(POVS_SWITCH_CONTEXT switchContext,
                         PNDIS_SWITCH_PORT_PARAMETERS portParam);
VOID HvTeardownPort(POVS_SWITCH_CONTEXT switchContext,
                    PNDIS_SWITCH_PORT_PARAMETERS portParam);
VOID HvDeletePort(POVS_SWITCH_CONTEXT switchContext,
                  PNDIS_SWITCH_PORT_PARAMETERS portParam);
VOID HvConnectNic(POVS_SWITCH_CONTEXT switchContext,
                  PNDIS_SWITCH_NIC_PARAMETERS nicParam);
VOID HvUpdateNic(POVS_SWITCH_CONTEXT switchContext,
                 PNDIS_SWITCH_NIC_PARAMETERS nicParam);
VOID HvDeleteNic(POVS_SWITCH_CONTEXT switchContext,
                 PNDIS_SWITCH_NIC_PARAMETERS nicParam);
VOID HvDisconnectNic(POVS_SWITCH_CONTEXT switchContext,
                     PNDIS_SWITCH_NIC_PARAMETERS nicParam);

static __inline BOOLEAN
OvsIsTunnelVportType(OVS_VPORT_TYPE ovsType)
{
    return ovsType == OVS_VPORT_TYPE_VXLAN ||
           ovsType == OVS_VPORT_TYPE_GRE ||
           ovsType == OVS_VPORT_TYPE_GRE64;
}

static __inline BOOLEAN
OvsIsInternalVportType(OVS_VPORT_TYPE ovsType)
{
    return ovsType == OVS_VPORT_TYPE_INTERNAL;
}

static __inline BOOLEAN
OvsIsBridgeInternalVport(POVS_VPORT_ENTRY vport)
{
    if (vport->isBridgeInternal) {
       ASSERT(vport->ovsType == OVS_VPORT_TYPE_INTERNAL);
    }
    return vport->isBridgeInternal == TRUE;
}

NTSTATUS OvsRemoveAndDeleteVport(PVOID usrParamsCtx,
                                 POVS_SWITCH_CONTEXT switchContext,
                                 POVS_VPORT_ENTRY vport,
                                 BOOLEAN hvDelete, BOOLEAN ovsDelete);

NDIS_STATUS InitOvsVportCommon(POVS_SWITCH_CONTEXT switchContext,
                               POVS_VPORT_ENTRY vport);
NTSTATUS OvsInitTunnelVport(PVOID usrParamsCtx, POVS_VPORT_ENTRY vport,
                            OVS_VPORT_TYPE ovsType, UINT16 dstport);
NTSTATUS OvsInitBridgeInternalVport(POVS_VPORT_ENTRY vport);

POVS_VPORT_ENTRY OvsAllocateVport(VOID);

#endif /* __VPORT_H_ */
