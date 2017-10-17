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
 * This file contains the definition of the switch object for the OVS.
 */

#ifndef __SWITCH_H_
#define __SWITCH_H_ 1

#include "NetProto.h"
#include "BufferMgmt.h"
#include "TunnelIntf.h"
#define OVS_MAX_VPORT_ARRAY_SIZE 1024
#define OVS_MAX_PID_ARRAY_SIZE   1024

#define OVS_VPORT_MASK (OVS_MAX_VPORT_ARRAY_SIZE - 1)
#define OVS_PID_MASK (OVS_MAX_PID_ARRAY_SIZE - 1)

#define OVS_INTERNAL_VPORT_DEFAULT_INDEX 0

//Tunnel port indicies
#define RESERVED_START_INDEX1    1
#define OVS_TUNNEL_INDEX_START RESERVED_START_INDEX1
#define OVS_VXLAN_VPORT_INDEX    2
#define OVS_GRE_VPORT_INDEX      3
#define OVS_TUNNEL_INDEX_END OVS_GRE_VPORT_INDEX

#define OVS_MAX_PHYS_ADAPTERS    32
#define OVS_MAX_IP_VPOR          32

#define OVS_HASH_BASIS   0x13578642

typedef struct _OVS_VPORT_ENTRY *POVS_VPORT_ENTRY;

typedef struct _OVS_DATAPATH
{
   PLIST_ENTRY             flowTable;       // Contains OvsFlows.
   UINT32                  nFlows;          // Number of entries in flowTable.

   // List_Links              queues[64];      // Hash table of queue IDs.

   /* Statistics. */
   UINT64                  hits;            // Number of flow table hits.
   UINT64                  misses;          // Number of flow table misses.
   UINT64                  lost;            // Number of dropped misses.

   /* Used to protect the flows in the flowtable. */
   PNDIS_RW_LOCK_EX        lock;
} OVS_DATAPATH, *POVS_DATAPATH;

/*
 * OVS_SWITCH_CONTEXT
 *
 * The context allocated per switch., For OVS, we only
 * support one switch which corresponding to one datapath.
 * Each datapath can have multiple logical bridges configured
 * which is maintained by vswitchd.
 */

typedef enum OVS_SWITCH_DATAFLOW_STATE
{
    OvsSwitchPaused,
    OvsSwitchRunning
} OVS_SWITCH_DATAFLOW_STATE, *POVS_SWITCH_DATAFLOW_STATE;

typedef enum OVS_SWITCH_CONTROFLOW_STATE
{
    OvsSwitchUnknown,
    OvsSwitchAttached,
    OvsSwitchDetached
} OVS_SWITCH_CONTROLFLOW_STATE, *POVS_SWITCH_CONTROLFLOW_STATE;

// XXX: Take care of alignment and grouping members by cacheline
typedef struct _OVS_SWITCH_CONTEXT
{
    /* Coarse and fine-grained switch states. */
    OVS_SWITCH_DATAFLOW_STATE dataFlowState;
    OVS_SWITCH_CONTROLFLOW_STATE controlFlowState;
    BOOLEAN                 isActivated;
    BOOLEAN                 isActivateFailed;

    UINT32                  dpNo;

    /*
     * 'virtualExternalVport' represents default external interface. This is
     * a virtual interface. The friendly name of such an interface has
     * been observed to be: "Microsoft Default External Interface". This NIC
     * has 'NicIndex' == 0.
     *
     * The "real" physical external NIC has 'NicIndex' > 0. For each
     * external interface, virtual or physical, NDIS gives an NIC level
     * OID callback. Note that, even though there are multiple "NICs",
     * there's only one underlying Hyper-V port. Thus, we get a single
     * NDIS port-level callback, but multiple NDIS NIC-level callbacks.
     *
     * The virtual external NIC can be accessed at 'virtualExternalVport', and
     * is assigned the name "external.defaultAdapter". The virtual external
     * NIC is not inserted into the 'portIdHashArray' since the port must not
     * be exposed to OVS userspace.
     *
     * The physical external NICs are assigned names "external.%INDEX%",
     * where '%INDEX%' represents the 'NicIndex' of the NIC.
     *
     * While adding a physical external NIC in OvsInitConfiguredSwitchNics(),
     * some required properties of the vport are available only at the
     * NDIS port-level. So, these are copied from 'virtualExternalVport'.
     * The vport created for the physical external NIC is inserted into the
     * 'portIdHashArray'.
     *
     * When the virtual external NIC is torn down or deleted, the
     * corresponding physical external ports are also torn down or
     * deleted. The number of physical external NICs is tracked by
     * 'numPhysicalNics'.
     */
    NDIS_SWITCH_PORT_ID     virtualExternalPortId;
    POVS_VPORT_ENTRY        virtualExternalVport;   /* the virtual adapter
                                                     * vport */
    INT32                   countInternalVports;    /* the number of internal
                                                     * vports */

    /*
     * 'portIdHashArray' ONLY contains ports that exist on the Hyper-V switch,
     * namely: VIF (vNIC) ports, external port and Hyper-V internal port.
     * 'numHvVports' counts the ports in 'portIdHashArray'. If a port got
     * deleted on the Hyper-V switch, it gets deleted from 'portIdHashArray'.
     * The port itself will not get deallocated if it has been added from OVS
     * userspace. 'numHvVports' is decremented when the port is deallocated.
     *
     * 'portNoHashArray' ONLY contains ports that are added from OVS userspace,
     * regardless of whether that port exists on the Hyper-V switch or not.
     * Tunnel ports and bridge-internal ports are examples of ports that do not
     * exist on the Hyper-V switch, and 'numNonHvVports' counts such ports in
     * 'portNoHashArray'.
     *
     * 'tunnelVportsArray' contains tunnel ports that are added from OVS
     * userspace. Currently only VXLAN tunnels are added in this list.
     *
     * 'ovsPortNameHashArray' contains the same entries as 'portNoHashArray' but
     * hashed on a different key.
     */
    PLIST_ENTRY             portIdHashArray;        // based on Hyper-V portId
    PLIST_ENTRY             portNoHashArray;        // based on ovs port number
    PLIST_ENTRY             tunnelVportsArray;      // based on ovs dst port number
    PLIST_ENTRY             ovsPortNameHashArray;   // based on ovsName
    PLIST_ENTRY             pidHashArray;           // based on packet pids
    NDIS_SPIN_LOCK          pidHashLock;            // Lock for pidHash table

    UINT32                  numPhysicalNics;        // the number of physical
                                                    // external NICs.
    UINT32                  numHvVports;
    UINT32                  numNonHvVports;

    /* Lock taken over the switch. This protects the ports on the switch. */
    PNDIS_RW_LOCK_EX        dispatchLock;

    /* The flowtable. */
    OVS_DATAPATH            datapath;

    /* Handle to the OVSExt filter driver. Same as 'gOvsExtDriverHandle'. */
    NDIS_HANDLE NdisFilterHandle;

    /* Handle and callbacks exposed by the underlying hyper-v switch. */
    NDIS_SWITCH_CONTEXT NdisSwitchContext;
    NDIS_SWITCH_OPTIONAL_HANDLERS NdisSwitchHandlers;

    volatile LONG pendingInjectedNblCount;
    volatile LONG pendingOidCount;

    OVS_NBL_POOL            ovsPool;
} OVS_SWITCH_CONTEXT, *POVS_SWITCH_CONTEXT;


_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_saves_global_(OldIrql, lockState)
_Acquires_lock_(datapath->lock)
static __inline VOID
OvsAcquireDatapathRead(OVS_DATAPATH *datapath,
                       LOCK_STATE_EX *lockState,
                       BOOLEAN dispatch)
{
    ASSERT(datapath);
    NdisAcquireRWLockRead(datapath->lock, lockState,
                          dispatch ? NDIS_RWL_AT_DISPATCH_LEVEL : 0);
}

_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_saves_global_(OldIrql, lockState)
_Acquires_lock_(datapath->lock)
static __inline VOID
OvsAcquireDatapathWrite(OVS_DATAPATH *datapath,
                        LOCK_STATE_EX *lockState,
                        BOOLEAN dispatch)
{
    ASSERT(datapath);
    NdisAcquireRWLockWrite(datapath->lock, lockState,
                           dispatch ? NDIS_RWL_AT_DISPATCH_LEVEL : 0);
}

_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_restores_global_(OldIrql, lockState)
_Requires_lock_held_(datapath->lock)
_Releases_lock_(datapath->lock)
static __inline VOID
OvsReleaseDatapath(OVS_DATAPATH *datapath,
                   LOCK_STATE_EX *lockState)
{
    ASSERT(datapath);
    NdisReleaseRWLock(datapath->lock, lockState);
}

BOOLEAN
OvsAcquireSwitchContext(VOID);

VOID
OvsReleaseSwitchContext(POVS_SWITCH_CONTEXT switchContext);

#endif /* __SWITCH_H_ */
