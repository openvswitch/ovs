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
#include "IpHelper.h"
#include "Switch.h"
#include "Jhash.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_IPHELPER
#include "Debug.h"

/*
 * Fow now, we assume only one internal adapter
 */

KSTART_ROUTINE             OvsStartIpHelper;


/*
 * Only when the internal IP is configured and virtual
 * internal port is connected, the IP helper request can be
 * queued.
 */
static BOOLEAN             ovsInternalIPConfigured;
static UINT32              ovsInternalPortNo;
static GUID                ovsInternalNetCfgId;
static MIB_IF_ROW2         ovsInternalRow;
static MIB_IPINTERFACE_ROW ovsInternalIPRow;

/* we only keep one internal IP for reference, it will not be used for
 * determining SRC IP of Tunnel
 */
static UINT32               ovsInternalIP;


/*
 * FWD_ENTRY -------->  IPFORWARD_ENTRY
 *      |
 *      |--------------------------------------> IPENIGH_ENTRY
 *
 * IPFORWARD_ENTRY  ------> FWD_ENTRY LIST with same IPFORWARD
 *
 * IPNEIGH_ENTRY    ------> FWD_ENTRY LIST with same IPNEIGH
 *
 */

static PLIST_ENTRY          ovsFwdHashTable;    // based on DST IP
static PLIST_ENTRY          ovsRouteHashTable;  // based on DST PREFIX
static PLIST_ENTRY          ovsNeighHashTable;  // based on DST IP
static LIST_ENTRY           ovsSortedIPNeighList;
static UINT32               ovsNumFwdEntries;


static PNDIS_RW_LOCK_EX     ovsTableLock;
static NDIS_SPIN_LOCK       ovsIpHelperLock;

static LIST_ENTRY           ovsIpHelperRequestList;
static UINT32               ovsNumIpHelperRequests;

static HANDLE               ipInterfaceNotificationHandle;
static HANDLE               ipRouteNotificationHandle;
static HANDLE               unicastIPNotificationHandle;

static OVS_IP_HELPER_THREAD_CONTEXT ovsIpHelperThreadContext;

static POVS_IPFORWARD_ENTRY OvsLookupIPForwardEntry(PIP_ADDRESS_PREFIX prefix);
static VOID OvsRemoveIPForwardEntry(POVS_IPFORWARD_ENTRY ipf);
static VOID OvsRemoveAllFwdEntriesWithSrc(UINT32 ipAddr);
static VOID OvsCleanupIpHelperRequestList(VOID);
static VOID OvsCleanupFwdTable(VOID);
static VOID OvsAddToSortedNeighList(POVS_IPNEIGH_ENTRY ipn);

static VOID
OvsDumpIfRow(PMIB_IF_ROW2 ifRow)
{
    OVS_LOG_INFO("InterfaceLuid: NetLuidIndex: %d, type: %d",
                 ifRow->InterfaceLuid.Info.NetLuidIndex,
                 ifRow->InterfaceLuid.Info.IfType);
    OVS_LOG_INFO("InterfaceIndex: %d", ifRow->InterfaceIndex);

    OVS_LOG_INFO("Interface GUID: %08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
                 ifRow->InterfaceGuid.Data1,
                 ifRow->InterfaceGuid.Data2,
                 ifRow->InterfaceGuid.Data3,
                 *(UINT16 *)ifRow->InterfaceGuid.Data4,
                 ifRow->InterfaceGuid.Data4[2],
                 ifRow->InterfaceGuid.Data4[3],
                 ifRow->InterfaceGuid.Data4[4],
                 ifRow->InterfaceGuid.Data4[5],
                 ifRow->InterfaceGuid.Data4[6],
                 ifRow->InterfaceGuid.Data4[7]);
    OVS_LOG_INFO("Perm MAC Address: %02x:%02x:%02x:%02x:%02x:%02x",
                 ifRow->PermanentPhysicalAddress[0],
                 ifRow->PermanentPhysicalAddress[1],
                 ifRow->PermanentPhysicalAddress[2],
                 ifRow->PermanentPhysicalAddress[3],
                 ifRow->PermanentPhysicalAddress[4],
                 ifRow->PermanentPhysicalAddress[5]);
}


static VOID
OvsDumpIfTable(PMIB_IF_TABLE2 ifTable)
{
    PMIB_IF_ROW2 ifRow;
    UINT32 i;

    OVS_LOG_INFO("======Number of entries: %d========", ifTable->NumEntries);

    for (i = 0; i < ifTable->NumEntries; i++) {
        ifRow = &ifTable->Table[i];
        OvsDumpIfRow(ifRow);
    }
}


NTSTATUS
OvsGetIfEntry(GUID *interfaceGuid, PMIB_IF_ROW2 ifEntry)
{
    NTSTATUS status;
    PMIB_IF_TABLE2 ifTable;
    UINT32 i;

    if (interfaceGuid == NULL || ifEntry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = GetIfTable2Ex(MibIfTableNormal, &ifTable);

    if (status != STATUS_SUCCESS) {
        OVS_LOG_INFO("Fail to get if table, status: %x", status);
        return status;
    }
    status = STATUS_NOT_FOUND;

    for (i = 0; i < ifTable->NumEntries; i++) {
        PMIB_IF_ROW2 ifRow;

        ifRow = &ifTable->Table[i];
        if (!memcmp(interfaceGuid, &ifRow->InterfaceGuid, sizeof (GUID))) {
            RtlCopyMemory(ifEntry, ifRow, sizeof (MIB_IF_ROW2));
            status = STATUS_SUCCESS;
            OvsDumpIfRow(ifEntry);
            break;
        }
    }

    FreeMibTable(ifTable);
    return status;
}


static VOID
OvsDumpIPInterfaceEntry(PMIB_IPINTERFACE_ROW ipRow)
{
    OVS_LOG_INFO("InterfaceLuid: NetLuidIndex: %d, type: %d",
                 ipRow->InterfaceLuid.Info.NetLuidIndex,
                 ipRow->InterfaceLuid.Info.IfType);
    OVS_LOG_INFO("InterfaceIndex: %d", ipRow->InterfaceIndex);

    OVS_LOG_INFO("MaxReassembleSize: %u", ipRow->MaxReassemblySize);
}


NTSTATUS
OvsGetIPInterfaceEntry(NET_LUID luid,
                       PMIB_IPINTERFACE_ROW ipRow)
{
    NTSTATUS status;

    if (ipRow == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ipRow->Family = AF_INET;
    ipRow->InterfaceLuid.Value = luid.Value;

    status = GetIpInterfaceEntry(ipRow);

    if (status != STATUS_SUCCESS) {
        OVS_LOG_INFO("Fail to get internal IP Interface mib row, status: %x",
                     status);
        return status;
    }
    OvsDumpIPInterfaceEntry(ipRow);
    return status;
}


static VOID
OvsDumpIPEntry(PMIB_UNICASTIPADDRESS_ROW ipRow)
{
    UINT32 ipAddr;

    OVS_LOG_INFO("InterfaceLuid: NetLuidIndex: %d, type: %d",
                 ipRow->InterfaceLuid.Info.NetLuidIndex,
                 ipRow->InterfaceLuid.Info.IfType);

    OVS_LOG_INFO("InterfaceIndex: %d", ipRow->InterfaceIndex);

    ASSERT(ipRow->Address.si_family == AF_INET);

    ipAddr = ipRow->Address.Ipv4.sin_addr.s_addr;
    OVS_LOG_INFO("Unicast Address: %d.%d.%d.%d\n",
                 ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                 (ipAddr >> 16) & 0xff, ipAddr >> 24);
}


NTSTATUS
OvsGetIPEntry(NET_LUID interfaceLuid,
              PMIB_UNICASTIPADDRESS_ROW ipEntry)
{
    PMIB_UNICASTIPADDRESS_TABLE ipTable;
    NTSTATUS status;
    UINT32 i;

    if (ipEntry == NULL || ipEntry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = GetUnicastIpAddressTable(AF_INET, &ipTable);

    if (status != STATUS_SUCCESS) {
        OVS_LOG_INFO("Fail to get unicast address table, status: %x", status);
        return status;
    }

    status = STATUS_NOT_FOUND;

    for (i = 0; i < ipTable->NumEntries; i++) {
        PMIB_UNICASTIPADDRESS_ROW ipRow;

        ipRow = &ipTable->Table[i];
        if (ipRow->InterfaceLuid.Value == interfaceLuid.Value) {
            RtlCopyMemory(ipEntry, ipRow, sizeof (*ipRow));
            OvsDumpIPEntry(ipEntry);
            status = STATUS_SUCCESS;
            break;
        }
    }

    FreeMibTable(ipTable);
    return status;
}

#ifdef OVS_ENABLE_IPPATH
static VOID
OvsDumpIPPath(PMIB_IPPATH_ROW ipPath)
{
    UINT32 ipAddr = ipPath->Source.Ipv4.sin_addr.s_addr;

    OVS_LOG_INFO("Source: %d.%d.%d.%d",
                 ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                 (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff);

    ipAddr = ipPath->Destination.Ipv4.sin_addr.s_addr;
    OVS_LOG_INFO("Destination: %d.%d.%d.%d",
                 ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                 (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff);

    ipAddr = ipPath->CurrentNextHop.Ipv4.sin_addr.s_addr;
    OVS_LOG_INFO("NextHop: %d.%d.%d.%d",
                 ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                 (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff);
}


NTSTATUS
OvsGetIPPathEntry(PMIB_IPPATH_ROW ipPath)
{
    NTSTATUS status;
    UINT32 ipAddr = ipPath->Destination.Ipv4.sin_addr.s_addr;

    status = GetIpPathEntry(ipPath);

    if (status != STATUS_SUCCESS) {
        OVS_LOG_INFO("Fail to get IP path to %d.%d.%d.%d, status:%x",
                     ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                     (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff, status);
        return status;
    }
    OvsDumpIPPath(ipPath);
    return status;
}
#endif

static VOID
OvsDumpRoute(const SOCKADDR_INET *sourceAddress,
             const SOCKADDR_INET *destinationAddress,
             PMIB_IPFORWARD_ROW2 route)
{
    UINT32 ipAddr = destinationAddress->Ipv4.sin_addr.s_addr;

    OVS_LOG_INFO("Destination: %d.%d.%d.%d",
                 ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                 (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff);

    ipAddr = sourceAddress->Ipv4.sin_addr.s_addr;
    OVS_LOG_INFO("Source: %d.%d.%d.%d",
                 ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                 (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff);

    ipAddr = route->NextHop.Ipv4.sin_addr.s_addr;
    OVS_LOG_INFO("NextHop: %d.%d.%d.%d",
                 ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                 (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff);
}


NTSTATUS
OvsGetRoute(NET_LUID interfaceLuid,
            const SOCKADDR_INET *destinationAddress,
            PMIB_IPFORWARD_ROW2 route,
            SOCKADDR_INET *sourceAddress)
{
    NTSTATUS status;

    if (destinationAddress == NULL || route == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = GetBestRoute2(&interfaceLuid, 0,
                           NULL, destinationAddress,
                           0, route, sourceAddress);

    if (status != STATUS_SUCCESS) {
        UINT32 ipAddr = destinationAddress->Ipv4.sin_addr.s_addr;
        OVS_LOG_INFO("Fail to get route to %d.%d.%d.%d, status: %x",
                     ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                     (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff, status);
        return status;
    }

    OvsDumpRoute(sourceAddress, destinationAddress, route);
    return status;
}

static VOID
OvsDumpIPNeigh(PMIB_IPNET_ROW2 ipNeigh)
{
    UINT32 ipAddr = ipNeigh->Address.Ipv4.sin_addr.s_addr;

    OVS_LOG_INFO("Neigh: %d.%d.%d.%d",
                     ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                     (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff);
    OVS_LOG_INFO("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x",
                 ipNeigh->PhysicalAddress[0],
                 ipNeigh->PhysicalAddress[1],
                 ipNeigh->PhysicalAddress[2],
                 ipNeigh->PhysicalAddress[3],
                 ipNeigh->PhysicalAddress[4],
                 ipNeigh->PhysicalAddress[5]);
}


NTSTATUS
OvsGetIPNeighEntry(PMIB_IPNET_ROW2 ipNeigh)
{
    NTSTATUS status;

    ASSERT(ipNeigh);

    status = GetIpNetEntry2(ipNeigh);

    if (status != STATUS_SUCCESS) {
        UINT32 ipAddr = ipNeigh->Address.Ipv4.sin_addr.s_addr;
        OVS_LOG_INFO("Fail to get ARP entry: %d.%d.%d.%d, status: %x",
                     ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                     (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff, status);
        return status;
    }
    if (ipNeigh->State == NlnsReachable ||
        ipNeigh->State == NlnsPermanent) {
        OvsDumpIPNeigh(ipNeigh);
        return STATUS_SUCCESS;
    }
    return STATUS_FWP_TCPIP_NOT_READY;
}


NTSTATUS
OvsResolveIPNeighEntry(PMIB_IPNET_ROW2 ipNeigh)
{
    NTSTATUS status;

    ASSERT(ipNeigh);
    status = ResolveIpNetEntry2(ipNeigh, NULL);

    if (status != STATUS_SUCCESS) {
        UINT32 ipAddr = ipNeigh->Address.Ipv4.sin_addr.s_addr;
        OVS_LOG_INFO("Fail to resolve ARP entry: %d.%d.%d.%d, status: %x",
                     ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                     (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff, status);
        return status;
    }

    if (ipNeigh->State == NlnsReachable ||
        ipNeigh->State == NlnsPermanent) {
        OvsDumpIPNeigh(ipNeigh);
        return STATUS_SUCCESS;
    }
    return STATUS_FWP_TCPIP_NOT_READY;
}


NTSTATUS
OvsGetOrResolveIPNeigh(UINT32 ipAddr,
                       PMIB_IPNET_ROW2 ipNeigh)
{
    NTSTATUS status;

    ASSERT(ipNeigh);

    RtlZeroMemory(ipNeigh, sizeof (*ipNeigh));
    ipNeigh->InterfaceLuid.Value = ovsInternalRow.InterfaceLuid.Value;
    ipNeigh->InterfaceIndex = ovsInternalRow.InterfaceIndex;
    ipNeigh->Address.si_family = AF_INET;
    ipNeigh->Address.Ipv4.sin_addr.s_addr = ipAddr;

    status = OvsGetIPNeighEntry(ipNeigh);

    if (status != STATUS_SUCCESS) {
        RtlZeroMemory(ipNeigh, sizeof (*ipNeigh));
        ipNeigh->InterfaceLuid.Value = ovsInternalRow.InterfaceLuid.Value;
        ipNeigh->InterfaceIndex = ovsInternalRow.InterfaceIndex;
        ipNeigh->Address.si_family = AF_INET;
        ipNeigh->Address.Ipv4.sin_addr.s_addr = ipAddr;
        status = OvsResolveIPNeighEntry(ipNeigh);
    }
    return status;
}


static VOID
OvsChangeCallbackIpInterface(PVOID context,
                             PMIB_IPINTERFACE_ROW ipRow,
                             MIB_NOTIFICATION_TYPE notificationType)
{
    UNREFERENCED_PARAMETER(context);
    switch (notificationType) {
    case MibParameterNotification:
    case MibAddInstance:
        if (ipRow->InterfaceLuid.Info.NetLuidIndex ==
            ovsInternalRow.InterfaceLuid.Info.NetLuidIndex &&
            ipRow->InterfaceLuid.Info.IfType ==
            ovsInternalRow.InterfaceLuid.Info.IfType &&
            ipRow->InterfaceIndex == ovsInternalRow.InterfaceIndex) {
            /*
             * Update the IP Interface Row
             */
            NdisAcquireSpinLock(&ovsIpHelperLock);
            RtlCopyMemory(&ovsInternalIPRow, ipRow,
                          sizeof (PMIB_IPINTERFACE_ROW));
            ovsInternalIPConfigured = TRUE;
            NdisReleaseSpinLock(&ovsIpHelperLock);
        }
        OVS_LOG_INFO("IP Interface with NetLuidIndex: %d, type: %d is %s",
                     ipRow->InterfaceLuid.Info.NetLuidIndex,
                     ipRow->InterfaceLuid.Info.IfType,
                     notificationType == MibAddInstance ? "added" : "modified");
        break;
    case MibDeleteInstance:
        OVS_LOG_INFO("IP Interface with NetLuidIndex: %d, type: %d, deleted",
                     ipRow->InterfaceLuid.Info.NetLuidIndex,
                     ipRow->InterfaceLuid.Info.IfType);
        if (ipRow->InterfaceLuid.Info.NetLuidIndex ==
            ovsInternalRow.InterfaceLuid.Info.NetLuidIndex &&
            ipRow->InterfaceLuid.Info.IfType ==
            ovsInternalRow.InterfaceLuid.Info.IfType &&
            ipRow->InterfaceIndex == ovsInternalRow.InterfaceIndex) {

            NdisAcquireSpinLock(&ovsIpHelperLock);
            ovsInternalIPConfigured = FALSE;
            NdisReleaseSpinLock(&ovsIpHelperLock);

            OvsCleanupIpHelperRequestList();

            OvsCleanupFwdTable();
        }

        break;
    case MibInitialNotification:
        OVS_LOG_INFO("Get Initial notification for IP Interface change.");
    default:
        return;
    }
}


static VOID
OvsChangeCallbackIpRoute(PVOID context,
                         PMIB_IPFORWARD_ROW2 ipRoute,
                         MIB_NOTIFICATION_TYPE notificationType)
{
    UINT32 ipAddr, nextHop;

    UNREFERENCED_PARAMETER(context);
    switch (notificationType) {
    case MibAddInstance:

        ASSERT(ipRoute);
        ipAddr = ipRoute->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr;
        nextHop = ipRoute->NextHop.Ipv4.sin_addr.s_addr;

        OVS_LOG_INFO("IPRoute: To %d.%d.%d.%d/%d through %d.%d.%d.%d added",
                     ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                     (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff,
                     ipRoute->DestinationPrefix.PrefixLength,
                     nextHop & 0xff, (nextHop >> 8) & 0xff,
                     (nextHop >> 16) & 0xff, (nextHop >> 24) & 0xff);
        break;

    case MibParameterNotification:
    case MibDeleteInstance:
        ASSERT(ipRoute);
        ipAddr = ipRoute->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr;
        nextHop = ipRoute->NextHop.Ipv4.sin_addr.s_addr;

        OVS_LOG_INFO("IPRoute: To %d.%d.%d.%d/%d through %d.%d.%d.%d %s.",
                     ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                     (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff,
                     ipRoute->DestinationPrefix.PrefixLength,
                     nextHop & 0xff, (nextHop >> 8) & 0xff,
                     (nextHop >> 16) & 0xff, (nextHop >> 24) & 0xff,
                     notificationType == MibDeleteInstance ? "deleted" :
                     "modified");

        if (ipRoute->InterfaceLuid.Info.NetLuidIndex ==
            ovsInternalRow.InterfaceLuid.Info.NetLuidIndex &&
            ipRoute->InterfaceLuid.Info.IfType ==
            ovsInternalRow.InterfaceLuid.Info.IfType &&
            ipRoute->InterfaceIndex == ovsInternalRow.InterfaceIndex) {

            POVS_IPFORWARD_ENTRY ipf;
            LOCK_STATE_EX lockState;

            NdisAcquireRWLockWrite(ovsTableLock, &lockState, 0);
            ipf = OvsLookupIPForwardEntry(&ipRoute->DestinationPrefix);
            if (ipf != NULL) {
                OvsRemoveIPForwardEntry(ipf);
            }
            NdisReleaseRWLock(ovsTableLock, &lockState);
        }
        break;

    case MibInitialNotification:
        OVS_LOG_INFO("Get Initial notification for IP Route change.");
    default:
        return;
    }
}


static VOID
OvsChangeCallbackUnicastIpAddress(PVOID context,
                                  PMIB_UNICASTIPADDRESS_ROW unicastRow,
                                  MIB_NOTIFICATION_TYPE notificationType)
{
    UINT32 ipAddr;

    UNREFERENCED_PARAMETER(context);
    switch (notificationType) {
    case MibParameterNotification:
    case MibAddInstance:
        ASSERT(unicastRow);
        ipAddr = unicastRow->Address.Ipv4.sin_addr.s_addr;
        if (unicastRow->InterfaceLuid.Info.NetLuidIndex ==
            ovsInternalRow.InterfaceLuid.Info.NetLuidIndex &&
            unicastRow->InterfaceLuid.Info.IfType ==
            ovsInternalRow.InterfaceLuid.Info.IfType &&
            unicastRow->InterfaceIndex == ovsInternalRow.InterfaceIndex) {
            ovsInternalIP = ipAddr;
        }
        OVS_LOG_INFO("IP Address: %d.%d.%d.%d is %s",
                     ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                     (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff,
                     notificationType == MibAddInstance ? "added": "modified");
        break;

    case MibDeleteInstance:
        ASSERT(unicastRow);
        ipAddr = unicastRow->Address.Ipv4.sin_addr.s_addr;
        OVS_LOG_INFO("IP Address removed: %d.%d.%d.%d",
                     ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                     (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff);
        if (unicastRow->InterfaceLuid.Info.NetLuidIndex ==
            ovsInternalRow.InterfaceLuid.Info.NetLuidIndex &&
            unicastRow->InterfaceLuid.Info.IfType ==
            ovsInternalRow.InterfaceLuid.Info.IfType &&
            unicastRow->InterfaceIndex == ovsInternalRow.InterfaceIndex) {

            LOCK_STATE_EX lockState;
            NdisAcquireRWLockWrite(ovsTableLock, &lockState, 0);
            OvsRemoveAllFwdEntriesWithSrc(ipAddr);
            NdisReleaseRWLock(ovsTableLock, &lockState);

        }
        break;

    case MibInitialNotification:
        OVS_LOG_INFO("Get Initial notification for Unicast IP Address change.");
    default:
        return;
    }
}


static VOID
OvsCancelChangeNotification()
{
    if (ipInterfaceNotificationHandle != NULL) {
        CancelMibChangeNotify2(ipInterfaceNotificationHandle);
        ipInterfaceNotificationHandle = NULL;
    }
    if (ipRouteNotificationHandle != NULL) {
        CancelMibChangeNotify2(ipRouteNotificationHandle);
        ipRouteNotificationHandle = NULL;
    }
    if (unicastIPNotificationHandle != NULL) {
        CancelMibChangeNotify2(unicastIPNotificationHandle);
        unicastIPNotificationHandle = NULL;
    }
}


static NTSTATUS
OvsRegisterChangeNotification()
{
    NTSTATUS status;


    status = NotifyIpInterfaceChange(AF_INET, OvsChangeCallbackIpInterface,
                                     NULL, TRUE,
                                     &ipInterfaceNotificationHandle);
    if (status != STATUS_SUCCESS) {
        OVS_LOG_ERROR("Fail to register Notify IP interface change, status:%x.",
                     status);
        return status;
    }

    status = NotifyRouteChange2(AF_INET, OvsChangeCallbackIpRoute, NULL,
                                TRUE, &ipRouteNotificationHandle);
    if (status != STATUS_SUCCESS) {
        OVS_LOG_ERROR("Fail to regiter ip route change, status: %x.",
                     status);
        goto register_cleanup;
    }
    status = NotifyUnicastIpAddressChange(AF_INET,
                                          OvsChangeCallbackUnicastIpAddress,
                                          NULL, TRUE,
                                          &unicastIPNotificationHandle);
    if (status != STATUS_SUCCESS) {
        OVS_LOG_ERROR("Fail to regiter unicast ip change, status: %x.", status);
    }
register_cleanup:
    if (status != STATUS_SUCCESS) {
        OvsCancelChangeNotification();
    }

    return status;
}


static POVS_IPNEIGH_ENTRY
OvsLookupIPNeighEntry(UINT32 ipAddr)
{
    PLIST_ENTRY link;
    POVS_IPNEIGH_ENTRY entry;
    UINT32 hash = OvsJhashWords(&ipAddr, 1, OVS_HASH_BASIS);

    LIST_FORALL(&ovsNeighHashTable[hash & OVS_NEIGH_HASH_TABLE_MASK], link) {
        entry = CONTAINING_RECORD(link, OVS_IPNEIGH_ENTRY, link);
        if (entry->ipAddr == ipAddr) {
            return entry;
        }
    }
    return NULL;
}


static UINT32
OvsHashIPPrefix(PIP_ADDRESS_PREFIX prefix)
{
    UINT64 words = (UINT64)prefix->Prefix.Ipv4.sin_addr.s_addr << 32 |
                   (UINT32)prefix->PrefixLength;
    return OvsJhashWords((UINT32 *)&words, 2, OVS_HASH_BASIS);
}


static POVS_IPFORWARD_ENTRY
OvsLookupIPForwardEntry(PIP_ADDRESS_PREFIX prefix)
{

    PLIST_ENTRY link;
    POVS_IPFORWARD_ENTRY ipfEntry;
    UINT32 hash;
    ASSERT(prefix->Prefix.si_family == AF_INET);

    hash = RtlUlongByteSwap(prefix->Prefix.Ipv4.sin_addr.s_addr);

    ASSERT(prefix->PrefixLength >= 32 ||
           (hash & (((UINT32)1 <<  (32 - prefix->PrefixLength)) - 1)) == 0);

    hash = OvsHashIPPrefix(prefix);
    LIST_FORALL(&ovsRouteHashTable[hash & OVS_ROUTE_HASH_TABLE_MASK], link) {
        ipfEntry = CONTAINING_RECORD(link, OVS_IPFORWARD_ENTRY, link);
        if (ipfEntry->prefix.PrefixLength == prefix->PrefixLength &&
            ipfEntry->prefix.Prefix.Ipv4.sin_addr.s_addr ==
            prefix->Prefix.Ipv4.sin_addr.s_addr) {
            return ipfEntry;
        }
    }
    return NULL;
}


static POVS_FWD_ENTRY
OvsLookupIPFwdEntry(UINT32 dstIp)
{
    PLIST_ENTRY link;
    POVS_FWD_ENTRY entry;
    UINT32 hash = OvsJhashWords(&dstIp, 1, OVS_HASH_BASIS);

    LIST_FORALL(&ovsFwdHashTable[hash & OVS_FWD_HASH_TABLE_MASK], link) {
        entry = CONTAINING_RECORD(link, OVS_FWD_ENTRY, link);
        if (entry->info.dstIpAddr == dstIp) {
            return entry;
        }
    }
    return NULL;
}


NTSTATUS
OvsLookupIPFwdInfo(UINT32 dstIp,
                   POVS_FWD_INFO info)
{
    POVS_FWD_ENTRY entry;
    LOCK_STATE_EX lockState;
    NTSTATUS status = STATUS_NOT_FOUND;

    NdisAcquireRWLockRead(ovsTableLock, &lockState, 0);
    entry = OvsLookupIPFwdEntry(dstIp);
    if (entry) {
        info->value[0] = entry->info.value[0];
        info->value[1] = entry->info.value[1];
        info->value[2] = entry->info.value[2];
        status = STATUS_SUCCESS;
    }
    NdisReleaseRWLock(ovsTableLock, &lockState);
    return status;
}


static POVS_IPNEIGH_ENTRY
OvsCreateIPNeighEntry(PMIB_IPNET_ROW2 ipNeigh)
{

    POVS_IPNEIGH_ENTRY entry;
    UINT64 timeVal;

    ASSERT(ipNeigh != NULL);
    entry = (POVS_IPNEIGH_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(OVS_IPNEIGH_ENTRY), OVS_IPHELPER_POOL_TAG);
    if (entry == NULL) {
        return NULL;
    }

    RtlZeroMemory(entry, sizeof (OVS_IPNEIGH_ENTRY));
    entry->ipAddr = ipNeigh->Address.Ipv4.sin_addr.s_addr;
    KeQuerySystemTime((LARGE_INTEGER *)&timeVal);
    entry->timeout = timeVal + OVS_IPNEIGH_TIMEOUT;
    RtlCopyMemory(entry->macAddr, ipNeigh->PhysicalAddress,
                  ETH_ADDR_LEN);
    InitializeListHead(&entry->fwdList);

    return entry;
}


static POVS_IPFORWARD_ENTRY
OvsCreateIPForwardEntry(PMIB_IPFORWARD_ROW2 ipRoute)
{

    POVS_IPFORWARD_ENTRY entry;

    ASSERT(ipRoute);

    entry = (POVS_IPFORWARD_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(OVS_IPFORWARD_ENTRY), OVS_IPHELPER_POOL_TAG);
    if (entry == NULL) {
        return NULL;
    }

    RtlZeroMemory(entry, sizeof (OVS_IPFORWARD_ENTRY));
    RtlCopyMemory(&entry->prefix, &ipRoute->DestinationPrefix,
                  sizeof (IP_ADDRESS_PREFIX));
    entry->nextHop = ipRoute->NextHop.Ipv4.sin_addr.s_addr;
    InitializeListHead(&entry->fwdList);

    return entry;
}


static POVS_FWD_ENTRY
OvsCreateFwdEntry(POVS_FWD_INFO fwdInfo)
{
    POVS_FWD_ENTRY entry;

    entry = (POVS_FWD_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(OVS_FWD_ENTRY), OVS_IPHELPER_POOL_TAG);
    if (entry == NULL) {
        return NULL;
    }

    RtlZeroMemory(entry, sizeof (OVS_FWD_ENTRY));
    RtlCopyMemory(&entry->info, fwdInfo, sizeof (OVS_FWD_INFO));
    return entry;
}


static VOID
OvsRemoveFwdEntry(POVS_FWD_ENTRY fwdEntry)
{
    POVS_IPFORWARD_ENTRY ipf;
    POVS_IPNEIGH_ENTRY ipn;

    ipf = fwdEntry->ipf;
    ipn = fwdEntry->ipn;

    RemoveEntryList(&fwdEntry->link);
    ovsNumFwdEntries--;

    RemoveEntryList(&fwdEntry->ipfLink);
    ipf->refCount--;

    RemoveEntryList(&fwdEntry->ipnLink);
    ipn->refCount--;

    if (ipf->refCount == 0) {
        ASSERT(IsListEmpty(&ipf->fwdList));
        RemoveEntryList(&ipf->link);
        OvsFreeMemoryWithTag(ipf, OVS_IPHELPER_POOL_TAG);
    }

    if (ipn->refCount == 0) {
        ASSERT(IsListEmpty(&ipn->fwdList));
        RemoveEntryList(&ipn->link);
        NdisAcquireSpinLock(&ovsIpHelperLock);
        RemoveEntryList(&ipn->slink);
        NdisReleaseSpinLock(&ovsIpHelperLock);
        OvsFreeMemoryWithTag(ipn, OVS_IPHELPER_POOL_TAG);
    }

    OvsFreeMemoryWithTag(fwdEntry, OVS_IPHELPER_POOL_TAG);
}


static VOID
OvsRemoveIPForwardEntry(POVS_IPFORWARD_ENTRY ipf)
{
    POVS_FWD_ENTRY fwdEntry;
    PLIST_ENTRY link, next;

    ipf->refCount++;

    LIST_FORALL_SAFE(&ipf->fwdList, link, next) {
        fwdEntry = CONTAINING_RECORD(link, OVS_FWD_ENTRY, ipfLink);
        OvsRemoveFwdEntry(fwdEntry);
    }
    ASSERT(ipf->refCount == 1);

    RemoveEntryList(&ipf->link);
    OvsFreeMemoryWithTag(ipf, OVS_IPHELPER_POOL_TAG);
}


static VOID
OvsRemoveIPNeighEntry(POVS_IPNEIGH_ENTRY ipn)
{
    PLIST_ENTRY link, next;
    POVS_FWD_ENTRY fwdEntry;

    ipn->refCount++;

    LIST_FORALL_SAFE(&ipn->fwdList, link, next) {
        fwdEntry = CONTAINING_RECORD(link, OVS_FWD_ENTRY, ipnLink);
        OvsRemoveFwdEntry(fwdEntry);
    }

    if (ipn->refCount == 1) {
        RemoveEntryList(&ipn->link);
        NdisAcquireSpinLock(&ovsIpHelperLock);
        RemoveEntryList(&ipn->slink);
        NdisReleaseSpinLock(&ovsIpHelperLock);
        OvsFreeMemoryWithTag(ipn, OVS_IPHELPER_POOL_TAG);
    }
}


static VOID
OvsAddToSortedNeighList(POVS_IPNEIGH_ENTRY ipn)
{
    PLIST_ENTRY link;
    POVS_IPNEIGH_ENTRY entry;

    if (!IsListEmpty(&ovsSortedIPNeighList)) {
        link = ovsSortedIPNeighList.Blink;
        entry = CONTAINING_RECORD(link, OVS_IPNEIGH_ENTRY, slink);
        if (entry->timeout > ipn->timeout) {
            ipn->timeout++;
        }
    }
    InsertTailList(&ovsSortedIPNeighList, &ipn->slink);
}


static VOID
OvsAddIPFwdCache(POVS_FWD_ENTRY fwdEntry,
                 POVS_IPFORWARD_ENTRY ipf,
                 POVS_IPNEIGH_ENTRY ipn)

{
    UINT32 hash;

    if (ipn->refCount == 0) {
        NdisAcquireSpinLock(&ovsIpHelperLock);
        OvsAddToSortedNeighList(ipn);
        NdisReleaseSpinLock(&ovsIpHelperLock);
        hash = OvsJhashWords(&ipn->ipAddr, 1, OVS_HASH_BASIS);
        InsertHeadList(&ovsNeighHashTable[hash & OVS_NEIGH_HASH_TABLE_MASK],
                       &ipn->link);
    }
    if (ipf->refCount == 0) {
        hash = OvsHashIPPrefix(&ipf->prefix);
        InsertHeadList(&ovsRouteHashTable[hash & OVS_ROUTE_HASH_TABLE_MASK],
                       &ipf->link);
    }

    InsertHeadList(&ipf->fwdList, &fwdEntry->ipfLink);
    ipf->refCount++;
    fwdEntry->ipf = ipf;

    InsertHeadList(&ipn->fwdList, &fwdEntry->ipnLink);
    ipn->refCount++;
    fwdEntry->ipn = ipn;

    hash = OvsJhashWords(&fwdEntry->info.dstIpAddr, 1, OVS_HASH_BASIS);
    InsertHeadList(&ovsFwdHashTable[hash & OVS_FWD_HASH_TABLE_MASK],
                   &fwdEntry->link);
    ovsNumFwdEntries++;
}


static VOID
OvsRemoveAllFwdEntriesWithSrc(UINT32 ipAddr)
{
    UINT32 i;
    POVS_FWD_ENTRY fwdEntry;
    PLIST_ENTRY link, next;

    for (i = 0; i < OVS_FWD_HASH_TABLE_SIZE; i++) {
        LIST_FORALL_SAFE(&ovsFwdHashTable[i], link, next) {
            fwdEntry = CONTAINING_RECORD(link, OVS_FWD_ENTRY, link);
            if (fwdEntry->info.srcIpAddr == ipAddr) {
                OvsRemoveFwdEntry(fwdEntry);
            }
        }
    }
}


static VOID
OvsCleanupFwdTable(VOID)
{
    PLIST_ENTRY link, next;
    POVS_IPNEIGH_ENTRY ipn;
    UINT32 i;
    LOCK_STATE_EX lockState;

    NdisAcquireRWLockWrite(ovsTableLock, &lockState, 0);
    if (ovsNumFwdEntries) {
       LIST_FORALL_SAFE(&ovsSortedIPNeighList, link, next) {
           ipn = CONTAINING_RECORD(link, OVS_IPNEIGH_ENTRY, slink);
           OvsRemoveIPNeighEntry(ipn);
       }
    }
    for (i = 0; i < OVS_FWD_HASH_TABLE_SIZE; i++) {
        ASSERT(IsListEmpty(&ovsFwdHashTable[i]));
    }
    for (i = 0; i < OVS_ROUTE_HASH_TABLE_SIZE; i++) {
        ASSERT(IsListEmpty(&ovsRouteHashTable[i]));
    }
    NdisReleaseRWLock(ovsTableLock, &lockState);
}


static VOID
OvsCleanupIpHelperRequestList(VOID)
{
    LIST_ENTRY list;
    PLIST_ENTRY next, link;
    POVS_IP_HELPER_REQUEST request;

    NdisAcquireSpinLock(&ovsIpHelperLock);
    if (ovsNumIpHelperRequests == 0) {
       NdisReleaseSpinLock(&ovsIpHelperLock);
       return;
    }

    InitializeListHead(&list);
    OvsAppendList(&list,  &ovsIpHelperRequestList);
    ovsNumIpHelperRequests = 0;
    NdisReleaseSpinLock(&ovsIpHelperLock);

    LIST_FORALL_SAFE(&list, link, next) {
        request = CONTAINING_RECORD(link, OVS_IP_HELPER_REQUEST, link);

        if (request->command == OVS_IP_HELPER_FWD_REQUEST &&
            request->fwdReq.cb) {
            request->fwdReq.cb(request->fwdReq.nbl,
                               request->fwdReq.inPort,
                               &request->fwdReq.tunnelKey,
                               request->fwdReq.cbData1,
                               request->fwdReq.cbData2,
                               STATUS_DEVICE_NOT_READY,
                               NULL);
        }
        OvsFreeMemoryWithTag(request, OVS_IPHELPER_POOL_TAG);
    }
}



static VOID
OvsWakeupIPHelper(VOID)
{
    KeSetEvent(&ovsIpHelperThreadContext.event, 0, FALSE);
}

VOID
OvsInternalAdapterDown(VOID)
{
    NdisAcquireSpinLock(&ovsIpHelperLock);
    ovsInternalPortNo = OVS_DEFAULT_PORT_NO;
    ovsInternalIPConfigured = FALSE;
    NdisReleaseSpinLock(&ovsIpHelperLock);

    OvsCleanupIpHelperRequestList();

    OvsCleanupFwdTable();
}


VOID
OvsInternalAdapterUp(UINT32 portNo,
                     GUID *netCfgInstanceId)
{
    POVS_IP_HELPER_REQUEST request;

    RtlCopyMemory(&ovsInternalNetCfgId, netCfgInstanceId, sizeof (GUID));
    RtlZeroMemory(&ovsInternalRow, sizeof (MIB_IF_ROW2));

    request = (POVS_IP_HELPER_REQUEST)OvsAllocateMemoryWithTag(
        sizeof(OVS_IP_HELPER_REQUEST), OVS_IPHELPER_POOL_TAG);
    if (request == NULL) {
        OVS_LOG_ERROR("Fail to initialize Internal Adapter");
        return;
    }
    RtlZeroMemory(request, sizeof (OVS_IP_HELPER_REQUEST));
    request->command = OVS_IP_HELPER_INTERNAL_ADAPTER_UP;

    NdisAcquireSpinLock(&ovsIpHelperLock);
    ovsInternalPortNo = portNo;
    InsertHeadList(&ovsIpHelperRequestList, &request->link);
    ovsNumIpHelperRequests++;
    if (ovsNumIpHelperRequests == 1) {
        OvsWakeupIPHelper();
    }
    NdisReleaseSpinLock(&ovsIpHelperLock);
}


static VOID
OvsHandleInternalAdapterUp(POVS_IP_HELPER_REQUEST request)
{
    NTSTATUS status;
    MIB_UNICASTIPADDRESS_ROW ipEntry;
    GUID *netCfgInstanceId = &ovsInternalNetCfgId;

    OvsFreeMemoryWithTag(request, OVS_IPHELPER_POOL_TAG);

    status = OvsGetIfEntry(&ovsInternalNetCfgId, &ovsInternalRow);

    if (status != STATUS_SUCCESS) {
        OVS_LOG_ERROR("Fali to get IF entry for internal port with GUID"
                      "  %08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
                      netCfgInstanceId->Data1,
                      netCfgInstanceId->Data2,
                      netCfgInstanceId->Data3,
                      *(UINT16 *)netCfgInstanceId->Data4,
                      netCfgInstanceId->Data4[2],
                      netCfgInstanceId->Data4[3],
                      netCfgInstanceId->Data4[4],
                      netCfgInstanceId->Data4[5],
                      netCfgInstanceId->Data4[6],
                      netCfgInstanceId->Data4[7]);
        return;
    }

    status = OvsGetIPInterfaceEntry(ovsInternalRow.InterfaceLuid,
                                    &ovsInternalIPRow);

    if (status == STATUS_SUCCESS) {
        NdisAcquireSpinLock(&ovsIpHelperLock);
        ovsInternalIPConfigured = TRUE;
        NdisReleaseSpinLock(&ovsIpHelperLock);
    } else {
        return;
    }

    status = OvsGetIPEntry(ovsInternalRow.InterfaceLuid, &ipEntry);
    if (status != STATUS_SUCCESS) {
        OVS_LOG_INFO("Fali to get IP entry for internal port with GUID"
                     "  %08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
                     netCfgInstanceId->Data1,
                     netCfgInstanceId->Data2,
                     netCfgInstanceId->Data3,
                     *(UINT16 *)netCfgInstanceId->Data4,
                     netCfgInstanceId->Data4[2],
                     netCfgInstanceId->Data4[3],
                     netCfgInstanceId->Data4[4],
                     netCfgInstanceId->Data4[5],
                     netCfgInstanceId->Data4[6],
                     netCfgInstanceId->Data4[7]);
    }
}


static NTSTATUS
OvsEnqueueIpHelperRequest(POVS_IP_HELPER_REQUEST request)
{

    NdisAcquireSpinLock(&ovsIpHelperLock);

    if (ovsInternalPortNo == OVS_DEFAULT_PORT_NO ||
        ovsInternalIPConfigured == FALSE) {
        NdisReleaseSpinLock(&ovsIpHelperLock);
        OvsFreeMemoryWithTag(request, OVS_IPHELPER_POOL_TAG);
        return STATUS_NDIS_ADAPTER_NOT_READY;
    } else {
        InsertHeadList(&ovsIpHelperRequestList, &request->link);
        ovsNumIpHelperRequests++;
        if (ovsNumIpHelperRequests == 1) {
            OvsWakeupIPHelper();
        }
        NdisReleaseSpinLock(&ovsIpHelperLock);
        return STATUS_SUCCESS;
    }
}


NTSTATUS
OvsFwdIPHelperRequest(PNET_BUFFER_LIST nbl,
                      UINT32 inPort,
                      const OvsIPv4TunnelKey *tunnelKey,
                      OvsIPHelperCallback cb,
                      PVOID cbData1,
                      PVOID cbData2)
{
    POVS_IP_HELPER_REQUEST request;

    request = (POVS_IP_HELPER_REQUEST)OvsAllocateMemoryWithTag(
        sizeof(OVS_IP_HELPER_REQUEST), OVS_IPHELPER_POOL_TAG);

    if (request == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    request->command = OVS_IP_HELPER_FWD_REQUEST;
    request->fwdReq.nbl = nbl;
    request->fwdReq.inPort = inPort;
    RtlCopyMemory(&request->fwdReq.tunnelKey, tunnelKey,
                  sizeof (*tunnelKey));
    request->fwdReq.cb = cb;
    request->fwdReq.cbData1 = cbData1;
    request->fwdReq.cbData2 = cbData2;

    return OvsEnqueueIpHelperRequest(request);
}


static VOID
OvsHandleFwdRequest(POVS_IP_HELPER_REQUEST request)
{
    SOCKADDR_INET dst, src;
    NTSTATUS status = STATUS_SUCCESS;
    MIB_IPFORWARD_ROW2 ipRoute;
    MIB_IPNET_ROW2 ipNeigh;
    OVS_FWD_INFO fwdInfo;
    UINT32 ipAddr;
    UINT32 srcAddr;
    POVS_FWD_ENTRY fwdEntry = NULL;
    POVS_IPFORWARD_ENTRY ipf = NULL;
    POVS_IPNEIGH_ENTRY ipn = NULL;
    LOCK_STATE_EX lockState;
    BOOLEAN  newIPF = FALSE;
    BOOLEAN  newIPN = FALSE;
    BOOLEAN  newFWD = FALSE;

    status = OvsLookupIPFwdInfo(request->fwdReq.tunnelKey.dst,
                                &fwdInfo);
    if (status == STATUS_SUCCESS) {
        goto fwd_handle_nbl;
    }

    /* find IPRoute */
    RtlZeroMemory(&dst, sizeof(dst));
    RtlZeroMemory(&src, sizeof(src));
    RtlZeroMemory(&ipRoute, sizeof (MIB_IPFORWARD_ROW2));
    dst.si_family = AF_INET;
    dst.Ipv4.sin_addr.s_addr = request->fwdReq.tunnelKey.dst;

    status = OvsGetRoute(ovsInternalRow.InterfaceLuid, &dst, &ipRoute, &src);
    if (status != STATUS_SUCCESS) {
        goto fwd_handle_nbl;
    }
    srcAddr = src.Ipv4.sin_addr.s_addr;

    /* find IPNeigh */
    ipAddr = ipRoute.NextHop.Ipv4.sin_addr.s_addr;
    if (ipAddr != 0) {
        NdisAcquireRWLockWrite(ovsTableLock, &lockState, 0);
        ipn = OvsLookupIPNeighEntry(ipAddr);
        if (ipn) {
            goto fwd_request_done;
        }
        NdisReleaseRWLock(ovsTableLock, &lockState);
    }
    RtlZeroMemory(&ipNeigh, sizeof (ipNeigh));
    ipNeigh.InterfaceLuid.Value = ovsInternalRow.InterfaceLuid.Value;
    if (ipAddr == 0) {
        ipAddr = request->fwdReq.tunnelKey.dst;
    }
    status = OvsGetOrResolveIPNeigh(ipAddr, &ipNeigh);
    if (status != STATUS_SUCCESS) {
        goto fwd_handle_nbl;
    }

    NdisAcquireRWLockWrite(ovsTableLock, &lockState, 0);

fwd_request_done:

    /*
     * Initialize ipf
     */
    ipf = OvsLookupIPForwardEntry(&ipRoute.DestinationPrefix);
    if (ipf == NULL) {
        ipf = OvsCreateIPForwardEntry(&ipRoute);
        if (ipf == NULL) {
            NdisReleaseRWLock(ovsTableLock, &lockState);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto fwd_handle_nbl;
        }
        newIPF = TRUE;
    } else {
        PLIST_ENTRY link;
        link = ipf->fwdList.Flink;
        fwdEntry = CONTAINING_RECORD(link, OVS_FWD_ENTRY, ipfLink);
        srcAddr = fwdEntry->info.srcIpAddr;
    }

    /*
     * initialize ipn
     */
    if (ipn == NULL) {
        ipn = OvsLookupIPNeighEntry(ipAddr);
        if (ipn == NULL) {
            ipn = OvsCreateIPNeighEntry(&ipNeigh);
            if (ipn == NULL) {
                NdisReleaseRWLock(ovsTableLock, &lockState);
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto fwd_handle_nbl;
            }
            newIPN = TRUE;
        }
    }

    /*
     * initialize fwdEntry
     */
    fwdInfo.dstIpAddr = request->fwdReq.tunnelKey.dst;
    fwdInfo.srcIpAddr = srcAddr;
    RtlCopyMemory(fwdInfo.dstMacAddr, ipn->macAddr, ETH_ADDR_LEN);
    RtlCopyMemory(fwdInfo.srcMacAddr, ovsInternalRow.PhysicalAddress,
                  ETH_ADDR_LEN);
    fwdInfo.srcPortNo = request->fwdReq.inPort;

    fwdEntry = OvsCreateFwdEntry(&fwdInfo);
    if (fwdEntry == NULL) {
        NdisReleaseRWLock(ovsTableLock, &lockState);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto fwd_handle_nbl;
    }
    newFWD = TRUE;
    /*
     * Cache the result
     */
    OvsAddIPFwdCache(fwdEntry, ipf, ipn);
    NdisReleaseRWLock(ovsTableLock, &lockState);

fwd_handle_nbl:

    if (status != STATUS_SUCCESS) {
        if (newFWD) {
            ASSERT(fwdEntry != NULL);
            OvsFreeMemoryWithTag(fwdEntry, OVS_IPHELPER_POOL_TAG);
        }
        if (newIPF) {
            ASSERT(ipf && ipf->refCount == 0);
            OvsFreeMemoryWithTag(ipf, OVS_IPHELPER_POOL_TAG);
        }
        if (newIPN) {
            ASSERT(ipn && ipn->refCount == 0);
            OvsFreeMemoryWithTag(ipn, OVS_IPHELPER_POOL_TAG);
        }
        ipAddr = request->fwdReq.tunnelKey.dst;
        OVS_LOG_INFO("Fail to handle IP helper request for dst: %d.%d.%d.%d",
                     ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                     (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff);
    }
    if (request->fwdReq.cb) {
        request->fwdReq.cb(request->fwdReq.nbl,
                           request->fwdReq.inPort,
                           &request->fwdReq.tunnelKey,
                           request->fwdReq.cbData1,
                           request->fwdReq.cbData2,
                           status,
                           status == STATUS_SUCCESS ? &fwdInfo : NULL);
    }
    OvsFreeMemoryWithTag(request, OVS_IPHELPER_POOL_TAG);
}


static VOID
OvsUpdateIPNeighEntry(UINT32 ipAddr,
                      PMIB_IPNET_ROW2 ipNeigh,
                      NTSTATUS status)
{
    UINT64 timeVal;
    POVS_IPNEIGH_ENTRY ipn;
    LOCK_STATE_EX lockState;
    KeQuerySystemTime((LARGE_INTEGER *)&timeVal);
    /*
     * if mac changed, update all relevant fwdEntry
     */
    if (status != STATUS_SUCCESS) {
        NdisAcquireRWLockWrite(ovsTableLock, &lockState, 0);
    } else {
        NdisAcquireRWLockRead(ovsTableLock, &lockState, 0);
    }
    ipn = OvsLookupIPNeighEntry(ipAddr);
    if (ipn == NULL) {
        NdisReleaseRWLock(ovsTableLock, &lockState);
        return;
    }
    if (status != STATUS_SUCCESS) {
        OvsRemoveIPNeighEntry(ipn);
        NdisReleaseRWLock(ovsTableLock, &lockState);
        return;
    }

    if (memcmp((const PVOID)ipn->macAddr,
               (const PVOID)ipNeigh->PhysicalAddress,
               (size_t)ETH_ADDR_LEN)) {
        PLIST_ENTRY link;
        POVS_FWD_ENTRY fwdEntry;
        NdisReleaseRWLock(ovsTableLock, &lockState);
        /*
         * need update, release and acquire write lock
         * This is not the common case.
         */

        NdisAcquireRWLockWrite(ovsTableLock, &lockState, 0);
        ipn = OvsLookupIPNeighEntry(ipAddr);

        if (ipn == NULL) {
            NdisReleaseRWLock(ovsTableLock, &lockState);
            return;
        }

        LIST_FORALL(&ipn->fwdList, link) {
            fwdEntry = CONTAINING_RECORD(link, OVS_FWD_ENTRY, ipnLink);
            RtlCopyMemory(fwdEntry->info.dstMacAddr,
                          ipNeigh->PhysicalAddress, ETH_ADDR_LEN);
        }
    }
    /*
     * update timeout and move to the end of
     * the sorted list
     */

    NdisAcquireSpinLock(&ovsIpHelperLock);
    RemoveEntryList(&ipn->slink);
    ipn->timeout = timeVal + OVS_IPNEIGH_TIMEOUT;
    OvsAddToSortedNeighList(ipn);
    NdisReleaseSpinLock(&ovsIpHelperLock);
    NdisReleaseRWLock(ovsTableLock, &lockState);
}


static VOID
OvsHandleIPNeighTimeout(UINT32 ipAddr)
{
    MIB_IPNET_ROW2 ipNeigh;
    NTSTATUS status;

    status = OvsGetOrResolveIPNeigh(ipAddr, &ipNeigh);

    OvsUpdateIPNeighEntry(ipAddr, &ipNeigh, status);
}


/*
 *----------------------------------------------------------------------------
 *  IP Helper system threash handle following request
 *    1. Intialize Internal port row when internal port is connected
 *    2. Handle FWD request
 *    3. Handle IP Neigh timeout
 *
 *    IP Interface, unicast address, and IP route change will be handled
 *    by the revelant callback.
 *----------------------------------------------------------------------------
 */
VOID
OvsStartIpHelper(PVOID data)
{
    POVS_IP_HELPER_THREAD_CONTEXT context = (POVS_IP_HELPER_THREAD_CONTEXT)data;
    POVS_IP_HELPER_REQUEST req;
    POVS_IPNEIGH_ENTRY ipn;
    PLIST_ENTRY link;
    UINT64   timeVal, timeout;

    OVS_LOG_INFO("Start the IP Helper Thread, context: %p", context);

    NdisAcquireSpinLock(&ovsIpHelperLock);
    while (!context->exit) {

        timeout = 0;
        while (!IsListEmpty(&ovsIpHelperRequestList)) {
            if (context->exit) {
                goto ip_helper_wait;
            }
            link = ovsIpHelperRequestList.Flink;
            RemoveEntryList(link);
            NdisReleaseSpinLock(&ovsIpHelperLock);
            req = CONTAINING_RECORD(link, OVS_IP_HELPER_REQUEST, link);
            switch (req->command) {
            case OVS_IP_HELPER_INTERNAL_ADAPTER_UP:
                OvsHandleInternalAdapterUp(req);
                break;
            case OVS_IP_HELPER_FWD_REQUEST:
                OvsHandleFwdRequest(req);
                break;
            default:
                OvsFreeMemoryWithTag(req, OVS_IPHELPER_POOL_TAG);
            }
            NdisAcquireSpinLock(&ovsIpHelperLock);
        }

        /* for now, let us hold the lock here, if this cause any issue
         * we will change to use IpHelper lock only to protect
         * IPN
         */
        while (!IsListEmpty(&ovsSortedIPNeighList)) {
            UINT32 ipAddr;
            if (context->exit) {
                goto ip_helper_wait;
            }
            link = ovsSortedIPNeighList.Flink;
            ipn = CONTAINING_RECORD(link, OVS_IPNEIGH_ENTRY, slink);
            KeQuerySystemTime((LARGE_INTEGER *)&timeVal);
            if (ipn->timeout > timeVal) {
                timeout = ipn->timeout;
                break;
            }
            ipAddr = ipn->ipAddr;

            NdisReleaseSpinLock(&ovsIpHelperLock);

            OvsHandleIPNeighTimeout(ipAddr);

            NdisAcquireSpinLock(&ovsIpHelperLock);
        }
        if (!IsListEmpty(&ovsIpHelperRequestList)) {
            continue;
        }

ip_helper_wait:
        if (context->exit) {
            break;
        }

        KeClearEvent(&context->event);
        NdisReleaseSpinLock(&ovsIpHelperLock);

        KeWaitForSingleObject(&context->event, Executive, KernelMode,
                              FALSE, (LARGE_INTEGER *)&timeout);
        NdisAcquireSpinLock(&ovsIpHelperLock);
    }
    NdisReleaseSpinLock(&ovsIpHelperLock);
    OvsCleanupFwdTable();
    OvsCleanupIpHelperRequestList();

    OVS_LOG_INFO("Terminating the OVS IP Helper system thread");

    PsTerminateSystemThread(STATUS_SUCCESS);
}


NTSTATUS
OvsInitIpHelper(NDIS_HANDLE ndisFilterHandle)
{
    NTSTATUS status;
    HANDLE threadHandle;
    UINT32 i;

    ovsFwdHashTable = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_FWD_HASH_TABLE_SIZE, OVS_IPHELPER_POOL_TAG);

    ovsRouteHashTable = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_ROUTE_HASH_TABLE_SIZE, OVS_IPHELPER_POOL_TAG);

    ovsNeighHashTable = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_NEIGH_HASH_TABLE_SIZE, OVS_IPHELPER_POOL_TAG);

    RtlZeroMemory(&ovsInternalRow, sizeof(MIB_IF_ROW2));
    RtlZeroMemory(&ovsInternalIPRow, sizeof (MIB_IPINTERFACE_ROW));
    ovsInternalIP = 0;

    ovsInternalPortNo = OVS_DEFAULT_PORT_NO;

    InitializeListHead(&ovsSortedIPNeighList);

    ovsTableLock = NdisAllocateRWLock(ndisFilterHandle);
    NdisAllocateSpinLock(&ovsIpHelperLock);

    InitializeListHead(&ovsIpHelperRequestList);
    ovsNumIpHelperRequests = 0;
    ipInterfaceNotificationHandle = NULL;
    ipRouteNotificationHandle = NULL;
    unicastIPNotificationHandle = NULL;

    if (ovsFwdHashTable == NULL ||
        ovsRouteHashTable == NULL ||
        ovsNeighHashTable == NULL ||
        ovsTableLock == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto init_cleanup;
    }

    for (i = 0; i < OVS_FWD_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&ovsFwdHashTable[i]);
    }

    for (i = 0; i < OVS_ROUTE_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&ovsRouteHashTable[i]);
    }

    for (i = 0; i < OVS_NEIGH_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&ovsNeighHashTable[i]);
    }


    KeInitializeEvent(&ovsIpHelperThreadContext.event, NotificationEvent,
                      FALSE);
    status = OvsRegisterChangeNotification();
    ovsIpHelperThreadContext.exit = 0;
    if (status == STATUS_SUCCESS) {
        status = PsCreateSystemThread(&threadHandle, SYNCHRONIZE,
                                      NULL, NULL, NULL, OvsStartIpHelper,
                                      &ovsIpHelperThreadContext);
        if (status != STATUS_SUCCESS) {
            goto init_cleanup;
        }
        ObReferenceObjectByHandle(threadHandle, SYNCHRONIZE, NULL,
                                  KernelMode,
                                  &ovsIpHelperThreadContext.threadObject,
                                  NULL);
        ZwClose(threadHandle);
    }

init_cleanup:

    if (status != STATUS_SUCCESS) {
        OvsCancelChangeNotification();
        if (ovsFwdHashTable) {
            OvsFreeMemoryWithTag(ovsFwdHashTable, OVS_IPHELPER_POOL_TAG);
            ovsFwdHashTable = NULL;
        }
        if (ovsRouteHashTable) {
            OvsFreeMemoryWithTag(ovsRouteHashTable, OVS_IPHELPER_POOL_TAG);
            ovsRouteHashTable = NULL;
        }
        if (ovsNeighHashTable) {
            OvsFreeMemoryWithTag(ovsNeighHashTable, OVS_IPHELPER_POOL_TAG);
            ovsNeighHashTable = NULL;
        }
        if (ovsTableLock) {
            NdisFreeRWLock(ovsTableLock);
            ovsTableLock = NULL;
        }
        NdisFreeSpinLock(&ovsIpHelperLock);
    }
    return STATUS_SUCCESS;
}


VOID
OvsCleanupIpHelper(VOID)
{
    OvsCancelChangeNotification();

    NdisAcquireSpinLock(&ovsIpHelperLock);
    ovsIpHelperThreadContext.exit = 1;
    OvsWakeupIPHelper();
    NdisReleaseSpinLock(&ovsIpHelperLock);

    KeWaitForSingleObject(ovsIpHelperThreadContext.threadObject, Executive,
                          KernelMode, FALSE, NULL);
    ObDereferenceObject(ovsIpHelperThreadContext.threadObject);

    OvsFreeMemoryWithTag(ovsFwdHashTable, OVS_IPHELPER_POOL_TAG);
    OvsFreeMemoryWithTag(ovsRouteHashTable, OVS_IPHELPER_POOL_TAG);
    OvsFreeMemoryWithTag(ovsNeighHashTable, OVS_IPHELPER_POOL_TAG);

    NdisFreeRWLock(ovsTableLock);
    NdisFreeSpinLock(&ovsIpHelperLock);
}

VOID
OvsCancelFwdIpHelperRequest(PNET_BUFFER_LIST nbl)
{
    PLIST_ENTRY link, next;
    POVS_IP_HELPER_REQUEST req;
    LIST_ENTRY list;
    InitializeListHead(&list);

    NdisAcquireSpinLock(&ovsIpHelperLock);
    LIST_FORALL_SAFE(&ovsIpHelperRequestList, link, next) {
        req = CONTAINING_RECORD(link, OVS_IP_HELPER_REQUEST, link);
        if (req->command == OVS_IP_HELPER_FWD_REQUEST &&
            (nbl == NULL || req->fwdReq.nbl == nbl)) {
            RemoveEntryList(link);
            InsertHeadList(&list, link);
            if (nbl != NULL) {
                break;
            }
        }
    }
    NdisReleaseSpinLock(&ovsIpHelperLock);

    LIST_FORALL_SAFE(&list, link, next) {
        req = CONTAINING_RECORD(link, OVS_IP_HELPER_REQUEST, link);
        if (req->fwdReq.cb) {
            req->fwdReq.cb(req->fwdReq.nbl, req->fwdReq.inPort,
                           &req->fwdReq.tunnelKey,
                           req->fwdReq.cbData1,
                           req->fwdReq.cbData2,
                           STATUS_DEVICE_NOT_READY,
                           NULL);
        }
        OvsFreeMemoryWithTag(req, OVS_IPHELPER_POOL_TAG);
    }
}
