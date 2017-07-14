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

extern POVS_SWITCH_CONTEXT gOvsSwitchContext;

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_IPHELPER
#include "Debug.h"

/*
 * IpHelper supports multiple internal adapters.
 */

KSTART_ROUTINE             OvsStartIpHelper;

/* Contains the entries of internal adapter objects. */
static LIST_ENTRY          ovsInstanceList;

/* Passive-level lock used to protect the internal adapter object list. */
static ERESOURCE           ovsInstanceListLock;

/*
 * This structure is used to define each adapter instance.
 *
 * Note:
 * Only when the internal IP is configured and virtual
 * internal port is connected, the IP helper request can be
 * queued.
 *
 * We only keep internal IP for reference, it will not be used for determining
 * SRC IP of the Tunnel.
 *
 * The lock must not raise the IRQL higher than PASSIVE_LEVEL in order for the
 * route manipulation functions, i.e. GetBestRoute, to work.
 */
typedef struct _OVS_IPHELPER_INSTANCE
{
    LIST_ENTRY          link;

    BOOLEAN             isIpConfigured;
    UINT32              portNo;
    GUID                netCfgId;
    MIB_IF_ROW2         internalRow;
    MIB_IPINTERFACE_ROW internalIPRow;
    UINT32              ipAddress;

    ERESOURCE           lock;
} OVS_IPHELPER_INSTANCE, *POVS_IPHELPER_INSTANCE;

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
static VOID OvsRemoveAllFwdEntriesWithPortNo(UINT32 portNo);
static VOID OvsCleanupIpHelperRequestList(VOID);
static VOID OvsCleanupFwdTable(VOID);
static VOID OvsAddToSortedNeighList(POVS_IPNEIGH_ENTRY ipn);
static POVS_IPHELPER_INSTANCE OvsIpHelperAllocateInstance(
                                               POVS_IP_HELPER_REQUEST request);
static VOID OvsIpHelperDeleteInstance(POVS_IPHELPER_INSTANCE instance);


static VOID
OvsDumpMessageWithGuid(char* message, GUID guid)
{
    OVS_LOG_INFO(message, guid.Data1, guid.Data2, guid.Data3,
                 *(UINT16 *)guid.Data4, guid.Data4[2], guid.Data4[3],
                 guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

static VOID
OvsDumpIfRow(PMIB_IF_ROW2 ifRow)
{
    OVS_LOG_INFO("InterfaceLuid: NetLuidIndex: %d, type: %d",
                 ifRow->InterfaceLuid.Info.NetLuidIndex,
                 ifRow->InterfaceLuid.Info.IfType);
    OVS_LOG_INFO("InterfaceIndex: %d", ifRow->InterfaceIndex);

    OvsDumpMessageWithGuid("Interface GUID: "
                           "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
                           ifRow->InterfaceGuid);
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

    if (ipEntry == NULL) {
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
OvsGetRoute(SOCKADDR_INET *destinationAddress,
            PMIB_IPFORWARD_ROW2 route,
            SOCKADDR_INET *sourceAddress,
            POVS_IPHELPER_INSTANCE *instance,
            POVS_VPORT_ENTRY* vport,
            UINT32 srcIp)
{
    NTSTATUS status = STATUS_NETWORK_UNREACHABLE;
    NTSTATUS result = STATUS_SUCCESS;
    PLIST_ENTRY head, link, next;
    ULONG minMetric = MAXULONG;

    if (destinationAddress == NULL || route == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquireResourceExclusiveLite(&ovsInstanceListLock, TRUE);
    head = &(ovsInstanceList);
    LIST_FORALL_SAFE(head, link, next) {
        SOCKADDR_INET crtSrcAddr = { 0 };
        MIB_IPFORWARD_ROW2 crtRoute = { 0 };
        POVS_IPHELPER_INSTANCE crtInstance = NULL;
        WCHAR interfaceName[IF_MAX_STRING_SIZE + 1];

        crtInstance = CONTAINING_RECORD(link, OVS_IPHELPER_INSTANCE, link);

        ExAcquireResourceExclusiveLite(&crtInstance->lock, TRUE);
        result = GetBestRoute2(&crtInstance->internalRow.InterfaceLuid, 0,
                               NULL, destinationAddress, 0, &crtRoute,
                               &crtSrcAddr);

        if (result != STATUS_SUCCESS) {
            ExReleaseResourceLite(&crtInstance->lock);
            continue;
        }

        if (minMetric > crtRoute.Metric &&
            (!srcIp || srcIp == crtSrcAddr.Ipv4.sin_addr.S_un.S_addr)) {
            status = STATUS_SUCCESS;
            size_t len = 0;
            minMetric = crtRoute.Metric;
            LOCK_STATE_EX lockState;

            RtlCopyMemory(sourceAddress, &crtSrcAddr, sizeof(*sourceAddress));
            RtlCopyMemory(route, &crtRoute, sizeof(*route));
            *instance = crtInstance;

            status =
                ConvertInterfaceLuidToAlias(&crtInstance->internalRow.InterfaceLuid,
                                            interfaceName,
                                            IF_MAX_STRING_SIZE + 1);
            if (NT_SUCCESS(status)) {
                status = RtlStringCbLengthW(interfaceName, IF_MAX_STRING_SIZE,
                                            &len);
            }

            if (gOvsSwitchContext != NULL && NT_SUCCESS(status)) {
                NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock,
                                      &lockState, 0);
                *vport = OvsFindVportByHvNameW(gOvsSwitchContext,
                                               interfaceName,
                                               len);
                NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
            }
        }
        ExReleaseResourceLite(&crtInstance->lock);
    }
    ExReleaseResourceLite(&ovsInstanceListLock);

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
OvsGetOrResolveIPNeigh(PMIB_IF_ROW2 ipRow,
                       UINT32 ipAddr,
                       PMIB_IPNET_ROW2 ipNeigh)
{
    NTSTATUS status;

    ASSERT(ipNeigh);

    RtlZeroMemory(ipNeigh, sizeof (*ipNeigh));
    ipNeigh->InterfaceLuid.Value = ipRow->InterfaceLuid.Value;
    ipNeigh->InterfaceIndex = ipRow->InterfaceIndex;
    ipNeigh->Address.si_family = AF_INET;
    ipNeigh->Address.Ipv4.sin_addr.s_addr = ipAddr;

    status = OvsGetIPNeighEntry(ipNeigh);

    if (status != STATUS_SUCCESS) {
        RtlZeroMemory(ipNeigh, sizeof (*ipNeigh));
        ipNeigh->InterfaceLuid.Value = ipRow->InterfaceLuid.Value;
        ipNeigh->InterfaceIndex = ipRow->InterfaceIndex;
        ipNeigh->Address.si_family = AF_INET;
        ipNeigh->Address.Ipv4.sin_addr.s_addr = ipAddr;
        status = OvsResolveIPNeighEntry(ipNeigh);
    }
    return status;
}

static __inline BOOLEAN
OvsCheckInstanceRow(PMIB_IF_ROW2 instanceRow,
                    PNET_LUID netLuid,
                    NET_IFINDEX ifIndex)
{
    return (instanceRow->InterfaceLuid.Info.NetLuidIndex ==
            netLuid->Info.NetLuidIndex &&
            instanceRow->InterfaceLuid.Info.IfType ==
            netLuid->Info.IfType &&
            instanceRow->InterfaceIndex ==
            ifIndex);
}

static VOID
OvsUpdateIpInterfaceNotification(PMIB_IPINTERFACE_ROW ipRow)
{
    PLIST_ENTRY head, link, next;

    ExAcquireResourceExclusiveLite(&ovsInstanceListLock, TRUE);
    head = &(ovsInstanceList);
    LIST_FORALL_SAFE(head, link, next) {
        POVS_IPHELPER_INSTANCE instance = NULL;

        instance = CONTAINING_RECORD(link, OVS_IPHELPER_INSTANCE, link);

        ExAcquireResourceExclusiveLite(&instance->lock, TRUE);
        if (OvsCheckInstanceRow(&instance->internalRow,
                                &ipRow->InterfaceLuid,
                                ipRow->InterfaceIndex)) {

            /*
             * Update the IP Interface Row
             */
            RtlCopyMemory(&instance->internalIPRow, ipRow,
                          sizeof(PMIB_IPINTERFACE_ROW));
            instance->isIpConfigured = TRUE;

            OVS_LOG_INFO("IP Interface with NetLuidIndex: %d, type: %d is %s",
                         ipRow->InterfaceLuid.Info.NetLuidIndex,
                         ipRow->InterfaceLuid.Info.IfType,
                         "modified");

            ExReleaseResourceLite(&instance->lock);
            break;
        }
        ExReleaseResourceLite(&instance->lock);
    }
    ExReleaseResourceLite(&ovsInstanceListLock);

    return;
}

static VOID
OvsAddIpInterfaceNotification(PMIB_IPINTERFACE_ROW ipRow)
{
    PLIST_ENTRY head, link, next;
    BOOLEAN found = FALSE;

    ExAcquireResourceExclusiveLite(&ovsInstanceListLock, TRUE);
    head = &(ovsInstanceList);
    LIST_FORALL_SAFE(head, link, next) {
        POVS_IPHELPER_INSTANCE instance = NULL;

        instance = CONTAINING_RECORD(link, OVS_IPHELPER_INSTANCE, link);

        ExAcquireResourceExclusiveLite(&instance->lock, TRUE);
        if (OvsCheckInstanceRow(&instance->internalRow, &ipRow->InterfaceLuid,
                                ipRow->InterfaceIndex)) {

            instance->isIpConfigured = FALSE;
            ExReleaseResourceLite(&instance->lock);

            found = TRUE;

            break;
        }
        ExReleaseResourceLite(&instance->lock);
    }
    ExReleaseResourceLite(&ovsInstanceListLock);

    if (found != TRUE) {
        NTSTATUS status;
        POVS_IPHELPER_INSTANCE instance = NULL;
        MIB_UNICASTIPADDRESS_ROW ipEntry;
        BOOLEAN error = TRUE;
        LOCK_STATE_EX lockState;

        instance = (POVS_IPHELPER_INSTANCE)OvsAllocateMemoryWithTag(
            sizeof(*instance), OVS_IPHELPER_POOL_TAG);
        if (instance == NULL) {
            goto error;
        }
        RtlZeroMemory(instance, sizeof(*instance));

        InitializeListHead(&instance->link);
        ExInitializeResourceLite(&instance->lock);
        WCHAR interfaceName[IF_MAX_STRING_SIZE + 1];
        status = ConvertInterfaceLuidToAlias(&ipRow->InterfaceLuid,
                                             interfaceName,
                                             IF_MAX_STRING_SIZE + 1);
        if (gOvsSwitchContext == NULL || !NT_SUCCESS(status)) {
            goto error;
        }
        NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState, 0);
        POVS_VPORT_ENTRY vport = OvsFindVportByHvNameW(gOvsSwitchContext,
                                                       interfaceName,
                                                       sizeof(WCHAR) *
                                                       wcslen(interfaceName));

        if (vport != NULL) {
            RtlCopyMemory(&instance->netCfgId,
                          &vport->netCfgInstanceId,
                          sizeof(instance->netCfgId));
            instance->portNo = vport->portNo;
        }
        NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
        RtlZeroMemory(&instance->internalRow, sizeof(MIB_IF_ROW2));
        RtlZeroMemory(&instance->internalIPRow, sizeof(MIB_IPINTERFACE_ROW));
        status = OvsGetIfEntry(&instance->netCfgId,
                               &instance->internalRow);

        if (status != STATUS_SUCCESS) {
            OvsDumpMessageWithGuid("Fail to get IF entry for internal port with GUID"
                                   "  %08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
                                   instance->netCfgId);
            goto error;
        }

        status = OvsGetIPInterfaceEntry(instance->internalRow.InterfaceLuid,
                                        &instance->internalIPRow);

        if (status == STATUS_SUCCESS) {
            instance->isIpConfigured = TRUE;
        } else {
            goto error;
        }

        status = OvsGetIPEntry(instance->internalRow.InterfaceLuid, &ipEntry);
        if (status != STATUS_SUCCESS) {
            OvsDumpMessageWithGuid("Failed to get IP entry for internal port with GUID"
                                   " %08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
                                   instance->netCfgId);
        }

        ExAcquireResourceExclusiveLite(&ovsInstanceListLock, TRUE);
        InsertHeadList(&ovsInstanceList, &instance->link);
        ExReleaseResourceLite(&ovsInstanceListLock);

        error = FALSE;

error:
        if (error) {
            OvsIpHelperDeleteInstance(instance);
        }
    }

    return;
}

static VOID
OvsRemoveIpInterfaceNotification(PMIB_IPINTERFACE_ROW ipRow)
{
    PLIST_ENTRY head, link, next;

    ExAcquireResourceExclusiveLite(&ovsInstanceListLock, TRUE);
    head = &(ovsInstanceList);
    LIST_FORALL_SAFE(head, link, next) {
        POVS_IPHELPER_INSTANCE instance = NULL;

        instance = CONTAINING_RECORD(link, OVS_IPHELPER_INSTANCE, link);

        ExAcquireResourceExclusiveLite(&instance->lock, TRUE);
        if (OvsCheckInstanceRow(&instance->internalRow, &ipRow->InterfaceLuid,
                                ipRow->InterfaceIndex)) {

            instance->isIpConfigured = FALSE;
            RemoveEntryList(&instance->link);

            ExReleaseResourceLite(&instance->lock);
            OvsIpHelperDeleteInstance(instance);

            OVS_LOG_INFO("IP Interface with NetLuidIndex: %d, type: %d is "\
                         "deleted",
                         ipRow->InterfaceLuid.Info.NetLuidIndex,
                         ipRow->InterfaceLuid.Info.IfType);

            break;
        }
        ExReleaseResourceLite(&instance->lock);
    }
    ExReleaseResourceLite(&ovsInstanceListLock);

    if (IsListEmpty(&ovsInstanceList)) {
        OvsCleanupIpHelperRequestList();
        OvsCleanupFwdTable();
    }

    return;
}

static VOID
OvsChangeCallbackIpInterface(PVOID context,
                             PMIB_IPINTERFACE_ROW ipRow,
                             MIB_NOTIFICATION_TYPE notificationType)
{
    UNREFERENCED_PARAMETER(context);
    switch (notificationType) {
    case MibParameterNotification:
        OvsUpdateIpInterfaceNotification(ipRow);
        break;
    case MibAddInstance:
        OvsAddIpInterfaceNotification(ipRow);
        break;

    case MibDeleteInstance:
        OvsRemoveIpInterfaceNotification(ipRow);
        break;
    case MibInitialNotification:
        OVS_LOG_INFO("Got Initial notification for IP Interface change.");
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
    {
        ASSERT(ipRoute);
        ipAddr = ipRoute->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr;
        nextHop = ipRoute->NextHop.Ipv4.sin_addr.s_addr;

        POVS_IPFORWARD_ENTRY ipf;
        LOCK_STATE_EX lockState;

        NdisAcquireRWLockWrite(ovsTableLock, &lockState, 0);
        ipf = OvsLookupIPForwardEntry(&ipRoute->DestinationPrefix);
        if (ipf != NULL) {
            OvsRemoveIPForwardEntry(ipf);
        }
        NdisReleaseRWLock(ovsTableLock, &lockState);

        OVS_LOG_INFO("IPRoute: To %d.%d.%d.%d/%d through %d.%d.%d.%d %s.",
                     ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                     (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff,
                     ipRoute->DestinationPrefix.PrefixLength,
                     nextHop & 0xff, (nextHop >> 8) & 0xff,
                     (nextHop >> 16) & 0xff, (nextHop >> 24) & 0xff,
                     notificationType == MibDeleteInstance ? "deleted" :
                     "modified");
        break;
    }

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
    {
        PLIST_ENTRY head, link, next;

        ASSERT(unicastRow);
        ipAddr = unicastRow->Address.Ipv4.sin_addr.s_addr;

        ExAcquireResourceExclusiveLite(&ovsInstanceListLock, TRUE);
        head = &(ovsInstanceList);
        LIST_FORALL_SAFE(head, link, next) {
            POVS_IPHELPER_INSTANCE instance = NULL;

            instance = CONTAINING_RECORD(link, OVS_IPHELPER_INSTANCE, link);

            ExAcquireResourceExclusiveLite(&instance->lock, TRUE);
            if (instance->isIpConfigured &&
                OvsCheckInstanceRow(&instance->internalRow,
                                    &unicastRow->InterfaceLuid,
                                    unicastRow->InterfaceIndex)) {

                instance->ipAddress = ipAddr;

                OVS_LOG_INFO("IP Address: %d.%d.%d.%d is %s",
                             ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                             (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff,
                             notificationType == MibAddInstance ? "added": "modified");

                ExReleaseResourceLite(&instance->lock);
                break;
            }
            ExReleaseResourceLite(&instance->lock);
        }
        ExReleaseResourceLite(&ovsInstanceListLock);

        break;
    }

    case MibDeleteInstance:
    {
        PLIST_ENTRY head, link, next;
        LOCK_STATE_EX lockState;
        BOOLEAN found = FALSE;

        ASSERT(unicastRow);
        ipAddr = unicastRow->Address.Ipv4.sin_addr.s_addr;

        ExAcquireResourceExclusiveLite(&ovsInstanceListLock, TRUE);
        head = &(ovsInstanceList);
        LIST_FORALL_SAFE(head, link, next) {
            POVS_IPHELPER_INSTANCE instance = NULL;

            instance = CONTAINING_RECORD(link, OVS_IPHELPER_INSTANCE, link);

            ExAcquireResourceExclusiveLite(&instance->lock, TRUE);
            if (instance->isIpConfigured &&
                OvsCheckInstanceRow(&instance->internalRow,
                                    &unicastRow->InterfaceLuid,
                                    unicastRow->InterfaceIndex)) {

                found = TRUE;

                ExReleaseResourceLite(&instance->lock);
                break;
            }
            ExReleaseResourceLite(&instance->lock);
        }
        ExReleaseResourceLite(&ovsInstanceListLock);

        if (found) {
            NdisAcquireRWLockWrite(ovsTableLock, &lockState, 0);
            OvsRemoveAllFwdEntriesWithSrc(ipAddr);
            NdisReleaseRWLock(ovsTableLock, &lockState);

            OVS_LOG_INFO("IP Address removed: %d.%d.%d.%d",
                         ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                         (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff);
        }

        break;
    }

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
    UINT dummy = 0;


    status = NotifyIpInterfaceChange(AF_INET, OvsChangeCallbackIpInterface,
                                     NULL, TRUE,
                                     &ipInterfaceNotificationHandle);
    if (status != STATUS_SUCCESS) {
        OVS_LOG_ERROR("Fail to register Notify IP interface change, status:%x.",
                      status);
        return status;
    }

    /* The CallerContext is dummy and should never be used */
    status = NotifyRouteChange2(AF_INET, OvsChangeCallbackIpRoute, &dummy,
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
    UINT32 hash = OvsJhashWords(&ipAddr, 1, OVS_HASH_BASIS);

    LIST_FORALL(&ovsNeighHashTable[hash & OVS_NEIGH_HASH_TABLE_MASK], link) {
        POVS_IPNEIGH_ENTRY entry;

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
    UINT32 hash;
    ASSERT(prefix->Prefix.si_family == AF_INET);

    hash = RtlUlongByteSwap(prefix->Prefix.Ipv4.sin_addr.s_addr);

    ASSERT(prefix->PrefixLength >= 32 ||
           (hash & (((UINT32)1 <<  (32 - prefix->PrefixLength)) - 1)) == 0);

    hash = OvsHashIPPrefix(prefix);
    LIST_FORALL(&ovsRouteHashTable[hash & OVS_ROUTE_HASH_TABLE_MASK], link) {
        POVS_IPFORWARD_ENTRY ipfEntry;

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
OvsLookupIPFwdEntry(UINT32 srcIp, UINT32 dstIp)
{
    PLIST_ENTRY link;
    UINT32 hash = OvsJhashWords(&dstIp, 1, OVS_HASH_BASIS);

    LIST_FORALL(&ovsFwdHashTable[hash & OVS_FWD_HASH_TABLE_MASK], link) {
        POVS_FWD_ENTRY entry;

        entry = CONTAINING_RECORD(link, OVS_FWD_ENTRY, link);
        if (entry->info.dstIpAddr == dstIp &&
            (!srcIp || entry->info.srcIpAddr == srcIp)) {
            return entry;
        }
    }
    return NULL;
}


NTSTATUS
OvsLookupIPFwdInfo(UINT32 srcIp,
                   UINT32 dstIp,
                   POVS_FWD_INFO info)
{
    POVS_FWD_ENTRY entry;
    LOCK_STATE_EX lockState;
    NTSTATUS status = STATUS_NOT_FOUND;

    NdisAcquireRWLockRead(ovsTableLock, &lockState, 0);
    entry = OvsLookupIPFwdEntry(srcIp, dstIp);
    if (entry) {
        RtlCopyMemory(info->value, entry->info.value,
                      sizeof entry->info.value);
        status = STATUS_SUCCESS;
    }
    NdisReleaseRWLock(ovsTableLock, &lockState);
    return status;
}


static POVS_IPNEIGH_ENTRY
OvsCreateIPNeighEntry(PMIB_IPNET_ROW2 ipNeigh,
                      POVS_IPHELPER_INSTANCE instance)
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
    entry->context = (PVOID)instance;

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
    PLIST_ENTRY link, next;

    ipf->refCount++;

    LIST_FORALL_SAFE(&ipf->fwdList, link, next) {
        POVS_FWD_ENTRY fwdEntry;

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

    ipn->refCount++;

    LIST_FORALL_SAFE(&ipn->fwdList, link, next) {
        POVS_FWD_ENTRY fwdEntry;

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

    if (!IsListEmpty(&ovsSortedIPNeighList)) {
        link = ovsSortedIPNeighList.Blink;
        POVS_IPNEIGH_ENTRY entry;
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
    PLIST_ENTRY link, next;

    for (i = 0; i < OVS_FWD_HASH_TABLE_SIZE; i++) {
        LIST_FORALL_SAFE(&ovsFwdHashTable[i], link, next) {
            POVS_FWD_ENTRY fwdEntry;

            fwdEntry = CONTAINING_RECORD(link, OVS_FWD_ENTRY, link);
            if (fwdEntry->info.srcIpAddr == ipAddr) {
                OvsRemoveFwdEntry(fwdEntry);
            }
        }
    }
}


static VOID
OvsRemoveAllFwdEntriesWithPortNo(UINT32 portNo)
{
    UINT32 i;
    PLIST_ENTRY link, next;

    for (i = 0; i < OVS_FWD_HASH_TABLE_SIZE; i++) {
        LIST_FORALL_SAFE(&ovsFwdHashTable[i], link, next) {
            POVS_FWD_ENTRY fwdEntry;

            fwdEntry = CONTAINING_RECORD(link, OVS_FWD_ENTRY, link);
            if (fwdEntry->info.srcPortNo == portNo) {
                OvsRemoveFwdEntry(fwdEntry);
            }
        }
    }
}

static VOID
OvsCleanupFwdTable(VOID)
{
    PLIST_ENTRY link, next;
    UINT32 i;
    LOCK_STATE_EX lockState;

    NdisAcquireRWLockWrite(ovsTableLock, &lockState, 0);
    if (ovsNumFwdEntries) {
        LIST_FORALL_SAFE(&ovsSortedIPNeighList, link, next) {
            POVS_IPNEIGH_ENTRY ipn;

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

    NdisAcquireSpinLock(&ovsIpHelperLock);
    InitializeListHead(&list);
    OvsAppendList(&list, &ovsIpHelperRequestList);
    ovsNumIpHelperRequests = 0;
    NdisReleaseSpinLock(&ovsIpHelperLock);

    LIST_FORALL_SAFE(&list, link, next) {
        POVS_IP_HELPER_REQUEST request;

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
OvsInternalAdapterDown(UINT32 portNo,
                       GUID netCfgInstanceId)
{
    POVS_IP_HELPER_REQUEST request;

    request = (POVS_IP_HELPER_REQUEST)OvsAllocateMemoryWithTag(
        sizeof(OVS_IP_HELPER_REQUEST), OVS_IPHELPER_POOL_TAG);
    if (request == NULL) {
        OVS_LOG_ERROR("Fail to initialize Internal Adapter");
        return;
    }
    RtlZeroMemory(request, sizeof (OVS_IP_HELPER_REQUEST));
    RtlCopyMemory(&request->instanceReq.netCfgInstanceId,
                  &netCfgInstanceId,
                  sizeof(netCfgInstanceId));
    request->command = OVS_IP_HELPER_INTERNAL_ADAPTER_DOWN;
    request->instanceReq.portNo = portNo;

    NdisAcquireSpinLock(&ovsIpHelperLock);
    InsertHeadList(&ovsIpHelperRequestList, &request->link);
    ovsNumIpHelperRequests++;
    if (ovsNumIpHelperRequests == 1) {
        OvsWakeupIPHelper();
    }
    NdisReleaseSpinLock(&ovsIpHelperLock);
}


VOID
OvsInternalAdapterUp(UINT32 portNo,
                     GUID *netCfgInstanceId)
{
    POVS_IP_HELPER_REQUEST request;

    request = (POVS_IP_HELPER_REQUEST)OvsAllocateMemoryWithTag(
        sizeof(OVS_IP_HELPER_REQUEST), OVS_IPHELPER_POOL_TAG);
    if (request == NULL) {
        OVS_LOG_ERROR("Fail to initialize Internal Adapter");
        return;
    }
    RtlZeroMemory(request, sizeof (OVS_IP_HELPER_REQUEST));
    RtlCopyMemory(&request->instanceReq.netCfgInstanceId,
                  netCfgInstanceId,
                  sizeof(*netCfgInstanceId));
    request->command = OVS_IP_HELPER_INTERNAL_ADAPTER_UP;
    request->instanceReq.portNo = portNo;

    NdisAcquireSpinLock(&ovsIpHelperLock);
    InsertHeadList(&ovsIpHelperRequestList, &request->link);
    ovsNumIpHelperRequests++;
    if (ovsNumIpHelperRequests == 1) {
        NdisReleaseSpinLock(&ovsIpHelperLock);
        OvsWakeupIPHelper();
    } else {
        NdisReleaseSpinLock(&ovsIpHelperLock);
    }
}


static POVS_IPHELPER_INSTANCE
OvsIpHelperAllocateInstance(POVS_IP_HELPER_REQUEST request)
{
    POVS_IPHELPER_INSTANCE instance = NULL;

    instance = (POVS_IPHELPER_INSTANCE)OvsAllocateMemoryWithTag(
        sizeof(*instance), OVS_IPHELPER_POOL_TAG);
    if (instance) {
        RtlZeroMemory(instance, sizeof(*instance));

        RtlCopyMemory(&instance->netCfgId,
                      &request->instanceReq.netCfgInstanceId,
                      sizeof(instance->netCfgId));
        instance->portNo = request->instanceReq.portNo;

        InitializeListHead(&instance->link);
        ExInitializeResourceLite(&instance->lock);
    }

    return instance;
}


static VOID
OvsIpHelperDeleteInstance(POVS_IPHELPER_INSTANCE instance)
{
    if (instance) {
        ExDeleteResourceLite(&instance->lock);
        OvsFreeMemoryWithTag(instance, OVS_IPHELPER_POOL_TAG);
    }
}


static VOID
OvsIpHelperDeleteAllInstances()
{
    PLIST_ENTRY head, link, next;

    ExAcquireResourceExclusiveLite(&ovsInstanceListLock, TRUE);
    head = &ovsInstanceList;
    if (!IsListEmpty(head)) {
        LIST_FORALL_SAFE(head, link, next) {
            POVS_IPHELPER_INSTANCE instance = NULL;
            instance = CONTAINING_RECORD(link, OVS_IPHELPER_INSTANCE, link);

            ExAcquireResourceExclusiveLite(&instance->lock, TRUE);

            instance->isIpConfigured = FALSE;
            RemoveEntryList(&instance->link);

            ExReleaseResourceLite(&instance->lock);

            OvsIpHelperDeleteInstance(instance);
        }
    }
    ExReleaseResourceLite(&ovsInstanceListLock);
}


static VOID
OvsHandleInternalAdapterUp(POVS_IP_HELPER_REQUEST request)
{
    NTSTATUS status;
    POVS_IPHELPER_INSTANCE instance = NULL;
    MIB_UNICASTIPADDRESS_ROW ipEntry;
    BOOLEAN error = TRUE;

    do {
        instance = OvsIpHelperAllocateInstance(request);
        if (instance == NULL) {
            break;
        }
        RtlZeroMemory(&instance->internalRow, sizeof(MIB_IF_ROW2));
        RtlZeroMemory(&instance->internalIPRow, sizeof(MIB_IPINTERFACE_ROW));
        status = OvsGetIfEntry(&instance->netCfgId,
                               &instance->internalRow);

        if (status != STATUS_SUCCESS) {
            OvsDumpMessageWithGuid("Fail to get IF entry for internal port with GUID"
                                   "  %08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
                                   instance->netCfgId);
            break;
        }

        status = OvsGetIPInterfaceEntry(instance->internalRow.InterfaceLuid,
                                        &instance->internalIPRow);

        if (status == STATUS_SUCCESS) {
            instance->isIpConfigured = TRUE;
        } else {
            break;
        }

        status = OvsGetIPEntry(instance->internalRow.InterfaceLuid, &ipEntry);
        if (status != STATUS_SUCCESS) {
            OvsDumpMessageWithGuid("Fail to get IP entry for internal port with GUID"
                                   "  %08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
                                   instance->netCfgId);
        }

        ExAcquireResourceExclusiveLite(&ovsInstanceListLock, TRUE);
        InsertHeadList(&ovsInstanceList, &instance->link);
        ExReleaseResourceLite(&ovsInstanceListLock);

        error = FALSE;
    } while (error);

    OvsFreeMemoryWithTag(request, OVS_IPHELPER_POOL_TAG);
    if (error) {
        OvsIpHelperDeleteInstance(instance);
    }
}


static NTSTATUS
OvsEnqueueIpHelperRequest(POVS_IP_HELPER_REQUEST request)
{
    if (IsListEmpty(&ovsInstanceList)) {
        OvsFreeMemoryWithTag(request, OVS_IPHELPER_POOL_TAG);
        return STATUS_NDIS_ADAPTER_NOT_READY;
    } else {
        NdisAcquireSpinLock(&ovsIpHelperLock);
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
    NTSTATUS status;
    MIB_IPFORWARD_ROW2 ipRoute;
    MIB_IPNET_ROW2 ipNeigh;
    OVS_FWD_INFO fwdInfo = { 0 };
    UINT32 ipAddr;
    UINT32 srcAddr;
    POVS_FWD_ENTRY fwdEntry = NULL;
    POVS_IPFORWARD_ENTRY ipf = NULL;
    POVS_IPNEIGH_ENTRY ipn = NULL;
    LOCK_STATE_EX lockState;
    BOOLEAN  newIPF = FALSE;
    BOOLEAN  newIPN = FALSE;
    BOOLEAN  newFWD = FALSE;
    POVS_IPHELPER_INSTANCE instance = NULL;

    status = OvsLookupIPFwdInfo(request->fwdReq.tunnelKey.src,
                                request->fwdReq.tunnelKey.dst,
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

    status = OvsGetRoute(&dst, &ipRoute, &src, &instance, &fwdInfo.vport, request->fwdReq.tunnelKey.src);
    if (request->fwdReq.tunnelKey.src && request->fwdReq.tunnelKey.src != src.Ipv4.sin_addr.s_addr) {
        UINT32 tempAddr = dst.Ipv4.sin_addr.s_addr;
        OVS_LOG_INFO("Fail to get route to %d.%d.%d.%d, status: %x",
                     tempAddr & 0xff, (tempAddr >> 8) & 0xff,
                     (tempAddr >> 16) & 0xff, (tempAddr >> 24) & 0xff, status);
        goto fwd_handle_nbl;
    }
    if (status != STATUS_SUCCESS || instance == NULL) {
        UINT32 tempAddr = dst.Ipv4.sin_addr.s_addr;
        OVS_LOG_INFO("Fail to get route to %d.%d.%d.%d, status: %x",
                     tempAddr & 0xff, (tempAddr >> 8) & 0xff,
                     (tempAddr >> 16) & 0xff, (tempAddr >> 24) & 0xff, status);
        goto fwd_handle_nbl;
    }

    ExAcquireResourceExclusiveLite(&instance->lock, TRUE);
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
    ipNeigh.InterfaceLuid.Value = instance->internalRow.InterfaceLuid.Value;
    if (ipAddr == 0) {
        ipAddr = request->fwdReq.tunnelKey.dst;
    }
    status = OvsGetOrResolveIPNeigh(&instance->internalRow,
                                    ipAddr, &ipNeigh);
    if (status != STATUS_SUCCESS) {
        ExReleaseResourceLite(&instance->lock);
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
            ExReleaseResourceLite(&instance->lock);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto fwd_handle_nbl;
        }
        newIPF = TRUE;
    } else {
        PLIST_ENTRY link;
        link = ipf->fwdList.Flink;
        fwdEntry = CONTAINING_RECORD(link, OVS_FWD_ENTRY, ipfLink);
        if (fwdEntry->info.srcIpAddr != srcAddr) {
            OvsRemoveFwdEntry(fwdEntry);
            NdisReleaseRWLock(ovsTableLock, &lockState);
            ExReleaseResourceLite(&instance->lock);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto fwd_handle_nbl;
        }
        srcAddr = fwdEntry->info.srcIpAddr;
    }

    /*
     * initialize ipn
     */
    if (ipn == NULL) {
        ipn = OvsLookupIPNeighEntry(ipAddr);
        if (ipn == NULL) {
            ipn = OvsCreateIPNeighEntry(&ipNeigh, instance);
            if (ipn == NULL) {
                NdisReleaseRWLock(ovsTableLock, &lockState);
                ExReleaseResourceLite(&instance->lock);
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
    RtlCopyMemory(fwdInfo.srcMacAddr, instance->internalRow.PhysicalAddress,
                  ETH_ADDR_LEN);
    fwdInfo.srcPortNo = request->fwdReq.inPort;

    fwdEntry = OvsCreateFwdEntry(&fwdInfo);
    if (fwdEntry == NULL) {
        NdisReleaseRWLock(ovsTableLock, &lockState);
        ExReleaseResourceLite(&instance->lock);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto fwd_handle_nbl;
    }
    newFWD = TRUE;
    if (status == STATUS_SUCCESS) {
        /*
         * Cache the result
         */
        OvsAddIPFwdCache(fwdEntry, ipf, ipn);
        NdisReleaseRWLock(ovsTableLock, &lockState);
        ExReleaseResourceLite(&instance->lock);
    }

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
            POVS_FWD_ENTRY fwdEntry;
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

/*
 *----------------------------------------------------------------------------
 *  IP Helper system thread handles the following requests:
 *    1. Intialize Internal port row when internal port is connected
 *    2. Handle FWD request
 *    3. Handle IP Neigh timeout
 *
 *    IP Interface, unicast address, and IP route change will be handled
 *    by the revelant callbacks.
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
    PLARGE_INTEGER threadSleepTimeout;

    OVS_LOG_INFO("Start the IP Helper Thread, context: %p", context);

    NdisAcquireSpinLock(&ovsIpHelperLock);
    while (!context->exit) {

        threadSleepTimeout = NULL;
        timeout = 0;
        while (!IsListEmpty(&ovsIpHelperRequestList)) {
            if (context->exit) {
                goto ip_helper_wait;
            }
            link = ovsIpHelperRequestList.Flink;
            RemoveEntryList(link);
            ovsNumIpHelperRequests--;
            NdisReleaseSpinLock(&ovsIpHelperLock);
            req = CONTAINING_RECORD(link, OVS_IP_HELPER_REQUEST, link);
            switch (req->command) {
            case OVS_IP_HELPER_INTERNAL_ADAPTER_UP:
                OvsHandleInternalAdapterUp(req);
                break;
            case OVS_IP_HELPER_INTERNAL_ADAPTER_DOWN:
            {
                PLIST_ENTRY head, current, next;
                UINT32 portNo = req->instanceReq.portNo;
                GUID netCfgInstanceId = req->instanceReq.netCfgInstanceId;

                ExAcquireResourceExclusiveLite(&ovsInstanceListLock, TRUE);
                head = &ovsInstanceList;
                LIST_FORALL_SAFE(head, current, next) {
                    POVS_IPHELPER_INSTANCE instance = NULL;
                    LOCK_STATE_EX lockState;

                    instance = CONTAINING_RECORD(current, OVS_IPHELPER_INSTANCE,
                                                 link);

                    ExAcquireResourceExclusiveLite(&instance->lock, TRUE);
                    if (instance->portNo == portNo &&
                        IsEqualGUID(&instance->netCfgId, &netCfgInstanceId)) {

                        NdisAcquireRWLockWrite(ovsTableLock, &lockState, 0);
                        OvsRemoveAllFwdEntriesWithPortNo(instance->portNo);
                        NdisReleaseRWLock(ovsTableLock, &lockState);

                        RemoveEntryList(&instance->link);

                        ExReleaseResourceLite(&instance->lock);

                        OvsIpHelperDeleteInstance(instance);
                        break;
                    }
                    ExReleaseResourceLite(&instance->lock);
                }

                if (IsListEmpty(&ovsInstanceList)) {
                    OvsCleanupIpHelperRequestList();

                    OvsCleanupFwdTable();
                }
                ExReleaseResourceLite(&ovsInstanceListLock);
            }
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
                threadSleepTimeout = (PLARGE_INTEGER)&timeout;
                break;
            }
            ipAddr = ipn->ipAddr;
            MIB_IPNET_ROW2 ipNeigh;
            NTSTATUS status;
            POVS_IPHELPER_INSTANCE instance = (POVS_IPHELPER_INSTANCE)ipn->context;
            NdisReleaseSpinLock(&ovsIpHelperLock);
            ExAcquireResourceExclusiveLite(&ovsInstanceListLock, TRUE);

            status = OvsGetOrResolveIPNeigh(&instance->internalRow,
                                            ipAddr, &ipNeigh);
            OvsUpdateIPNeighEntry(ipAddr, &ipNeigh, status);

            ExReleaseResourceLite(&ovsInstanceListLock);

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

        /*
         * Wait indefinitely for the thread to be woken up.
         * Passing NULL as the Timeout value in the below
         * call to KeWaitForSingleObject achieves this.
         */
        KeWaitForSingleObject(&context->event, Executive, KernelMode,
                              FALSE, threadSleepTimeout);
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
    NTSTATUS status = NDIS_STATUS_SUCCESS;
    HANDLE threadHandle;
    UINT32 i;

    ovsFwdHashTable = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_FWD_HASH_TABLE_SIZE, OVS_IPHELPER_POOL_TAG);

    ovsRouteHashTable = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_ROUTE_HASH_TABLE_SIZE, OVS_IPHELPER_POOL_TAG);

    ovsNeighHashTable = (PLIST_ENTRY)OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * OVS_NEIGH_HASH_TABLE_SIZE, OVS_IPHELPER_POOL_TAG);

    InitializeListHead(&ovsSortedIPNeighList);

    ovsTableLock = NdisAllocateRWLock(ndisFilterHandle);
    NdisAllocateSpinLock(&ovsIpHelperLock);

    InitializeListHead(&ovsIpHelperRequestList);
    ovsNumIpHelperRequests = 0;
    ipInterfaceNotificationHandle = NULL;
    ipRouteNotificationHandle = NULL;
    unicastIPNotificationHandle = NULL;

    ExInitializeResourceLite(&ovsInstanceListLock);
    InitializeListHead(&ovsInstanceList);

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
        ExDeleteResourceLite(&ovsInstanceListLock);
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

    OvsIpHelperDeleteAllInstances();
    ExDeleteResourceLite(&ovsInstanceListLock);
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
