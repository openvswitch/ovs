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

#ifndef __IP_HELPER_H_
#define __IP_HELPER_H_ 1

#include <ntddk.h>
#include <netioapi.h>
#include "Vport.h"

#define OVS_FWD_HASH_TABLE_SIZE ((UINT32)1 << 10)
#define OVS_FWD_HASH_TABLE_MASK (OVS_FWD_HASH_TABLE_SIZE - 1)

#define OVS_ROUTE_HASH_TABLE_SIZE ((UINT32)1 << 8)
#define OVS_ROUTE_HASH_TABLE_MASK (OVS_ROUTE_HASH_TABLE_SIZE - 1)

#define OVS_NEIGH_HASH_TABLE_SIZE ((UINT32)1 << 8)
#define OVS_NEIGH_HASH_TABLE_MASK (OVS_NEIGH_HASH_TABLE_SIZE - 1)

#define OVS_IPNEIGH_TIMEOUT 100000000   // 10 s

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
    SOCKADDR_INET       ipAddress;
    ERESOURCE           lock;
} OVS_IPHELPER_INSTANCE, *POVS_IPHELPER_INSTANCE;


typedef struct _OVS_IPNEIGH_ENTRY {
    UINT8                       macAddr[ETH_ADDR_LEN];
    UINT16                      refCount;
    SOCKADDR_INET               ipAddr;
    UINT32                      pad;
    UINT64                      timeout;
    LIST_ENTRY                  link;
    LIST_ENTRY                  slink;
    LIST_ENTRY                  fwdList;
    POVS_IPHELPER_INSTANCE      instance;
} OVS_IPNEIGH_ENTRY, *POVS_IPNEIGH_ENTRY;

typedef struct _OVS_IPFORWARD_ENTRY {
    IP_ADDRESS_PREFIX prefix;
    SOCKADDR_INET     nextHop;
    UINT16            refCount;
    LIST_ENTRY        link;
    LIST_ENTRY        fwdList;
} OVS_IPFORWARD_ENTRY, *POVS_IPFORWARD_ENTRY;

typedef union _OVS_FWD_INFO {
    struct {
        SOCKADDR_INET   dstIphAddr;
        SOCKADDR_INET   srcIphAddr;
        UINT8         dstMacAddr[ETH_ADDR_LEN];
        UINT8         srcMacAddr[ETH_ADDR_LEN];
        UINT32        srcPortNo;
        POVS_VPORT_ENTRY   vport;
    };
    UINT64            value[10];
} OVS_FWD_INFO, *POVS_FWD_INFO;

typedef struct _OVS_FWD_ENTRY {
    OVS_FWD_INFO      info;
    POVS_IPFORWARD_ENTRY ipf;
    POVS_IPNEIGH_ENTRY   ipn;
    LIST_ENTRY        link;
    LIST_ENTRY        ipfLink;
    LIST_ENTRY        ipnLink;
} OVS_FWD_ENTRY, *POVS_FWD_ENTRY;

enum {
    OVS_IP_HELPER_INTERNAL_ADAPTER_UP,
    OVS_IP_HELPER_INTERNAL_ADAPTER_DOWN,
    OVS_IP_HELPER_FWD_REQUEST,
};

typedef VOID (*OvsIPHelperCallback)(PNET_BUFFER_LIST nbl,
                                    UINT32 inPort,
                                    PVOID tunnelKey,
                                    PVOID cbData1,
                                    PVOID cbData2,
                                    NTSTATUS status,
                                    POVS_FWD_INFO fwdInfo);

typedef struct _OVS_FWD_REQUEST_INFO {
    PNET_BUFFER_LIST  nbl;
    UINT32            inPort;
    OvsIPTunnelKey    tunnelKey;
    OvsIPHelperCallback cb;
    PVOID             cbData1;
    PVOID             cbData2;
} OVS_FWD_REQUEST_INFO, *POVS_FWD_REQUEST_INFO;

typedef struct _OVS_INSTANCE_REQUEST_INFO {
    GUID              netCfgInstanceId;
    UINT32            portNo;
} OVS_INSTANCE_REQUEST_INFO, *POVS_INSTANCE_REQUEST_INFO;

typedef struct _OVS_IP_HELPER_REQUEST {
    LIST_ENTRY        link;
    UINT32            command;
    union {
        OVS_FWD_REQUEST_INFO        fwdReq;
        OVS_INSTANCE_REQUEST_INFO   instanceReq;
    };
} OVS_IP_HELPER_REQUEST, *POVS_IP_HELPER_REQUEST;


typedef struct _OVS_IP_HELPER_THREAD_CONTEXT {
    KEVENT            event;
    PVOID             threadObject;
    UINT32            exit;
} OVS_IP_HELPER_THREAD_CONTEXT, *POVS_IP_HELPER_THREAD_CONTEXT;

NTSTATUS OvsInitIpHelper(NDIS_HANDLE ndisFilterHandle);
VOID OvsCleanupIpHelper(VOID);

VOID OvsInternalAdapterUp(UINT32 portNo, GUID *netCfgInstanceId);
VOID OvsInternalAdapterDown(UINT32 portNo, GUID netCfgInstanceId);

NTSTATUS OvsFwdIPHelperRequest(PNET_BUFFER_LIST nbl, UINT32 inPort,
                               const PVOID tunnelKey,
                               OvsIPHelperCallback cb,
                               PVOID cbData1,
                               PVOID cbData2);

VOID OvsCancelFwdIpHelperRequest(PNET_BUFFER_LIST nbl);

NTSTATUS
OvsLookupIPhFwdInfo(SOCKADDR_INET srcIp, SOCKADDR_INET dstIp,
                    POVS_FWD_INFO info);

static __inline BOOLEAN
OvsIphAddrEquals(const SOCKADDR_INET *src, const SOCKADDR_INET *dst)
{
    BOOLEAN addrEqual = FALSE;
    if (!src || !dst) return FALSE;

    if (src->si_family == AF_INET &&
        dst->si_family == AF_INET) {
        addrEqual = (src->Ipv4.sin_addr.s_addr == dst->Ipv4.sin_addr.s_addr);
    } else if(src->si_family == AF_INET6 &&
              dst->si_family == AF_INET6) {
        if (RtlEqualMemory(&src->Ipv6.sin6_addr,
                           &dst->Ipv6.sin6_addr,
                           sizeof(src->Ipv6.sin6_addr))) {
           addrEqual = TRUE;
        }
    }
    return addrEqual;
}

/* check if the pointers to SOCKADDR_INET is zero*/
static __inline BOOLEAN
OvsIphIsZero(const SOCKADDR_INET *ipAddr)
{
    BOOLEAN isZero = FALSE;
    UCHAR zeros[16] = { 0 };
    if (!ipAddr)  return FALSE;

    if (ipAddr->si_family == AF_INET ||
        ipAddr->si_family == AF_UNSPEC) {
        isZero = (ipAddr->Ipv4.sin_addr.s_addr == 0);
    } else if(ipAddr->si_family == AF_INET6) {
        if (RtlEqualMemory(&ipAddr->Ipv6.sin6_addr.u.Byte,
                           &zeros,
                           sizeof(ipAddr->Ipv6.sin6_addr))) {
            isZero = TRUE;
        }
    }
    return isZero;
}

/* Copy the content from the pointer to SOCKADDR_INET
 * To the pointer to SOCKADDR_INET
 */
static __inline void
OvsCopyIphAddress(SOCKADDR_INET *dstAddr, const SOCKADDR_INET *srcAddr)
{
    if (!srcAddr || !dstAddr) return;

    dstAddr->si_family = srcAddr->si_family;

    if (srcAddr->si_family == AF_INET) {
        dstAddr->Ipv4.sin_addr.s_addr = srcAddr->Ipv4.sin_addr.s_addr;
    } else if (srcAddr->si_family == AF_INET6) {
        RtlCopyMemory(&dstAddr->Ipv6, &srcAddr->Ipv6,
                      sizeof(srcAddr->Ipv6));
    }
    return;
}

/* compute the hash value based on SOCKADDR_INET*/
uint32_t
OvsJhashIphHdr(const SOCKADDR_INET *iphAddr);

NTSTATUS
OvsConvertWcharToAnsiStr(WCHAR* wStr, size_t wlen,
                         CHAR* str, size_t maxStrLen);
#endif /* __IP_HELPER_H_ */
