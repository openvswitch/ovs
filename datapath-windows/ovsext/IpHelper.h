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
#include <Vport.h>

#define OVS_FWD_HASH_TABLE_SIZE ((UINT32)1 << 10)
#define OVS_FWD_HASH_TABLE_MASK (OVS_FWD_HASH_TABLE_SIZE - 1)

#define OVS_ROUTE_HASH_TABLE_SIZE ((UINT32)1 << 8)
#define OVS_ROUTE_HASH_TABLE_MASK (OVS_ROUTE_HASH_TABLE_SIZE - 1)

#define OVS_NEIGH_HASH_TABLE_SIZE ((UINT32)1 << 8)
#define OVS_NEIGH_HASH_TABLE_MASK (OVS_NEIGH_HASH_TABLE_SIZE - 1)

#define OVS_IPNEIGH_TIMEOUT 100000000   // 10 s


typedef struct _OVS_IPNEIGH_ENTRY {
    UINT8             macAddr[ETH_ADDR_LEN];
    UINT16            refCount;
    UINT32            ipAddr;
    UINT32            pad;
    UINT64            timeout;
    LIST_ENTRY        link;
    LIST_ENTRY        slink;
    LIST_ENTRY        fwdList;
    PVOID             context;
} OVS_IPNEIGH_ENTRY, *POVS_IPNEIGH_ENTRY;

typedef struct _OVS_IPFORWARD_ENTRY {
    IP_ADDRESS_PREFIX prefix;
    UINT32            nextHop;
    UINT16            refCount;
    LIST_ENTRY        link;
    LIST_ENTRY        fwdList;
} OVS_IPFORWARD_ENTRY, *POVS_IPFORWARD_ENTRY;

typedef union _OVS_FWD_INFO {
    struct {
        UINT32        dstIpAddr;
        UINT32        srcIpAddr;
        UINT8         dstMacAddr[ETH_ADDR_LEN];
        UINT8         srcMacAddr[ETH_ADDR_LEN];
        UINT32        srcPortNo;
        POVS_VPORT_ENTRY   vport;
    };
    UINT64            value[4];
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
    OvsIPv4TunnelKey  tunnelKey;
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
NTSTATUS OvsLookupIPFwdInfo(UINT32 srcIp, UINT32 dstIp, POVS_FWD_INFO info);
VOID OvsCancelFwdIpHelperRequest(PNET_BUFFER_LIST nbl);

#endif /* __IP_HELPER_H_ */
