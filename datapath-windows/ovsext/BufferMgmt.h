/*
 * Copyright (c) 2014, 2016 VMware, Inc.
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

#ifndef __BUFFER_MGMT_H_
#define __BUFFER_MGMT_H_ 1

#define MEM_ALIGN                       MEMORY_ALLOCATION_ALIGNMENT
#define MEM_ALIGN_SIZE(_x)  ((MEM_ALIGN - 1 + (_x))/MEM_ALIGN * MEM_ALIGN)
#define OVS_CTX_MAGIC                   0xabcd

#define OVS_DEFAULT_NBL_CONTEXT_SIZE    MEM_ALIGN_SIZE(64)
#define OVS_DEFAULT_NBL_CONTEXT_FILL    \
      (OVS_DEFAULT_NBL_CONTEXT_SIZE - sizeof (OVS_BUFFER_CONTEXT))

#define OVS_DEFAULT_DATA_SIZE           256
#define OVS_DEFAULT_HEADROOM_SIZE       128
#define OVS_FIX_NBL_DATA_SIZE    (OVS_DEFAULT_DATA_SIZE + OVS_DEFAULT_HEADROOM_SIZE)

/* Default we copy 18 bytes, to make sure ethernet header and vlan is in
 * continuous buffer */
#define OVS_DEFAULT_COPY_SIZE          18

enum {
    OVS_BUFFER_NEED_COMPLETE            = BIT16(0),
    OVS_BUFFER_PRIVATE_MDL              = BIT16(1),
    OVS_BUFFER_PRIVATE_DATA             = BIT16(2),
    OVS_BUFFER_PRIVATE_NET_BUFFER       = BIT16(3),
    OVS_BUFFER_PRIVATE_FORWARD_CONTEXT  = BIT16(4),
    OVS_BUFFER_PRIVATE_CONTEXT          = BIT16(5),
    OVS_BUFFER_FROM_FIX_SIZE_POOL       = BIT16(6),
    OVS_BUFFER_FROM_ZERO_SIZE_POOL      = BIT16(7),
    OVS_BUFFER_FROM_NBL_ONLY_POOL       = BIT16(8),
    OVS_BUFFER_RECV_BUFFER              = BIT16(9),
    OVS_BUFFER_SEND_BUFFER              = BIT16(10),
    OVS_BUFFER_FRAGMENT                 = BIT16(11),
};

typedef union _OVS_BUFFER_CONTEXT {
    struct {
        UINT16 magic;
        UINT16 flags;
        UINT32 srcPortNo;
        UINT32 refCount;
        union {
            UINT32 origDataLength;
            UINT32 dataOffsetDelta;
        };
        UINT16 mru;
    };

    UINT64 value[MEM_ALIGN_SIZE(32) >> 3];
} OVS_BUFFER_CONTEXT, *POVS_BUFFER_CONTEXT;

typedef struct _OVS_NBL_POOL {
    NDIS_SWITCH_CONTEXT ndisContext;
    NDIS_HANDLE   ndisHandle;
    NDIS_HANDLE   fixSizePool;   // data size of 256
    NDIS_HANDLE   zeroSizePool;  // no data, NBL + NB + Context
    NDIS_HANDLE   nblOnlyPool;   // NBL + context for clone
    NDIS_HANDLE   nbPool;        // NB for clone
#ifdef DBG
    LONG          fixNBLCount;
    LONG          zeroNBLCount;
    LONG          nblOnlyCount;
    LONG          nbCount;
    LONG          sysNBLCount;
    LONG          fragNBLCount;
#endif
} OVS_NBL_POOL, *POVS_NBL_POOL;


NDIS_STATUS OvsInitBufferPool(PVOID context);

VOID OvsCleanupBufferPool(PVOID context);

PNET_BUFFER_LIST OvsAllocateFixSizeNBL(PVOID context,
                                       UINT32 size,
                                       UINT32 headRoom);

PNET_BUFFER_LIST OvsAllocateVariableSizeNBL(PVOID context,
                                            UINT32 size,
                                            UINT32 headRoom);

POVS_BUFFER_CONTEXT OvsInitExternalNBLContext(PVOID context,
                                              PNET_BUFFER_LIST nbl,
                                              BOOLEAN isRecv);

PNET_BUFFER_LIST OvsPartialCopyNBL(PVOID context,
                                   PNET_BUFFER_LIST nbl,
                                   UINT32 copySize,
                                   UINT32 headRoom,
                                   BOOLEAN copyNblInfo);
PNET_BUFFER_LIST OvsPartialCopyToMultipleNBLs(PVOID context,
                                              PNET_BUFFER_LIST nbl,
                                              UINT32 copySize,
                                              UINT32 headRoom,
                                              BOOLEAN copyNblInfo);

PNET_BUFFER_LIST OvsFullCopyNBL(PVOID context, PNET_BUFFER_LIST nbl,
                                UINT32 headRoom, BOOLEAN copyNblInfo);

PNET_BUFFER_LIST OvsTcpSegmentNBL(PVOID context,
                                  PNET_BUFFER_LIST nbl,
                                  POVS_PACKET_HDR_INFO hdrInfo,
                                  UINT32 MSS,
                                  UINT32 headRoom,
                                  BOOLEAN isIpFragment);

PNET_BUFFER_LIST OvsFragmentNBL(PVOID context,
                                PNET_BUFFER_LIST nbl,
                                POVS_PACKET_HDR_INFO hdrInfo,
                                UINT32 MSS,
                                UINT32 headRoom,
                                BOOLEAN isIpFragment);

PNET_BUFFER_LIST OvsAllocateNBLFromBuffer(PVOID context,
                                          PVOID buffer,
                                          ULONG length);

PNET_BUFFER_LIST OvsFullCopyToMultipleNBLs(PVOID context, PNET_BUFFER_LIST nbl,
                                           UINT32 headRoom,
                                           BOOLEAN copyNblInfo);

PNET_BUFFER_LIST OvsCompleteNBL(PVOID context, PNET_BUFFER_LIST nbl,
                                BOOLEAN updateRef);

NDIS_STATUS OvsSetCtxSourcePortNo(PNET_BUFFER_LIST nbl, UINT32 portNo);

NDIS_STATUS OvsGetCtxSourcePortNo(PNET_BUFFER_LIST nbl, UINT32 *portNo);

NTSTATUS OvsCreateNewNBLsFromMultipleNBs(PVOID context,
                                         PNET_BUFFER_LIST *curNbl,
                                         PNET_BUFFER_LIST *lastNbl);

#endif /* __BUFFER_MGMT_H_ */
