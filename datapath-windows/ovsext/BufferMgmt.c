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

/*
 * ****************************************************************************
 *
 *       Simple Buffer Management framework for OVS
 *
 *  It introduces four NDIS buffer pools
 *     **Fix size net buffer list pool--this is used for small buffer
 *     One allocation will include NBL + NB + MDL + Data + CONTEXT.
 *
 *     **Variable size net buffer list pool--this is used for variable size
 *     buffer. The allocation of net buffer list will include NBL + NB +
 *     CONTEXT, a separate allocation of MDL + data buffer is required.
 *
 *     **NBL only net buffer list pool-- this is used for partial copy
 *     (or clone). In this case we can not allocate net buffer list and
 *     net buffer at the same time.
 *
 *     **Net buffer pool-- this is required when net buffer need to be
 *     allocated separately.
 *
 *  A Buffer context is defined to track the buffer specific information
 *  so that during NBL completion, proper action can be taken. Please see
 *  code for details.
 *
 *  Here is the usage of the management API
 *  All external NBL should be initialized its NBL context by calling
 *     OvsInitExternalNBLContext()
 *
 *  After the external NBL context is initialized, it can call the following
 *  API to allocate, copy or partial copy NBL.
 *
 *     OvsAllocateFixSizeNBL()
 *     OvsAllocateVariableSizeNBL()
 *
 *     OvsPartialCopyNBL()
 *     OvsPartialCopyToMultipleNBLs()
 *
 *     OvsFullCopyNBL()
 *     OvsFullCopyToMultipleNBLs()
 *
 *  See code comments for detail description of the functions.
 *
 *  All NBLs is completed through
 *       OvsCompleteNBL()
 *     If this API return non NULL value, then the returned NBL should be
 *     returned to upper layer by calling
 *     NdisFSendNetBufferListsComplete() if the buffer is from upper
 *     layer. In case of WFP, it can call the corresponding completion routine
 *     to return the NBL to the framework.
 *
 *  NOTE:
 *     1. Copy or partial copy will not copy destination port array
 *     2. Copy or partial copy will copy src port id and index
 *     3. New Allocated NBL will have src port set to default port id
 *     4. If original packet has direction flag set, the copied or partial
 *        copied NBL will still be in same direction.
 *     5. When you advance or retreate the buffer, you may need to update
 *        relevant meta data to keep it consistent.
 *
 * ****************************************************************************
 */

#include "precomp.h"
#include "Debug.h"
#include "Flow.h"
#include "Offload.h"
#include "NetProto.h"
#include "PacketIO.h"
#include "PacketParser.h"
#include "Switch.h"
#include "Vport.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_BUFMGMT


/*
 * --------------------------------------------------------------------------
 * OvsInitBufferPool --
 *
 *    Allocate NBL and NB pool
 *
 * XXX: more optimization may be done for buffer management include local cache
 * of NBL, NB, data, context, MDL.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsInitBufferPool(PVOID ovsContext)
{
    POVS_NBL_POOL ovsPool;
    POVS_SWITCH_CONTEXT context = (POVS_SWITCH_CONTEXT)ovsContext;
    NET_BUFFER_LIST_POOL_PARAMETERS  nblParam;
    NET_BUFFER_POOL_PARAMETERS nbParam;

    C_ASSERT(MEMORY_ALLOCATION_ALIGNMENT >= 8);

    OVS_LOG_TRACE("Enter: context: %p", context);

    ovsPool = &context->ovsPool;
    RtlZeroMemory(ovsPool, sizeof (OVS_NBL_POOL));
    ovsPool->ndisHandle = context->NdisFilterHandle;
    ovsPool->ndisContext = context->NdisSwitchContext;
    /*
     * fix size NBL pool includes
     *    NBL + NB + MDL + DATA + Context
     *    This is mainly used for Packet execute or slow path when copy is
     *    required and size is less than OVS_DEFAULT_DATA_SIZE. We expect
     *    Most of packet from user space will use this Pool. (This is
     *    true for all bfd and cfm packet.
     */
    RtlZeroMemory(&nblParam, sizeof (nblParam));
    OVS_INIT_OBJECT_HEADER(&nblParam.Header,
                           NDIS_OBJECT_TYPE_DEFAULT,
                           NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
                           NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1);
    nblParam.ContextSize = OVS_DEFAULT_NBL_CONTEXT_SIZE;
    nblParam.PoolTag = OVS_FIX_SIZE_NBL_POOL_TAG;
    nblParam.fAllocateNetBuffer = TRUE;
    nblParam.DataSize = OVS_DEFAULT_DATA_SIZE + OVS_DEFAULT_HEADROOM_SIZE;

    ovsPool->fixSizePool =
        NdisAllocateNetBufferListPool(context->NdisSwitchContext, &nblParam);
    if (ovsPool->fixSizePool == NULL) {
        goto pool_cleanup;
    }

    /*
     * Zero Size NBL Pool includes
     *    NBL + NB + Context
     *    This is mainly for packet with large data Size, in this case MDL and
     *    Data will be allocate separately.
     */
    RtlZeroMemory(&nblParam, sizeof (nblParam));
    OVS_INIT_OBJECT_HEADER(&nblParam.Header,
                           NDIS_OBJECT_TYPE_DEFAULT,
                           NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
                           NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1);

    nblParam.ContextSize = OVS_DEFAULT_NBL_CONTEXT_SIZE;
    nblParam.PoolTag = OVS_VARIABLE_SIZE_NBL_POOL_TAG;
    nblParam.fAllocateNetBuffer = TRUE;
    nblParam.DataSize = 0;

    ovsPool->zeroSizePool =
        NdisAllocateNetBufferListPool(context->NdisSwitchContext, &nblParam);
    if (ovsPool->zeroSizePool == NULL) {
        goto pool_cleanup;
    }

    /*
     * NBL only pool just includes
     *    NBL (+ context)
     *    This is mainly used for clone and partial copy
     */
    RtlZeroMemory(&nblParam, sizeof (nblParam));
    OVS_INIT_OBJECT_HEADER(&nblParam.Header,
                           NDIS_OBJECT_TYPE_DEFAULT,
                           NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1,
                           NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1);

    nblParam.ContextSize = OVS_DEFAULT_NBL_CONTEXT_SIZE;
    nblParam.PoolTag = OVS_NBL_ONLY_POOL_TAG;
    nblParam.fAllocateNetBuffer = FALSE;
    nblParam.DataSize = 0;

    ovsPool->nblOnlyPool =
        NdisAllocateNetBufferListPool(context->NdisSwitchContext, &nblParam);
    if (ovsPool->nblOnlyPool == NULL) {
        goto pool_cleanup;
    }

    /* nb Pool
     *    NB only pool, used for copy
     */

    OVS_INIT_OBJECT_HEADER(&nbParam.Header,
                           NDIS_OBJECT_TYPE_DEFAULT,
                           NET_BUFFER_POOL_PARAMETERS_REVISION_1,
                           NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1);
    nbParam.PoolTag = OVS_NET_BUFFER_POOL_TAG;
    nbParam.DataSize = 0;
    ovsPool->nbPool =
        NdisAllocateNetBufferPool(context->NdisSwitchContext, &nbParam);
    if (ovsPool->nbPool == NULL) {
        goto pool_cleanup;
    }
    OVS_LOG_TRACE("Exit: fixSizePool: %p zeroSizePool: %p nblOnlyPool: %p"
                  "nbPool: %p", ovsPool->fixSizePool, ovsPool->zeroSizePool,
                  ovsPool->nblOnlyPool, ovsPool->nbPool);
    return NDIS_STATUS_SUCCESS;

pool_cleanup:
    OvsCleanupBufferPool(context);
    OVS_LOG_TRACE("Exit: Fail to initialize ovs buffer pool");
    return NDIS_STATUS_RESOURCES;
}


/*
 * --------------------------------------------------------------------------
 * OvsCleanupBufferPool --
 *  Free Buffer pool for NBL and NB.
 * --------------------------------------------------------------------------
 */
VOID
OvsCleanupBufferPool(PVOID ovsContext)
{
    POVS_NBL_POOL ovsPool;
    POVS_SWITCH_CONTEXT context = (POVS_SWITCH_CONTEXT)ovsContext;
    ovsPool = &context->ovsPool;
    OVS_LOG_TRACE("Enter: context: %p", context);
#ifdef DBG
    ASSERT(ovsPool->fixNBLCount == 0);
    ASSERT(ovsPool->zeroNBLCount == 0);
    ASSERT(ovsPool->nblOnlyCount == 0);
    ASSERT(ovsPool->nbCount == 0);
    ASSERT(ovsPool->sysNBLCount == 0);
    ASSERT(ovsPool->fragNBLCount == 0);
#endif

    if (ovsPool->fixSizePool) {
        NdisFreeNetBufferListPool(ovsPool->fixSizePool);
        ovsPool->fixSizePool = NULL;
    }
    if (ovsPool->zeroSizePool) {
        NdisFreeNetBufferListPool(ovsPool->zeroSizePool);
        ovsPool->zeroSizePool = NULL;
    }
    if (ovsPool->nblOnlyPool) {
        NdisFreeNetBufferListPool(ovsPool->nblOnlyPool);
        ovsPool->nblOnlyPool = NULL;
    }
    if (ovsPool->nbPool) {
        NdisFreeNetBufferPool(ovsPool->nbPool);
        ovsPool->nbPool = NULL;
    }
    OVS_LOG_TRACE("Exit: cleanup OVS Buffer pool");
}


static VOID
OvsInitNBLContext(POVS_BUFFER_CONTEXT ctx,
                  UINT16 flags,
                  UINT32 origDataLength,
                  UINT32 srcPortNo,
                  UINT16 mru)
{
    ctx->magic = OVS_CTX_MAGIC;
    ctx->refCount = 1;
    ctx->flags = flags;
    ctx->srcPortNo = srcPortNo;
    ctx->origDataLength = origDataLength;
    ctx->mru = mru;
    ctx->pendingSend = 0;
}


static VOID
OvsDumpForwardingDetails(PNET_BUFFER_LIST nbl)
{
#if OVS_DBG_DEFAULT >= OVS_DBG_LOUD
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO info;
    info = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(nbl);
    if (info == NULL) {
        return;
    }
    OVS_LOG_INFO("nbl: %p, numAvailableDest: %d, srcId:%d, srcIndex: %d "
                 "isDataSafe: %s, safeDataSize: %d",
                 nbl, info->NumAvailableDestinations, info->SourcePortId,
                 info->SourceNicIndex,
                 info->IsPacketDataSafe ? "TRUE" : "FALSE",
                 info->IsPacketDataSafe ? 0 : info->SafePacketDataSize);
#else
    UNREFERENCED_PARAMETER(nbl);
#endif
}

static VOID
OvsDumpNBLContext(PNET_BUFFER_LIST nbl)
{
#if OVS_DBG_DEFAULT >= OVS_DBG_LOUD
    PNET_BUFFER_LIST_CONTEXT ctx = nbl->Context;
    if (ctx == NULL) {
        OVS_LOG_INFO("No Net Buffer List context");
        return;
    }
    while (ctx) {
        OVS_LOG_INFO("nbl: %p, ctx: %p, TotalSize: %d, Offset: %d",
                     nbl, ctx, ctx->Size, ctx->Offset);
        ctx = ctx->Next;
    }
#else
    UNREFERENCED_PARAMETER(nbl);
#endif
}


static VOID
OvsDumpMDLChain(PMDL mdl)
{
    PMDL tmp;
    tmp = mdl;
    while (tmp) {
        OVS_LOG_INFO("MDL: %p, Size: %d, MappedSystemVa: %p, StartVa: %p"
                     " ByteCount: %d, ByteOffset: %d",
                     tmp, tmp->Size, tmp->MappedSystemVa,
                     tmp->StartVa, tmp->ByteCount, tmp->ByteOffset);
        tmp = tmp->Next;
    }
}


static VOID
OvsDumpNetBuffer(PNET_BUFFER nb)
{
    OVS_LOG_INFO("NET_BUFFER: %p, ChecksumBias: %d Handle: %p, MDLChain: %p "
                 "CurrMDL: %p, CurrOffset: %d, DataLen: %d, Offset: %d",
                 nb,
                 NET_BUFFER_CHECKSUM_BIAS(nb), nb->NdisPoolHandle,
                 NET_BUFFER_FIRST_MDL(nb),
                 NET_BUFFER_CURRENT_MDL(nb),
                 NET_BUFFER_CURRENT_MDL_OFFSET(nb),
                 NET_BUFFER_DATA_LENGTH(nb),
                 NET_BUFFER_DATA_OFFSET(nb));
    OvsDumpMDLChain(NET_BUFFER_FIRST_MDL(nb));
}


static VOID
OvsDumpNetBufferList(PNET_BUFFER_LIST nbl)
{
#if OVS_DBG_DEFAULT >= OVS_DBG_LOUD
    PNET_BUFFER nb;
    OVS_LOG_INFO("NBL: %p, parent: %p, SrcHandle: %p, ChildCount:%d "
                 "poolHandle: %p",
                 nbl, nbl->ParentNetBufferList,
                 nbl->SourceHandle, nbl->ChildRefCount,
                 nbl->NdisPoolHandle);
    OvsDumpNBLContext(nbl);
    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    while (nb) {
        OvsDumpNetBuffer(nb);
        nb = NET_BUFFER_NEXT_NB(nb);
    }
#else
    UNREFERENCED_PARAMETER(nbl);
#endif
}

/*
 * --------------------------------------------------------------------------
 * OvsAllocateFixSizeNBL --
 *
 *    Allocate fix size NBL which include
 *       NBL + NB + MBL + Data + Context
 *    Please note:
 *       * Forwarding Context is allocated, but forwarding detail information
 *       is not initailized.
 *       * The headroom can not be larger than OVS_DEFAULT_HEADROOM_SIZE(128
 *       byte).
 * --------------------------------------------------------------------------
 */
PNET_BUFFER_LIST
OvsAllocateFixSizeNBL(PVOID ovsContext,
                      UINT32 size,
                      UINT32 headRoom)
{
    PNET_BUFFER_LIST nbl = NULL;
    POVS_SWITCH_CONTEXT context = (POVS_SWITCH_CONTEXT)ovsContext;
    POVS_BUFFER_CONTEXT ctx;
    POVS_NBL_POOL ovsPool = &context->ovsPool;
    NDIS_STATUS status;
    UINT32 line;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO info;

    if ((headRoom + size) > OVS_FIX_NBL_DATA_SIZE || size == 0) {
        line = __LINE__;
        goto allocate_done;
    }

    nbl = NdisAllocateNetBufferList(ovsPool->fixSizePool,
                                    (UINT16)sizeof (OVS_BUFFER_CONTEXT),
                                    (UINT16)OVS_DEFAULT_NBL_CONTEXT_FILL);

    if (nbl == NULL) {
        line = __LINE__;
        goto allocate_done;
    }

    nbl->SourceHandle = ovsPool->ndisHandle;
    status = context->NdisSwitchHandlers.
             AllocateNetBufferListForwardingContext(ovsPool->ndisContext, nbl);

    if (status != NDIS_STATUS_SUCCESS) {
        NdisFreeNetBufferList(nbl);
        nbl = NULL;
        line = __LINE__;
        goto allocate_done;
    }
    info = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(nbl);
    ASSERT(info);
    info->IsPacketDataSafe = TRUE;
    info->SourcePortId = NDIS_SWITCH_DEFAULT_PORT_ID;

    status = NdisRetreatNetBufferDataStart(NET_BUFFER_LIST_FIRST_NB(nbl),
                                           size, 0, NULL);
    ASSERT(status == NDIS_STATUS_SUCCESS);

#ifdef DBG
    InterlockedIncrement((LONG volatile *)&ovsPool->fixNBLCount);
    OvsDumpNetBufferList(nbl);
    OvsDumpForwardingDetails(nbl);
#endif

    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
    ASSERT(ctx);

    OvsInitNBLContext(ctx, OVS_BUFFER_FROM_FIX_SIZE_POOL |
                      OVS_BUFFER_PRIVATE_FORWARD_CONTEXT, size,
                      OVS_DPPORT_NUMBER_INVALID, 0);
    line = __LINE__;
allocate_done:
    OVS_LOG_LOUD("Allocate Fix NBL: %p, line: %d", nbl, line);
    return nbl;
}


static PMDL
OvsAllocateMDLAndData(NDIS_HANDLE ndisHandle,
                      UINT32 dataSize)
{
    PMDL mdl;
    PVOID data;

    data = OvsAllocateMemoryWithTag(dataSize, OVS_MDL_POOL_TAG);
    if (data == NULL) {
        return NULL;
    }

    mdl = NdisAllocateMdl(ndisHandle, data, dataSize);
    if (mdl == NULL) {
        OvsFreeMemoryWithTag(data, OVS_MDL_POOL_TAG);
    }

    return mdl;
}


static VOID
OvsFreeMDLAndData(PMDL mdl)
{
    PVOID data;

    data = MmGetMdlVirtualAddress(mdl);
    NdisFreeMdl(mdl);
    OvsFreeMemoryWithTag(data, OVS_MDL_POOL_TAG);
}


/*
 * --------------------------------------------------------------------------
 * OvsAllocateVariableSizeNBL --
 *
 *    Allocate variable size NBL, the NBL looks like
 *      NBL + NB + Context
 *      MDL + Data
 * --------------------------------------------------------------------------
 */
PNET_BUFFER_LIST
OvsAllocateVariableSizeNBL(PVOID ovsContext,
                           UINT32 size,
                           UINT32 headRoom)
{
    PNET_BUFFER_LIST nbl = NULL;
    POVS_SWITCH_CONTEXT context = (POVS_SWITCH_CONTEXT)ovsContext;
    POVS_NBL_POOL ovsPool = &context->ovsPool;
    POVS_BUFFER_CONTEXT ctx;
    UINT32 realSize;
    PMDL mdl;
    NDIS_STATUS status;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO info;
    if (size == 0) {
        return NULL;
    }
    realSize = MEM_ALIGN_SIZE(size + headRoom);

    mdl = OvsAllocateMDLAndData(ovsPool->ndisHandle, realSize);
    if (mdl == NULL) {
        return NULL;
    }

    nbl = NdisAllocateNetBufferAndNetBufferList(ovsPool->zeroSizePool,
                                         (UINT16)sizeof (OVS_BUFFER_CONTEXT),
                                         (UINT16)OVS_DEFAULT_NBL_CONTEXT_FILL,
                                                mdl, realSize, 0);
    if (nbl == NULL) {
        OvsFreeMDLAndData(mdl);
        return NULL;
    }

    nbl->SourceHandle = ovsPool->ndisHandle;
    status = context->NdisSwitchHandlers.
             AllocateNetBufferListForwardingContext(ovsPool->ndisContext, nbl);

    if (status != NDIS_STATUS_SUCCESS) {
       /*
        * do we need to remove mdl from nbl XXX
        */
        OvsFreeMDLAndData(mdl);
        NdisFreeNetBufferList(nbl);
        return NULL;
    }

    info = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(nbl);
    ASSERT(info);
    info->IsPacketDataSafe = TRUE;
    info->SourcePortId = NDIS_SWITCH_DEFAULT_PORT_ID;
    status = NdisRetreatNetBufferDataStart(NET_BUFFER_LIST_FIRST_NB(nbl),
                                           size, 0, NULL);
    ASSERT(status == NDIS_STATUS_SUCCESS);

#ifdef DBG
    InterlockedIncrement((LONG volatile *)&ovsPool->zeroNBLCount);
    OvsDumpNetBufferList(nbl);
    OvsDumpForwardingDetails(nbl);
#endif

    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);

    OvsInitNBLContext(ctx, OVS_BUFFER_PRIVATE_MDL | OVS_BUFFER_PRIVATE_DATA |
                           OVS_BUFFER_PRIVATE_FORWARD_CONTEXT |
                           OVS_BUFFER_FROM_ZERO_SIZE_POOL,
                           size, OVS_DPPORT_NUMBER_INVALID, 0);

    OVS_LOG_LOUD("Allocate variable size NBL: %p", nbl);
    return nbl;
}


/*
 * --------------------------------------------------------------------------
 * OvsInitExternalNBLContext --
 *
 *     For NBL not allocated by OVS, it will allocate and initialize
 *     the NBL context.
 * --------------------------------------------------------------------------
 */
POVS_BUFFER_CONTEXT
OvsInitExternalNBLContext(PVOID ovsContext,
                          PNET_BUFFER_LIST nbl,
                          BOOLEAN isRecv)
{
    NDIS_HANDLE poolHandle;
    POVS_SWITCH_CONTEXT context = (POVS_SWITCH_CONTEXT)ovsContext;
    POVS_BUFFER_CONTEXT ctx;
    PNET_BUFFER nb;
    NDIS_STATUS status;
    UINT16 flags;

    poolHandle = NdisGetPoolFromNetBufferList(nbl);

    if (poolHandle == context->ovsPool.ndisHandle ||
        nbl->SourceHandle == context->ovsPool.ndisHandle) {
        return (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
    }
    status = NdisAllocateNetBufferListContext(nbl, sizeof (OVS_BUFFER_CONTEXT),
                                              OVS_DEFAULT_NBL_CONTEXT_FILL,
                                              OVS_OTHER_POOL_TAG);
    if (status != NDIS_STATUS_SUCCESS) {
        return NULL;
    }
#ifdef DBG
    OvsDumpNBLContext(nbl);
    InterlockedIncrement((LONG volatile *)&context->ovsPool.sysNBLCount);
#endif
    flags = isRecv ? OVS_BUFFER_RECV_BUFFER : OVS_BUFFER_SEND_BUFFER;
    flags |= OVS_BUFFER_NEED_COMPLETE | OVS_BUFFER_PRIVATE_CONTEXT;
    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);

    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    /*
     * we use first nb to decide whether we need advance or retreat during
     * complete.
     */
    OvsInitNBLContext(ctx, flags, NET_BUFFER_DATA_LENGTH(nb),
                      OVS_DPPORT_NUMBER_INVALID, 0);
    return ctx;
}

/*
 * --------------------------------------------------------------------------
 * OvsAllocateNBLContext
 *
 *    Create NBL buffer context and forwarding context.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsAllocateNBLContext(POVS_SWITCH_CONTEXT context,
                      PNET_BUFFER_LIST nbl)
{
    POVS_NBL_POOL ovsPool = &context->ovsPool;
    NDIS_STATUS status;

    status = NdisAllocateNetBufferListContext(nbl,
                                              sizeof (OVS_BUFFER_CONTEXT),
                                              OVS_DEFAULT_NBL_CONTEXT_FILL,
                                              OVS_OTHER_POOL_TAG);
    if (status != NDIS_STATUS_SUCCESS) {
        return NDIS_STATUS_FAILURE;
    }

    nbl->SourceHandle = ovsPool->ndisHandle;
    status = context->NdisSwitchHandlers.
        AllocateNetBufferListForwardingContext(ovsPool->ndisContext, nbl);

    if (status != NDIS_STATUS_SUCCESS) {
        NdisFreeNetBufferListContext(nbl, sizeof (OVS_BUFFER_CONTEXT));
        return NDIS_STATUS_FAILURE;
    }
    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsFreeNBLContext
 *
 *    Free the NBL buffer context and forwarding context.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsFreeNBLContext(POVS_SWITCH_CONTEXT context,
                  PNET_BUFFER_LIST nbl)
{
    POVS_NBL_POOL ovsPool = &context->ovsPool;

    context->NdisSwitchHandlers.
         FreeNetBufferListForwardingContext(ovsPool->ndisContext, nbl);
    NdisFreeNetBufferListContext(nbl, sizeof (OVS_BUFFER_CONTEXT));

    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsCopyNBLInfo
 *
 *    Copy NBL info from src to dst
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsCopyNBLInfo(PNET_BUFFER_LIST srcNbl, PNET_BUFFER_LIST dstNbl,
               POVS_BUFFER_CONTEXT srcCtx, UINT32 copySize,
               BOOLEAN copyNblInfo)
{
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO srcInfo, dstInfo;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    srcInfo = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(srcNbl);
    dstInfo = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(dstNbl);
    if (srcInfo) {
#ifdef OVS_USE_COPY_NET_BUFFER_LIST_INFO
        status = context->NdisSwitchHandlers.
            CopyNetBufferListInfo(ovsPool->ndisContext, dstNbl, srcNbl, 0);

        if (status != NDIS_STATUS_SUCCESS) {
            return status;
        }
#else
        dstInfo->SourcePortId = srcInfo->SourcePortId;
        dstInfo->SourceNicIndex = srcInfo->SourceNicIndex;
        if (copyNblInfo) {
            if (srcCtx->flags & OVS_BUFFER_RECV_BUFFER) {
                NdisCopyReceiveNetBufferListInfo(dstNbl, srcNbl);
            } else if (srcCtx->flags & OVS_BUFFER_SEND_BUFFER) {
                NdisCopySendNetBufferListInfo(dstNbl, srcNbl);
            }
        }
#endif
        dstInfo->IsPacketDataSafe = srcInfo->IsPacketDataSafe;
        if (!srcInfo->IsPacketDataSafe && copySize >
            srcInfo->SafePacketDataSize) {
            srcInfo->SafePacketDataSize = copySize;
        }
    } else {
        /*
         * Assume all data are safe
         */
        dstInfo->IsPacketDataSafe = TRUE;
        dstInfo->SourcePortId = NDIS_SWITCH_DEFAULT_PORT_ID;
    }
    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsPartialCopyNBL --
 *
 *    Partial copy NBL, if there is multiple NB in NBL, each one will be
 *    copied. We also reserve headroom for the new NBL.
 *
 *    Please note,
 *       NBL should have OVS_BUFFER_CONTEXT setup before calling
 *       this function.
 *       The NBL should already have ref to itself so that during copy
 *       it will not be freed.
 * --------------------------------------------------------------------------
 */
PNET_BUFFER_LIST
OvsPartialCopyNBL(PVOID ovsContext,
                  PNET_BUFFER_LIST nbl,
                  UINT32 copySize,
                  UINT32 headRoom,
                  BOOLEAN copyNblInfo)
{
    PNET_BUFFER_LIST newNbl;
    POVS_SWITCH_CONTEXT context = (POVS_SWITCH_CONTEXT)ovsContext;
    NDIS_STATUS status;
    PNET_BUFFER srcNb, dstNb;
    ULONG byteCopied;
    POVS_NBL_POOL ovsPool = &context->ovsPool;
    POVS_BUFFER_CONTEXT srcCtx, dstCtx;
    UINT16 flags;

    srcCtx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
    if (srcCtx == NULL || srcCtx->magic != OVS_CTX_MAGIC) {
        OVS_LOG_INFO("src nbl must have ctx initialized");
        ASSERT(srcCtx && srcCtx->magic == OVS_CTX_MAGIC);
        return NULL;
    }

    if (copySize) {
        NdisAdvanceNetBufferListDataStart(nbl, copySize, FALSE, NULL);
    }
    newNbl = NdisAllocateCloneNetBufferList(nbl, ovsPool->nblOnlyPool,
                                            NULL, 0);
    if (copySize) {
        status = NdisRetreatNetBufferListDataStart(nbl, copySize, 0,
                                                   NULL, NULL);
        ASSERT(status == NDIS_STATUS_SUCCESS);
    }

    if (newNbl == NULL) {
        return NULL;
    }

    /*
     * Allocate private memory for copy
     */
    if (copySize + headRoom) {
        status = NdisRetreatNetBufferListDataStart(newNbl, copySize + headRoom,
                                                   0, NULL, NULL);
        if (status != NDIS_STATUS_SUCCESS) {
            goto retreat_error;
        }

        if (headRoom) {
            NdisAdvanceNetBufferListDataStart(newNbl, headRoom, FALSE, NULL);
        }
        if (copySize) {
            srcNb = NET_BUFFER_LIST_FIRST_NB(nbl);
            dstNb = NET_BUFFER_LIST_FIRST_NB(newNbl);

            while (srcNb) {
                status = NdisCopyFromNetBufferToNetBuffer(dstNb, 0, copySize,
                                                          srcNb, 0,
                                                          &byteCopied);
                if (status != NDIS_STATUS_SUCCESS || copySize != byteCopied) {
                    goto nbl_context_error;
                }
                srcNb = NET_BUFFER_NEXT_NB(srcNb);
                dstNb = NET_BUFFER_NEXT_NB(dstNb);
            }
        }
    }

    status = OvsAllocateNBLContext(context, newNbl);
    if (status != NDIS_STATUS_SUCCESS) {
        goto nbl_context_error;
    }

    status = OvsCopyNBLInfo(nbl, newNbl, srcCtx, copySize, copyNblInfo);
    if (status != NDIS_STATUS_SUCCESS) {
        goto copy_list_info_error;
    }

#ifdef DBG
    InterlockedIncrement((LONG volatile *)&ovsPool->nblOnlyCount);
#endif

    newNbl->ParentNetBufferList = nbl;

    dstCtx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(newNbl);
    ASSERT(dstCtx != NULL);

    flags = srcCtx->flags & (OVS_BUFFER_RECV_BUFFER | OVS_BUFFER_SEND_BUFFER);

    flags |= OVS_BUFFER_FROM_NBL_ONLY_POOL | OVS_BUFFER_PRIVATE_CONTEXT |
             OVS_BUFFER_PRIVATE_FORWARD_CONTEXT;

    srcNb = NET_BUFFER_LIST_FIRST_NB(nbl);
    ASSERT(srcNb);
    OvsInitNBLContext(dstCtx, flags, NET_BUFFER_DATA_LENGTH(srcNb) - copySize,
                      OVS_DPPORT_NUMBER_INVALID, srcCtx->mru);

    InterlockedIncrement((LONG volatile *)&srcCtx->refCount);

#ifdef DBG
    OvsDumpNetBufferList(nbl);
    OvsDumpForwardingDetails(nbl);

    OvsDumpNetBufferList(newNbl);
    OvsDumpForwardingDetails(newNbl);
#endif

    OVS_LOG_LOUD("Partial Copy new NBL: %p", newNbl);
    return newNbl;

copy_list_info_error:
    OvsFreeNBLContext(context, newNbl);
nbl_context_error:
    if (copySize) {
        NdisAdvanceNetBufferListDataStart(newNbl, copySize, TRUE, NULL);
    }
retreat_error:
    NdisFreeCloneNetBufferList(newNbl, 0);
    return NULL;
}

/*
 * --------------------------------------------------------------------------
 * OvsPartialCopyToMultipleNBLs --
 *
 *     This is similar to OvsPartialCopyNBL() except that each NB will
 *     have its own NBL.
 * --------------------------------------------------------------------------
 */
PNET_BUFFER_LIST
OvsPartialCopyToMultipleNBLs(PVOID ovsContext,
                             PNET_BUFFER_LIST nbl,
                             UINT32 copySize,
                             UINT32 headRoom,
                             BOOLEAN copyNblInfo)
{
    PNET_BUFFER nb, nextNb = NULL, firstNb, prevNb;
    POVS_SWITCH_CONTEXT context = (POVS_SWITCH_CONTEXT)ovsContext;
    PNET_BUFFER_LIST firstNbl = NULL, newNbl, prevNbl = NULL;

    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (NET_BUFFER_NEXT_NB(nb) == NULL) {
        return OvsPartialCopyNBL(context, nbl, copySize, headRoom, copyNblInfo);
    }

    firstNb = nb;
    prevNb = nb;

    while (nb) {
        nextNb = NET_BUFFER_NEXT_NB(nb);
        NET_BUFFER_NEXT_NB(nb) = NULL;

        NET_BUFFER_LIST_FIRST_NB(nbl) = nb;

        newNbl = OvsPartialCopyNBL(context, nbl, copySize, headRoom,
                                   copyNblInfo);
        if (newNbl == NULL) {
            goto cleanup;
        }
        if (prevNbl == NULL) {
            firstNbl = newNbl;
        } else {
            NET_BUFFER_LIST_NEXT_NBL(prevNbl) = newNbl;
            NET_BUFFER_NEXT_NB(prevNb) = nb;
        }
        prevNbl = newNbl;
        prevNb = nb;
        nb = nextNb;
    }
    NET_BUFFER_LIST_FIRST_NB(nbl) = firstNb;
    return firstNbl;

cleanup:
    NET_BUFFER_NEXT_NB(prevNb) = nb;
    NET_BUFFER_NEXT_NB(nb) = nextNb;
    NET_BUFFER_LIST_FIRST_NB(nbl) = firstNb;

    newNbl = firstNbl;
    while (newNbl) {
        firstNbl = NET_BUFFER_LIST_NEXT_NBL(newNbl);
        NET_BUFFER_LIST_NEXT_NBL(newNbl) = NULL;
        OvsCompleteNBL(context, newNbl, TRUE);
        newNbl = firstNbl;
    }
    return NULL;
}


static PNET_BUFFER_LIST
OvsCopySinglePacketNBL(PVOID ovsContext,
                       PNET_BUFFER_LIST nbl,
                       PNET_BUFFER nb,
                       UINT32 headRoom,
                       BOOLEAN copyNblInfo)
{
    UINT32 size;
    ULONG copiedSize;
    POVS_SWITCH_CONTEXT context = (POVS_SWITCH_CONTEXT)ovsContext;
    PNET_BUFFER_LIST newNbl;
    PNET_BUFFER newNb;
    NDIS_STATUS status;
    POVS_BUFFER_CONTEXT srcCtx, dstCtx;

    size = NET_BUFFER_DATA_LENGTH(nb);
    if ((size + headRoom) <= OVS_FIX_NBL_DATA_SIZE) {
        newNbl = OvsAllocateFixSizeNBL(context, size, headRoom);
    } else {
        newNbl = OvsAllocateVariableSizeNBL(context, size, headRoom);
    }
    if (newNbl == NULL) {
        return NULL;
    }
    newNb = NET_BUFFER_LIST_FIRST_NB(newNbl);
    status = NdisCopyFromNetBufferToNetBuffer(newNb, 0, size, nb, 0,
                                              &copiedSize);

    srcCtx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
    if (status == NDIS_STATUS_SUCCESS) {
        status = OvsCopyNBLInfo(nbl, newNbl, srcCtx, copiedSize, copyNblInfo);
    }

    if (status != NDIS_STATUS_SUCCESS || copiedSize != size) {
        OvsCompleteNBL(context, newNbl, TRUE);
        return NULL;
    }

    dstCtx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(newNbl);
    ASSERT(dstCtx && srcCtx);
    ASSERT(srcCtx->magic == OVS_CTX_MAGIC && dstCtx->magic == OVS_CTX_MAGIC);

    dstCtx->flags |= srcCtx->flags & (OVS_BUFFER_RECV_BUFFER |
                                      OVS_BUFFER_SEND_BUFFER);
#ifdef DBG
    OvsDumpNetBufferList(newNbl);
    OvsDumpForwardingDetails(newNbl);
#endif
    OVS_LOG_LOUD("Copy single nb to new NBL: %p", newNbl);
    return newNbl;
}

/*
 * --------------------------------------------------------------------------
 * OvsFullCopyNBL --
 *
 *    Copy the NBL to a new NBL including data.
 *
 * Notes:
 *     The NBL can have multiple NBs, but the final result is one NBL.
 * --------------------------------------------------------------------------
 */
PNET_BUFFER_LIST
OvsFullCopyNBL(PVOID ovsContext,
               PNET_BUFFER_LIST nbl,
               UINT32 headRoom,
               BOOLEAN copyNblInfo)
{
    POVS_SWITCH_CONTEXT context = (POVS_SWITCH_CONTEXT)ovsContext;
    POVS_NBL_POOL ovsPool = &context->ovsPool;
    PNET_BUFFER_LIST newNbl;
    PNET_BUFFER nb, newNb, firstNb = NULL, prevNb = NULL;
    POVS_BUFFER_CONTEXT dstCtx, srcCtx;
    PMDL mdl;
    NDIS_STATUS status;
    UINT32 size, totalSize;
    ULONG copiedSize;
    UINT16 flags;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO dstInfo;

    srcCtx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
    if (srcCtx == NULL || srcCtx->magic != OVS_CTX_MAGIC) {
        OVS_LOG_INFO("src nbl must have ctx initialized");
        ASSERT(srcCtx && srcCtx->magic == OVS_CTX_MAGIC);
        return NULL;
    }

    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (nb == NULL) {
        return NULL;
    }

    if (NET_BUFFER_NEXT_NB(nb) == NULL) {
        return OvsCopySinglePacketNBL(context, nbl, nb, headRoom, copyNblInfo);
    }

    newNbl = NdisAllocateNetBufferList(ovsPool->nblOnlyPool,
                                       (UINT16)sizeof (OVS_BUFFER_CONTEXT),
                                       (UINT16)OVS_DEFAULT_NBL_CONTEXT_FILL);
    if (newNbl == NULL) {
        return NULL;
    }

    while (nb) {
        size = NET_BUFFER_DATA_LENGTH(nb);
        totalSize = MEM_ALIGN_SIZE(size + headRoom);
        mdl = OvsAllocateMDLAndData(ovsPool->ndisHandle, totalSize);

        if (mdl == NULL) {
            goto nblcopy_error;
        }
        newNb = NdisAllocateNetBuffer(ovsPool->nbPool, mdl, totalSize, 0);
        if (newNb == NULL) {
            OvsFreeMDLAndData(mdl);
            goto nblcopy_error;
        }
        if (firstNb == NULL) {
            firstNb = newNb;
        } else {
            NET_BUFFER_NEXT_NB(prevNb) = newNb;
        }
        prevNb = newNb;
#ifdef DBG
        InterlockedIncrement((LONG volatile *)&ovsPool->nbCount);
#endif
        status = NdisRetreatNetBufferDataStart(newNb, size, 0, NULL);
        ASSERT(status == NDIS_STATUS_SUCCESS);

        status = NdisCopyFromNetBufferToNetBuffer(newNb, 0, size, nb, 0,
                                                  &copiedSize);
        if (status != NDIS_STATUS_SUCCESS || size != copiedSize) {
            goto nblcopy_error;
        }

        nb = NET_BUFFER_NEXT_NB(nb);
    }

    NET_BUFFER_LIST_FIRST_NB(newNbl) = firstNb;

    newNbl->SourceHandle = ovsPool->ndisHandle;
    status = context->NdisSwitchHandlers.
         AllocateNetBufferListForwardingContext(ovsPool->ndisContext, newNbl);

    if (status != NDIS_STATUS_SUCCESS) {
        goto nblcopy_error;
    }

    status = OvsCopyNBLInfo(nbl, newNbl, srcCtx, 0, copyNblInfo);
    if (status != NDIS_STATUS_SUCCESS) {
        goto nblcopy_error;
    }

    dstInfo = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl);
    dstInfo->IsPacketDataSafe = TRUE;

    dstCtx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(newNbl);

    flags = srcCtx->flags & (OVS_BUFFER_RECV_BUFFER | OVS_BUFFER_SEND_BUFFER);

    flags |= OVS_BUFFER_PRIVATE_MDL | OVS_BUFFER_PRIVATE_DATA |
             OVS_BUFFER_PRIVATE_NET_BUFFER | OVS_BUFFER_FROM_NBL_ONLY_POOL |
             OVS_BUFFER_PRIVATE_FORWARD_CONTEXT;

    OvsInitNBLContext(dstCtx, flags, NET_BUFFER_DATA_LENGTH(firstNb),
                      OVS_DPPORT_NUMBER_INVALID, srcCtx->mru);

#ifdef DBG
    OvsDumpNetBufferList(nbl);
    OvsDumpForwardingDetails(nbl);
    InterlockedIncrement((LONG volatile *)&ovsPool->nblOnlyCount);
#endif
    OVS_LOG_LOUD("newNbl: %p", newNbl);
    return newNbl;

nblcopy_error:
    while (firstNb) {
#ifdef DBG
        InterlockedDecrement((LONG volatile *)&ovsPool->nbCount);
#endif
        prevNb = firstNb;
        firstNb = NET_BUFFER_NEXT_NB(prevNb);
        mdl = NET_BUFFER_FIRST_MDL(prevNb);
        NET_BUFFER_FIRST_MDL(prevNb) = NULL;
        NdisFreeNetBuffer(prevNb);
        OvsFreeMDLAndData(mdl);
    }
    NdisFreeNetBufferList(newNbl);
    OVS_LOG_ERROR("OvsFullCopyNBL failed");
    return NULL;
}

NDIS_STATUS
GetIpHeaderInfo(PNET_BUFFER_LIST curNbl,
                const POVS_PACKET_HDR_INFO hdrInfo,
                UINT32 *hdrSize)
{
    EthHdr *eth;
    IPHdr *ipHdr;
    PNET_BUFFER curNb;

    curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
    ASSERT(NET_BUFFER_NEXT_NB(curNb) == NULL);

    eth = (EthHdr *)NdisGetDataBuffer(curNb,
                                      hdrInfo->l4Offset,
                                      NULL, 1, 0);
    if (eth == NULL) {
        return NDIS_STATUS_INVALID_PACKET;
    }
    ipHdr = (IPHdr *)((PCHAR)eth + hdrInfo->l3Offset);
    *hdrSize = (UINT32)(hdrInfo->l3Offset + (ipHdr->ihl * 4));
    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * GetSegmentHeaderInfo
 *
 *    Extract header size and sequence number for the segment.
 * --------------------------------------------------------------------------
 */
static NDIS_STATUS
GetSegmentHeaderInfo(PNET_BUFFER_LIST nbl,
                     const POVS_PACKET_HDR_INFO hdrInfo,
                     UINT32 *hdrSize, UINT32 *seqNumber)
{
    TCPHdr tcpStorage;
    const TCPHdr *tcp;

    /* Parse the orginal Eth/IP/TCP header */
    tcp = OvsGetPacketBytes(nbl, sizeof *tcp, hdrInfo->l4Offset, &tcpStorage);
    if (tcp == NULL) {
        return NDIS_STATUS_FAILURE;
    }
    *seqNumber = ntohl(tcp->seq);
    *hdrSize = hdrInfo->l4Offset + TCP_HDR_LEN(tcp);

    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * FixFragmentHeader
 *
 *    Fix IP length, Offset, IP checksum.
 *    XXX - Support IpV6 Fragments
 * --------------------------------------------------------------------------
 */
static NDIS_STATUS
FixFragmentHeader(PNET_BUFFER nb, UINT16 fragmentSize,
                  BOOLEAN lastPacket, UINT16 offset)
{
    EthHdr *dstEth = NULL;
    PMDL mdl = NULL;
    PUINT8 bufferStart = NULL;

    mdl = NET_BUFFER_FIRST_MDL(nb);

    bufferStart = (PUINT8)OvsGetMdlWithLowPriority(mdl);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }
    dstEth = (EthHdr *)(bufferStart + NET_BUFFER_CURRENT_MDL_OFFSET(nb));

    switch (dstEth->Type) {
    case ETH_TYPE_IPV4_NBO:
    {
        IPHdr *dstIP = NULL;
        ASSERT((INT)MmGetMdlByteCount(mdl) - NET_BUFFER_CURRENT_MDL_OFFSET(nb)
            >= sizeof(EthHdr) + sizeof(IPHdr));

        dstIP = (IPHdr *)((PCHAR)dstEth + sizeof(*dstEth));
        ASSERT((INT)MmGetMdlByteCount(mdl) - NET_BUFFER_CURRENT_MDL_OFFSET(nb)
            >= sizeof(EthHdr) + dstIP->ihl * 4);
        dstIP->tot_len = htons(fragmentSize + dstIP->ihl * 4);
        if (lastPacket) {
            dstIP->frag_off = htons(offset & IP_OFFSET);
        } else {
            dstIP->frag_off = htons((offset & IP_OFFSET) | IP_MF);
        }

        dstIP->check = 0;
        dstIP->check = IPChecksum((UINT8 *)dstIP, dstIP->ihl * 4, 0);
        break;
    }
    case ETH_TYPE_IPV6_NBO:
    {
        return NDIS_STATUS_NOT_SUPPORTED;
    }
    default:
        OVS_LOG_ERROR("Invalid eth type: %d\n", dstEth->Type);
        ASSERT(! "Invalid eth type");
    }

    return STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * FixSegmentHeader
 *
 *    Fix IP length, IP checksum, TCP sequence number and TCP checksum
 *    in the segment.
 * --------------------------------------------------------------------------
 */
static NDIS_STATUS
FixSegmentHeader(PNET_BUFFER nb, UINT16 segmentSize, UINT32 seqNumber,
                 BOOLEAN lastPacket, UINT16 packetCounter)
{
    EthHdr *dstEth = NULL;
    TCPHdr *dstTCP = NULL;
    PMDL mdl = NULL;
    PUINT8 bufferStart = NULL;

    mdl = NET_BUFFER_FIRST_MDL(nb);

    bufferStart = (PUINT8)OvsGetMdlWithLowPriority(mdl);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }
    dstEth = (EthHdr *)(bufferStart + NET_BUFFER_CURRENT_MDL_OFFSET(nb));

    switch (dstEth->Type) {
    case ETH_TYPE_IPV4_NBO:
    {
        IPHdr *dstIP = NULL;

        ASSERT((INT)MmGetMdlByteCount(mdl) - NET_BUFFER_CURRENT_MDL_OFFSET(nb)
                >= sizeof(EthHdr) + sizeof(IPHdr) + sizeof(TCPHdr));
        dstIP = (IPHdr *)((PCHAR)dstEth + sizeof(*dstEth));
        dstTCP = (TCPHdr *)((PCHAR)dstIP + dstIP->ihl * 4);
        ASSERT((INT)MmGetMdlByteCount(mdl) - NET_BUFFER_CURRENT_MDL_OFFSET(nb)
                >= sizeof(EthHdr) + dstIP->ihl * 4 + TCP_HDR_LEN(dstTCP));

        /* Fix IP length and checksum */
        ASSERT(dstIP->protocol == IPPROTO_TCP);
        dstIP->tot_len = htons(segmentSize + dstIP->ihl * 4 + TCP_HDR_LEN(dstTCP));
        dstIP->id += packetCounter;
        dstIP->check = 0;
        dstIP->check = IPChecksum((UINT8 *)dstIP, dstIP->ihl * 4, 0);
        dstTCP->seq = htonl(seqNumber);

        /*
         * Set the TCP FIN and PSH bit only for the last packet
         * More information can be found under:
         * https://msdn.microsoft.com/en-us/library/windows/hardware/ff568840%28v=vs.85%29.aspx
         */
        if (dstTCP->fin) {
            dstTCP->fin = lastPacket;
        }
        if (dstTCP->psh) {
            dstTCP->psh = lastPacket;
        }
        UINT16 csumLength = segmentSize + TCP_HDR_LEN(dstTCP);
        dstTCP->check = IPPseudoChecksum(&dstIP->saddr,
                                         &dstIP->daddr,
                                         IPPROTO_TCP,
                                         csumLength);
        dstTCP->check = CalculateChecksumNB(nb,
                                            csumLength,
                                            sizeof(*dstEth) + dstIP->ihl * 4);
        break;
    }
    case ETH_TYPE_IPV6_NBO:
    {
        IPv6Hdr *dstIP = NULL;

        ASSERT((INT)MmGetMdlByteCount(mdl) - NET_BUFFER_CURRENT_MDL_OFFSET(nb)
            >= sizeof(EthHdr) + sizeof(IPv6Hdr) + sizeof(TCPHdr));
        dstIP = (IPv6Hdr *)((PCHAR)dstEth + sizeof(*dstEth));
        dstTCP = (TCPHdr *)((PCHAR)dstIP + sizeof(IPv6Hdr));
        ASSERT((INT)MmGetMdlByteCount(mdl) - NET_BUFFER_CURRENT_MDL_OFFSET(nb)
            >= sizeof(EthHdr) + sizeof(IPv6Hdr) + TCP_HDR_LEN(dstTCP));

        /* Fix IP length */
        ASSERT(dstIP->nexthdr == IPPROTO_TCP);
        dstIP->payload_len = htons(segmentSize + sizeof(IPv6Hdr) + TCP_HDR_LEN(dstTCP));

        dstTCP->seq = htonl(seqNumber);
        if (dstTCP->fin) {
            dstTCP->fin = lastPacket;
        }
        if (dstTCP->psh) {
            dstTCP->psh = lastPacket;
        }

        UINT16 csumLength = segmentSize + TCP_HDR_LEN(dstTCP);
        dstTCP->check = IPv6PseudoChecksum((UINT32*)&dstIP->saddr,
                                           (UINT32*)&dstIP->daddr,
                                           IPPROTO_TCP,
                                           csumLength);
        dstTCP->check = CalculateChecksumNB(nb,
                                            csumLength,
                                            sizeof(*dstEth) + sizeof(IPv6Hdr));
        break;
    }
    default:
        OVS_LOG_ERROR("Invalid eth type: %d\n", dstEth->Type);
        ASSERT(! "Invalid eth type");
    }

    return STATUS_SUCCESS;
}
 /*
  * --------------------------------------------------------------------------
 * OvsTcpSegmentNBL --
 *    Wrapper function to Fragment a given NBL based on MSS
 * --------------------------------------------------------------------------
 */
PNET_BUFFER_LIST
OvsTcpSegmentNBL(PVOID ovsContext,
                 PNET_BUFFER_LIST nbl,
                 POVS_PACKET_HDR_INFO hdrInfo,
                 UINT32 mss,
                 UINT32 headRoom,
                 BOOLEAN isIpFragment)
{
    return OvsFragmentNBL(ovsContext, nbl, hdrInfo, mss, headRoom, isIpFragment);
}


/*
 * --------------------------------------------------------------------------
 * OvsFragmentNBL --
 *
 *    Fragment NBL payload, and prepend each segment with Ether/IP/TCP header.
 *    Leave headRoom for additional encap.
 *
 *    Please note,
 *       NBL should have OVS_BUFFER_CONTEXT setup before calling
 *       this function.
 *       The NBL should already have ref to itself so that during copy
 *       it will not be freed.
 *       Currently this API assert there is only one NB in an NBL, it needs
 *       to be fixed if we receive multiple NBs in an NBL.
 * --------------------------------------------------------------------------
 */
PNET_BUFFER_LIST
OvsFragmentNBL(PVOID ovsContext,
               PNET_BUFFER_LIST nbl,
               POVS_PACKET_HDR_INFO hdrInfo,
               UINT32 fragmentSize,
               UINT32 headRoom,
               BOOLEAN isIpFragment)
{
    POVS_SWITCH_CONTEXT context = (POVS_SWITCH_CONTEXT)ovsContext;
#ifdef DBG
    POVS_NBL_POOL ovsPool = &context->ovsPool;
#endif
    POVS_BUFFER_CONTEXT dstCtx, srcCtx;
    UINT32 size, hdrSize, nblSize, seqNumber = 0;
    PNET_BUFFER_LIST newNbl;
    PNET_BUFFER nb, newNb;
    NDIS_STATUS status;
    UINT16 segmentSize;
    ULONG copiedSize;
    UINT16 offset = 0, packetCounter = 0;

    srcCtx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
    if (srcCtx == NULL || srcCtx->magic != OVS_CTX_MAGIC) {
        OVS_LOG_INFO("src nbl must have ctx initialized");
        ASSERT(srcCtx && srcCtx->magic == OVS_CTX_MAGIC);
        return NULL;
    }

    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    ASSERT(NET_BUFFER_NEXT_NB(nb) == NULL);

    /* Figure out the header size */
    if (isIpFragment) {
        status = GetIpHeaderInfo(nbl, hdrInfo, &hdrSize);
    } else {
        status = GetSegmentHeaderInfo(nbl, hdrInfo, &hdrSize, &seqNumber);
    }
    if (status != NDIS_STATUS_SUCCESS) {
        OVS_LOG_INFO("Cannot parse NBL header");
        return NULL;
    }
    /* Get the NBL size. */
    if (isIpFragment) {
        nblSize = fragmentSize - hdrSize;
    } else {
        nblSize = fragmentSize;
    }
    size = NET_BUFFER_DATA_LENGTH(nb) - hdrSize;

    /* XXX add to ovsPool counters? */
    newNbl = NdisAllocateFragmentNetBufferList(nbl, NULL, NULL, hdrSize,
                                               nblSize, hdrSize + headRoom ,
                                               0, 0);
    if (newNbl == NULL) {
        return NULL;
    }

    /* Now deal with TCP payload */
    for (newNb = NET_BUFFER_LIST_FIRST_NB(newNbl); newNb != NULL;
            newNb = NET_BUFFER_NEXT_NB(newNb)) {
        segmentSize = (size > nblSize ? nblSize : size) & 0xffff;
        if (headRoom) {
            NdisAdvanceNetBufferDataStart(newNb, headRoom, FALSE, NULL);
        }

        /* Now copy the eth/IP/TCP header and fix up */
        status = NdisCopyFromNetBufferToNetBuffer(newNb, 0, hdrSize, nb, 0,
                                                  &copiedSize);
        if (status != NDIS_STATUS_SUCCESS || hdrSize != copiedSize) {
            goto nblcopy_error;
        }

        if (isIpFragment) {
            status = FixFragmentHeader(newNb, segmentSize,
                                       NET_BUFFER_NEXT_NB(newNb) == NULL,
                                       offset);
        } else {
            status = FixSegmentHeader(newNb, segmentSize, seqNumber,
                                      NET_BUFFER_NEXT_NB(newNb) == NULL,
                                      packetCounter);
        }

        if (status != NDIS_STATUS_SUCCESS) {
            goto nblcopy_error;
        }

        /* Move on to the next segment */
        if (isIpFragment) {
            offset += (segmentSize) / 8;
        } else {
            seqNumber += segmentSize;
        }
        size -= segmentSize;
        packetCounter++;
    }

    status = OvsAllocateNBLContext(context, newNbl);
    if (status != NDIS_STATUS_SUCCESS) {
        goto nblcopy_error;
    }

    status = OvsCopyNBLInfo(nbl, newNbl, srcCtx, hdrSize + headRoom, FALSE);
    if (status != NDIS_STATUS_SUCCESS) {
        goto nbl_context_error;
    }

    if (isIpFragment) {
    /*Copy with Flag - NDIS_SWITCH_COPY_NBL_INFO_FLAGS_PRESERVE_DESTINATIONS.*/
        status = context->NdisSwitchHandlers.
            CopyNetBufferListInfo(context->ovsPool.ndisContext, newNbl, nbl, 1);

        if (status != NDIS_STATUS_SUCCESS) {
            goto nbl_context_error;
        }
    }
    newNbl->ParentNetBufferList = nbl;

    /* Remember it's a fragment NBL so we can free it properly */
    dstCtx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(newNbl);
    ASSERT(dstCtx != NULL);
    dstCtx->flags = OVS_BUFFER_FRAGMENT | OVS_BUFFER_PRIVATE_CONTEXT |
        OVS_BUFFER_PRIVATE_FORWARD_CONTEXT | OVS_BUFFER_SEND_BUFFER;
    dstCtx->refCount = 1;
    dstCtx->magic = OVS_CTX_MAGIC;
    dstCtx->dataOffsetDelta = hdrSize + headRoom;
    dstCtx->mru = 0;

    InterlockedIncrement((LONG volatile *)&srcCtx->refCount);
#ifdef DBG
    InterlockedIncrement((LONG volatile *)&ovsPool->fragNBLCount);

    OvsDumpNetBufferList(nbl);
    OvsDumpForwardingDetails(nbl);

    OvsDumpNetBufferList(newNbl);
    OvsDumpForwardingDetails(newNbl);
#endif
    OVS_LOG_TRACE("Fragment nbl %p to newNbl: %p", nbl, newNbl);
    return newNbl;

nbl_context_error:
    OvsFreeNBLContext(context, newNbl);
nblcopy_error:
#ifdef DBG
    InterlockedDecrement((LONG volatile *)&ovsPool->fragNBLCount);
#endif
    NdisFreeFragmentNetBufferList(newNbl, hdrSize + headRoom, 0);
    return NULL;
}

/*
 * --------------------------------------------------------------------------
 * OvsAllocateNBLFromBuffer --
 *
 * This function allocates all the stuff necessary for creating an NBL from the
 * input buffer of specified length, namely, a nonpaged data buffer of size
 * length, an MDL from it, and a NB and NBL from it. It does not allocate an NBL
 * context yet. It also copies data from the specified buffer to the NBL.
 * --------------------------------------------------------------------------
 */
PNET_BUFFER_LIST
OvsAllocateNBLFromBuffer(PVOID context,
                         PVOID buffer,
                         ULONG length)
{
    POVS_SWITCH_CONTEXT switchContext = (POVS_SWITCH_CONTEXT)context;
    UINT8 *data = NULL;
    PNET_BUFFER_LIST nbl = NULL;
    PNET_BUFFER nb;
    PMDL mdl;

    if (length > OVS_DEFAULT_DATA_SIZE) {
        nbl = OvsAllocateVariableSizeNBL(switchContext, length,
                                         OVS_DEFAULT_HEADROOM_SIZE);

    } else {
        nbl = OvsAllocateFixSizeNBL(switchContext, length,
                                    OVS_DEFAULT_HEADROOM_SIZE);
    }
    if (nbl == NULL) {
        return NULL;
    }

    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    mdl = NET_BUFFER_CURRENT_MDL(nb);
    data = (PUINT8)OvsGetMdlWithLowPriority(mdl)
        + NET_BUFFER_CURRENT_MDL_OFFSET(nb);
    if (!data) {
        OvsCompleteNBL(switchContext, nbl, TRUE);
        return NULL;
    }

    NdisMoveMemory(data, buffer, length);

    return nbl;
}

/*
 * --------------------------------------------------------------------------
 * OvsFullCopyToMultipleNBLs --
 *
 *    Copy NBL to multiple NBLs, each NB will have its own NBL
 * --------------------------------------------------------------------------
 */
PNET_BUFFER_LIST
OvsFullCopyToMultipleNBLs(PVOID ovsContext,
                          PNET_BUFFER_LIST nbl,
                          UINT32 headRoom,
                          BOOLEAN copyNblInfo)
{

    POVS_SWITCH_CONTEXT context = (POVS_SWITCH_CONTEXT)ovsContext;
    PNET_BUFFER_LIST firstNbl, currNbl, newNbl;
    PNET_BUFFER nb;
    POVS_BUFFER_CONTEXT srcCtx;

    srcCtx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
    if (srcCtx == NULL || srcCtx->magic != OVS_CTX_MAGIC) {
        OVS_LOG_INFO("src nbl must have ctx initialized");
        ASSERT(srcCtx && srcCtx->magic == OVS_CTX_MAGIC);
        return NULL;
    }

    nb =  NET_BUFFER_LIST_FIRST_NB(nbl);
    newNbl = OvsCopySinglePacketNBL(context, nbl, nb, headRoom, copyNblInfo);

    if (newNbl == NULL || NET_BUFFER_NEXT_NB(nb) == NULL) {
        return newNbl;
    } else {
        firstNbl = newNbl;
        currNbl = newNbl;
    }

    while (nb) {
        newNbl = OvsCopySinglePacketNBL(context, nbl, nb, headRoom,
                                        copyNblInfo);
        if (newNbl == NULL) {
            goto copymultiple_error;
        }
        NET_BUFFER_LIST_NEXT_NBL(currNbl) = newNbl;
        currNbl = newNbl;
        nb = NET_BUFFER_NEXT_NB(nb);
    }
    return firstNbl;

copymultiple_error:
    while (firstNbl) {
        currNbl = firstNbl;
        firstNbl = NET_BUFFER_LIST_NEXT_NBL(firstNbl);
        NET_BUFFER_LIST_NEXT_NBL(currNbl) = NULL;
        OvsCompleteNBL(context, currNbl, TRUE);
    }
    return NULL;

}


/*
 * --------------------------------------------------------------------------
 * OvsCompleteNBL --
 *
 *     This function tries to free the NBL allocated by OVS buffer
 *     management module. If it trigger the completion of the parent
 *     NBL, it will recursively call itself. If it trigger the completion
 *     of external NBL, it will be returned to the caller. The caller
 *     is responsible to call API to return to upper layer.
 * --------------------------------------------------------------------------
 */
PNET_BUFFER_LIST
OvsCompleteNBL(PVOID switch_ctx,
               PNET_BUFFER_LIST nbl,
               BOOLEAN updateRef)
{
    POVS_BUFFER_CONTEXT ctx;
    UINT16 flags;
    UINT32 dataOffsetDelta;
    PNET_BUFFER_LIST parent;
    NDIS_STATUS status;
    NDIS_HANDLE poolHandle;
    LONG value;
    POVS_SWITCH_CONTEXT context = (POVS_SWITCH_CONTEXT)switch_ctx;
    POVS_NBL_POOL ovsPool = &context->ovsPool;
    PNET_BUFFER nb;


    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);

    ASSERT(ctx && ctx->magic == OVS_CTX_MAGIC);

    OVS_LOG_TRACE("Enter: nbl: %p, ctx: %p, refCount: %d, updateRef:%d",
                 nbl, ctx, ctx->refCount, updateRef);

    if (updateRef) {
        value = InterlockedDecrement((LONG volatile *)&ctx->refCount);
        if (value != 0) {
            return NULL;
        }
    } else {
        /*
         * This is a special case, the refCount must be zero
         */
        ASSERT(ctx->refCount == 0);
    }

    nb = NET_BUFFER_LIST_FIRST_NB(nbl);

    flags = ctx->flags;
    dataOffsetDelta = ctx->dataOffsetDelta;
    if (!(flags & OVS_BUFFER_FRAGMENT) &&
        NET_BUFFER_DATA_LENGTH(nb) != ctx->origDataLength) {
        UINT32 diff;
        if (NET_BUFFER_DATA_LENGTH(nb) < ctx->origDataLength) {
            diff = ctx->origDataLength -NET_BUFFER_DATA_LENGTH(nb);
            status = NdisRetreatNetBufferListDataStart(nbl, diff, 0,
                                                       NULL, NULL);
            ASSERT(status == NDIS_STATUS_SUCCESS);
        } else {
            diff = NET_BUFFER_DATA_LENGTH(nb) - ctx->origDataLength;
            NdisAdvanceNetBufferListDataStart(nbl, diff, TRUE, NULL);
        }
    }

    if (flags & OVS_BUFFER_PRIVATE_CONTEXT) {
        NdisFreeNetBufferListContext(nbl, sizeof (OVS_BUFFER_CONTEXT));
    }

    if (flags & OVS_BUFFER_NEED_COMPLETE) {
        /*
         * return to caller for completion
         */
#ifdef DBG
        InterlockedDecrement((LONG volatile *)&ovsPool->sysNBLCount);
#endif
        return nbl;
    }

    if (flags & OVS_BUFFER_PRIVATE_FORWARD_CONTEXT) {
        context->NdisSwitchHandlers.
              FreeNetBufferListForwardingContext(ovsPool->ndisContext, nbl);
    }

    if (flags & (OVS_BUFFER_PRIVATE_MDL | OVS_BUFFER_PRIVATE_DATA)) {
        PNET_BUFFER nbTemp = NET_BUFFER_LIST_FIRST_NB(nbl);
        while (nbTemp) {
            PMDL mdl = NET_BUFFER_FIRST_MDL(nbTemp);
            if (mdl) {
                ASSERT(mdl->Next == NULL);
                OvsFreeMDLAndData(mdl);
            }
            NET_BUFFER_FIRST_MDL(nbTemp) = NULL;
            nbTemp = NET_BUFFER_NEXT_NB(nbTemp);
        }
    }

    if (flags & OVS_BUFFER_PRIVATE_NET_BUFFER) {
        PNET_BUFFER nbTemp, nextNb;

        nbTemp = NET_BUFFER_LIST_FIRST_NB(nbl);
        while (nbTemp) {
            nextNb = NET_BUFFER_NEXT_NB(nbTemp);
            NdisFreeNetBuffer(nbTemp);
#ifdef DBG
            InterlockedDecrement((LONG volatile *)&ovsPool->nbCount);
#endif
            nbTemp = nextNb;
        }
        NET_BUFFER_LIST_FIRST_NB(nbl) = NULL;
    }

    parent = nbl->ParentNetBufferList;

    poolHandle = NdisGetPoolFromNetBufferList(nbl);
    if (flags & OVS_BUFFER_FROM_FIX_SIZE_POOL) {
        ASSERT(poolHandle == ovsPool->fixSizePool);
#ifdef DBG
        InterlockedDecrement((LONG volatile *)&ovsPool->fixNBLCount);
#endif
        NdisFreeNetBufferList(nbl);
    } else if (flags & OVS_BUFFER_FROM_ZERO_SIZE_POOL) {
        ASSERT(poolHandle == ovsPool->zeroSizePool);
#ifdef DBG
        InterlockedDecrement((LONG volatile *)&ovsPool->zeroNBLCount);
#endif
        NdisFreeNetBufferList(nbl);
    } else if (flags & OVS_BUFFER_FROM_NBL_ONLY_POOL) {
        ASSERT(poolHandle == ovsPool->nblOnlyPool);
#ifdef DBG
        InterlockedDecrement((LONG volatile *)&ovsPool->nblOnlyCount);
#endif
        NdisFreeCloneNetBufferList(nbl, 0);
    } else if (flags & OVS_BUFFER_FRAGMENT) {
        OVS_LOG_TRACE("Free fragment %p parent %p", nbl, parent);
#ifdef DBG
        InterlockedDecrement((LONG volatile *)&ovsPool->fragNBLCount);
#endif
        NdisFreeFragmentNetBufferList(nbl, dataOffsetDelta, 0);
    }

    if (parent != NULL) {
        ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(parent);
        ASSERT(ctx && ctx->magic == OVS_CTX_MAGIC);
        UINT16 pendingSend = 1, exchange = 0;
        value = InterlockedDecrement((LONG volatile *)&ctx->refCount);
        InterlockedCompareExchange16((SHORT volatile *)&pendingSend, exchange, (SHORT)ctx->pendingSend);
        if (value == 1 && pendingSend == exchange) {
            InterlockedExchange16((SHORT volatile *)&ctx->pendingSend, 0);
            OvsSendNBLIngress(context, parent, ctx->sendFlags);
        } else if (value == 0){
            return OvsCompleteNBL(context, parent, FALSE);
        }
    }
    return NULL;
}

/*
 * --------------------------------------------------------------------------
 * OvsSetCtxSourcePortNo --
 *      Setter function which stores the source port of an NBL in the NBL
 * Context Info.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsSetCtxSourcePortNo(PNET_BUFFER_LIST nbl,
                      UINT32 portNo)
{
    POVS_BUFFER_CONTEXT ctx;
    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
    if (ctx == NULL) {
        ASSERT(ctx && ctx->magic == OVS_CTX_MAGIC);
        return STATUS_INVALID_PARAMETER;
    }

    ctx->srcPortNo = portNo;
    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsGetCtxSourcePortNo --
 *      Get source port of an NBL from its Context Info.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsGetCtxSourcePortNo(PNET_BUFFER_LIST nbl,
                      UINT32 *portNo)
{
    POVS_BUFFER_CONTEXT ctx;
    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
    if (ctx == NULL || portNo == NULL) {
        ASSERT(ctx && ctx->magic == OVS_CTX_MAGIC);
        return STATUS_INVALID_PARAMETER;
    }
    *portNo = ctx->srcPortNo;
    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsCreateNewNBLsFromMultipleNBs --
 *      Creates an NBL chain where each NBL has a single NB,
 *      from an NBL which has multiple NBs.
 *      Sets 'curNbl' and 'lastNbl' to the first and last NBL in the
 *      newly created NBL chain respectively, and completes the original NBL.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsCreateNewNBLsFromMultipleNBs(POVS_SWITCH_CONTEXT switchContext,
                                PNET_BUFFER_LIST *curNbl,
                                PNET_BUFFER_LIST *lastNbl)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNET_BUFFER_LIST newNbls = NULL;
    PNET_BUFFER_LIST nbl = NULL;
    BOOLEAN error = TRUE;

    do {
        /* Create new NBLs from curNbl with multiple net buffers. */
        newNbls = OvsPartialCopyToMultipleNBLs(switchContext,
                                               *curNbl, 0, 0, TRUE);
        if (NULL == newNbls) {
            OVS_LOG_ERROR("Failed to allocate NBLs with single NB.");
            status = NDIS_STATUS_RESOURCES;
            break;
        }

        nbl = newNbls;
        while (nbl) {
            *lastNbl = nbl;
            nbl = NET_BUFFER_LIST_NEXT_NBL(nbl);
        }

        (*curNbl)->Next = NULL;

        OvsCompleteNBL(switchContext, *curNbl, TRUE);

        *curNbl = newNbls;

        error = FALSE;
    } while (error);

    return status;
}
