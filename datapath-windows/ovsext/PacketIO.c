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
 * This file contains the implementation of the datapath/forwarding
 * functionality of the OVS.
 */

#include "precomp.h"

#include "Actions.h"
#include "Switch.h"
#include "Vport.h"
#include "NetProto.h"
#include "User.h"
#include "PacketIO.h"
#include "Flow.h"
#include "Event.h"
#include "User.h"

/* Due to an imported header file */
#pragma warning( disable:4505 )

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_DISPATCH
#include "Debug.h"

extern NDIS_STRING ovsExtGuidUC;
extern NDIS_STRING ovsExtFriendlyNameUC;

static VOID OvsFinalizeCompletionList(OvsCompletionList *completionList);
static VOID OvsCompleteNBLIngress(POVS_SWITCH_CONTEXT switchContext,
                    PNET_BUFFER_LIST netBufferLists, ULONG sendCompleteFlags);

VOID
OvsInitCompletionList(OvsCompletionList *completionList,
                      POVS_SWITCH_CONTEXT switchContext,
                      ULONG sendCompleteFlags)
{
    ASSERT(completionList);
    completionList->dropNbl = NULL;
    completionList->dropNblNext = &completionList->dropNbl;
    completionList->switchContext = switchContext;
    completionList->sendCompleteFlags = sendCompleteFlags;
}

/* Utility function used to complete an NBL. */
VOID
OvsAddPktCompletionList(OvsCompletionList *completionList,
                        BOOLEAN incoming,
                        NDIS_SWITCH_PORT_ID sourcePort,
                        PNET_BUFFER_LIST netBufferList,
                        UINT32 netBufferListCount,
                        PNDIS_STRING filterReason)
{
    POVS_BUFFER_CONTEXT ctx;

    /* XXX: We handle one NBL at a time. */
    ASSERT(netBufferList->Next == NULL);

    /* Make sure it has a context. */
    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(netBufferList);
    ASSERT(ctx && ctx->magic == OVS_CTX_MAGIC);

    completionList->switchContext->NdisSwitchHandlers.ReportFilteredNetBufferLists(
        completionList->switchContext->NdisSwitchContext, &ovsExtGuidUC,
        &ovsExtFriendlyNameUC, sourcePort,
        incoming ? NDIS_SWITCH_REPORT_FILTERED_NBL_FLAGS_IS_INCOMING : 0,
        netBufferListCount, netBufferList, filterReason);

    *completionList->dropNblNext = netBufferList;
    completionList->dropNblNext = &netBufferList->Next;
    ASSERT(completionList->dropNbl);
}

static __inline VOID
OvsReportNBLIngressError(POVS_SWITCH_CONTEXT switchContext,
                         PNET_BUFFER_LIST nblList,
                         PNDIS_STRING filterReason,
                         NDIS_STATUS error)
{
    PNET_BUFFER_LIST nbl = nblList;
    while (nbl) {
        PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail;
        fwdDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(nbl);

        nbl->Status = error;

        /* This can be optimized by batching NBL's from the same
         * SourcePortId. */
        switchContext->NdisSwitchHandlers.ReportFilteredNetBufferLists(
            switchContext->NdisSwitchContext, &ovsExtGuidUC,
            &ovsExtFriendlyNameUC, fwdDetail->SourcePortId,
            NDIS_SWITCH_REPORT_FILTERED_NBL_FLAGS_IS_INCOMING,
            1 /*Nbl count.*/, nbl, filterReason);

        nbl = NET_BUFFER_LIST_NEXT_NBL(nbl);
    }
}

static __inline ULONG
OvsGetSendCompleteFlags(ULONG sendFlags)
{
    BOOLEAN dispatch, sameSource;
    ULONG sendCompleteFlags;

    dispatch = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(sendFlags);
    sendCompleteFlags = (dispatch ?
                        NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);
    sameSource = NDIS_TEST_SEND_FLAG(sendFlags,
                                        NDIS_SEND_FLAGS_SWITCH_SINGLE_SOURCE);
    sendCompleteFlags |= (sameSource ?
                        NDIS_SEND_COMPLETE_FLAGS_SWITCH_SINGLE_SOURCE : 0);

    return sendCompleteFlags;
}

VOID
OvsSendNBLIngress(POVS_SWITCH_CONTEXT switchContext,
                  PNET_BUFFER_LIST netBufferLists,
                  ULONG sendFlags)
{
    if (switchContext->dataFlowState == OvsSwitchPaused) {
        /* If a filter module is in the Paused state, the filter driver must not
         * originate any send requests for that filter module. If NDIS calls
         * FilterSendNetBufferLists, the driver must not call
         * NdisFSendNetBufferLists to pass on the data until the driver is
         * restarted. The driver should call NdisFSendNetBufferListsComplete
         * immediately to complete the send operation. It should set the
         * complete status in each NET_BUFFER_LIST structure to
         * NDIS_STATUS_PAUSED.
         *
         * http://msdn.microsoft.com/en-us/library/windows/hardware/
         * ff549966(v=vs.85).aspx */
        NDIS_STRING filterReason;
        ULONG sendCompleteFlags = OvsGetSendCompleteFlags(sendFlags);

        RtlInitUnicodeString(&filterReason,
                             L"Switch state PAUSED, drop before FSendNBL.");
        OvsReportNBLIngressError(switchContext, netBufferLists, &filterReason,
                                 NDIS_STATUS_PAUSED);
        OvsCompleteNBLIngress(switchContext, netBufferLists,
                              sendCompleteFlags);
        return;
    }

    ASSERT(switchContext->dataFlowState == OvsSwitchRunning);

    NdisFSendNetBufferLists(switchContext->NdisFilterHandle, netBufferLists,
                            NDIS_DEFAULT_PORT_NUMBER, sendFlags);
}

static __inline VOID
OvsStartNBLIngressError(POVS_SWITCH_CONTEXT switchContext,
                        PNET_BUFFER_LIST nblList,
                        ULONG sendCompleteFlags,
                        PNDIS_STRING filterReason,
                        NDIS_STATUS error)
{
    ASSERT(error);
    OvsReportNBLIngressError(switchContext, nblList, filterReason, error);
    NdisFSendNetBufferListsComplete(switchContext->NdisFilterHandle, nblList,
                                    sendCompleteFlags);
}

static VOID
OvsAppendNativeForwardedPacket(POVS_SWITCH_CONTEXT switchContext,
                               PNET_BUFFER_LIST curNbl,
                               PNET_BUFFER_LIST *nativeNbls,
                               ULONG flags,
                               BOOLEAN isRecv)
{
    POVS_BUFFER_CONTEXT ctx = { 0 };
    NDIS_STRING filterReason;

    *nativeNbls = curNbl;

    ctx = OvsInitExternalNBLContext(switchContext, curNbl, isRecv);
    if (ctx == NULL) {
        RtlInitUnicodeString(&filterReason,
                             L"Cannot allocate native NBL context.");

        OvsStartNBLIngressError(switchContext, curNbl, flags, &filterReason,
                                NDIS_STATUS_RESOURCES);
    }
}

static VOID
OvsStartNBLIngress(POVS_SWITCH_CONTEXT switchContext,
                   PNET_BUFFER_LIST netBufferLists,
                   ULONG SendFlags)
{
    NDIS_SWITCH_PORT_ID sourcePort = 0;
    NDIS_SWITCH_NIC_INDEX sourceIndex = 0;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail;
    PNET_BUFFER_LIST curNbl = NULL, nextNbl = NULL, lastNbl = NULL;
    ULONG sendCompleteFlags;
    UCHAR dispatch;
    LOCK_STATE_EX lockState, dpLockState;
    NDIS_STATUS status;
    NDIS_STRING filterReason;
    LIST_ENTRY missedPackets;
    UINT32 num = 0;
    OvsCompletionList completionList;
#if (NDIS_SUPPORT_NDIS640)
    PNET_BUFFER_LIST nativeForwardedNbls = NULL;
    PNET_BUFFER_LIST *nextNativeForwardedNbl = &nativeForwardedNbls;
#endif

    dispatch = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags)?
                                            NDIS_RWL_AT_DISPATCH_LEVEL : 0;
    sendCompleteFlags = OvsGetSendCompleteFlags(SendFlags);
    SendFlags |= NDIS_SEND_FLAGS_SWITCH_DESTINATION_GROUP;

    InitializeListHead(&missedPackets);
    OvsInitCompletionList(&completionList, switchContext, sendCompleteFlags);

    for (curNbl = netBufferLists; curNbl != NULL; curNbl = nextNbl) {
        POVS_VPORT_ENTRY vport = NULL;
        UINT32 portNo = 0;
        OVS_DATAPATH *datapath = &switchContext->datapath;
        OVS_PACKET_HDR_INFO layers = { 0 };
        OvsFlowKey key = { 0 };
        UINT64 hash = 0;
        PNET_BUFFER curNb = NULL;
        POVS_BUFFER_CONTEXT ctx = NULL;

        nextNbl = curNbl->Next;
        curNbl->Next = NULL;

        fwdDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(curNbl);
        sourcePort = fwdDetail->SourcePortId;
        sourceIndex = (NDIS_SWITCH_NIC_INDEX)fwdDetail->SourceNicIndex;

#if (NDIS_SUPPORT_NDIS640)
        if (fwdDetail->NativeForwardingRequired) {
            /* Add current NBL to those that require native forwarding. */
            OvsAppendNativeForwardedPacket(
                switchContext,
                curNbl,
                nextNativeForwardedNbl,
                sendCompleteFlags,
                OvsIsExternalVportByPortId(switchContext, sourcePort));
            continue;
        }
#endif /* NDIS_SUPPORT_NDIS640 */

        ctx = OvsInitExternalNBLContext(switchContext, curNbl,
                  OvsIsExternalVportByPortId(switchContext, sourcePort));
        if (ctx == NULL) {
            RtlInitUnicodeString(&filterReason,
                L"Cannot allocate external NBL context.");

            OvsStartNBLIngressError(switchContext, curNbl,
                                    sendCompleteFlags, &filterReason,
                                    NDIS_STATUS_RESOURCES);
            continue;
        }

        /* Ethernet Header is a guaranteed safe access. */
        curNb = NET_BUFFER_LIST_FIRST_NB(curNbl);
        if (curNb->Next != NULL) {
            /* Create a NET_BUFFER_LIST for each NET_BUFFER. */
            status = OvsCreateNewNBLsFromMultipleNBs(switchContext,
                                                     &curNbl,
                                                     &lastNbl);
            if (!NT_SUCCESS(status)) {
                RtlInitUnicodeString(&filterReason,
                                     L"Cannot allocate NBLs with single NB.");

                OvsStartNBLIngressError(switchContext, curNbl,
                                        sendCompleteFlags, &filterReason,
                                        NDIS_STATUS_RESOURCES);
                continue;
            }

            lastNbl->Next = nextNbl;
            nextNbl = curNbl->Next;
            curNbl->Next = NULL;
        }
        {
            OvsFlow *flow;

            /* Take the DispatchLock so none of the VPORTs disconnect while
             * we are setting destination ports.
             *
             * XXX: acquire/release the dispatch lock for a "batch" of packets
             * rather than for each packet. */
            NdisAcquireRWLockRead(switchContext->dispatchLock, &lockState,
                                  dispatch);

            vport = OvsFindVportByPortIdAndNicIndex(switchContext, sourcePort,
                                                    sourceIndex);
            if (vport == NULL || vport->ovsState != OVS_STATE_CONNECTED) {
                RtlInitUnicodeString(&filterReason,
                    L"OVS-Cannot forward packet from unknown source port");
                goto dropit;
            } else {
                portNo = vport->portNo;
            }

            vport->stats.rxPackets++;
            vport->stats.rxBytes += NET_BUFFER_DATA_LENGTH(curNb);

            status = OvsExtractFlow(curNbl, vport->portNo, &key, &layers, NULL);
            if (status != NDIS_STATUS_SUCCESS) {
                RtlInitUnicodeString(&filterReason, L"OVS-Flow extract failed");
                goto dropit;
            }

            ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
            OvsAcquireDatapathRead(datapath, &dpLockState, TRUE);

            flow = OvsLookupFlow(datapath, &key, &hash, FALSE);
            if (flow) {
                OvsFlowUsed(flow, curNbl, &layers);
                datapath->hits++;
                /* If successful, OvsActionsExecute() consumes the NBL.
                 * Otherwise, it adds it to the completionList. No need to
                 * check the return value. */
                OvsActionsExecute(switchContext, &completionList, curNbl,
                                  portNo, SendFlags, &key, &hash, &layers,
                                  flow->actions, flow->actionsLen);
                OvsReleaseDatapath(datapath, &dpLockState);
                NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
                continue;
            } else {
                OvsReleaseDatapath(datapath, &dpLockState);

                datapath->misses++;
                status = OvsCreateAndAddPackets(NULL, 0, OVS_PACKET_CMD_MISS,
                             vport, &key, curNbl,
                             OvsIsExternalVportByPortId(switchContext, sourcePort),
                             &layers, switchContext, &missedPackets, &num);
                if (status == NDIS_STATUS_SUCCESS) {
                    /* Complete the packet since it was copied to user
                     * buffer. */
                    RtlInitUnicodeString(&filterReason,
                        L"OVS-Dropped since packet was copied to userspace");
                } else {
                    RtlInitUnicodeString(&filterReason,
                        L"OVS-Dropped due to failure to queue to userspace");
                }
                goto dropit;
            }

dropit:
            OvsAddPktCompletionList(&completionList, TRUE, sourcePort, curNbl, 0,
                                    &filterReason);
            NdisReleaseRWLock(switchContext->dispatchLock, &lockState);
        }
    }

#if (NDIS_SUPPORT_NDIS640)
    if (nativeForwardedNbls) {
        /* This is NVGRE encapsulated traffic and is forwarded to NDIS
         * in order to be handled by the HNV module. */
        OvsSendNBLIngress(switchContext, nativeForwardedNbls, SendFlags);
    }
#endif /* NDIS_SUPPORT_NDIS640 */

    /* Queue the missed packets. */
    OvsQueuePackets(&missedPackets, num);
    OvsFinalizeCompletionList(&completionList);
}


/*
 * --------------------------------------------------------------------------
 * Implements filter driver's FilterSendNetBufferLists Function.
 * --------------------------------------------------------------------------
 */
VOID
OvsExtSendNBL(NDIS_HANDLE filterModuleContext,
              PNET_BUFFER_LIST netBufferLists,
              NDIS_PORT_NUMBER portNumber,
              ULONG sendFlags)
{
    UNREFERENCED_PARAMETER(portNumber);

    /* 'filterModuleContext' is the switch context that gets created in the
     * AttachHandler. */
    POVS_SWITCH_CONTEXT switchContext;
    switchContext = (POVS_SWITCH_CONTEXT) filterModuleContext;

    if (switchContext->dataFlowState == OvsSwitchPaused) {
        NDIS_STRING filterReason;
        ULONG sendCompleteFlags = OvsGetSendCompleteFlags(sendFlags);

        RtlInitUnicodeString(&filterReason,
                             L"Switch state PAUSED, drop on ingress.");
        OvsStartNBLIngressError(switchContext, netBufferLists,
                                sendCompleteFlags, &filterReason,
                                NDIS_STATUS_PAUSED);
        return;
    }

    ASSERT(switchContext->dataFlowState == OvsSwitchRunning);

    OvsStartNBLIngress(switchContext, netBufferLists, sendFlags);
}

static VOID
OvsCompleteNBLIngress(POVS_SWITCH_CONTEXT switchContext,
                      PNET_BUFFER_LIST netBufferLists,
                      ULONG sendCompleteFlags)
{
    PNET_BUFFER_LIST curNbl = NULL, nextNbl = NULL;
    OvsCompletionList newList;

    newList.dropNbl = NULL;
    newList.dropNblNext = &newList.dropNbl;

    for (curNbl = netBufferLists; curNbl != NULL; curNbl = nextNbl) {
        nextNbl = curNbl->Next;
        curNbl->Next = NULL;

        curNbl = OvsCompleteNBL(switchContext, curNbl, TRUE);
        if (curNbl != NULL) {
            /* NBL originated from the upper layer. */
            *newList.dropNblNext = curNbl;
            newList.dropNblNext = &curNbl->Next;
        }
    }

    /* Complete the NBL's that were sent by the upper layer. */
    if (newList.dropNbl != NULL) {
        NdisFSendNetBufferListsComplete(switchContext->NdisFilterHandle, newList.dropNbl,
                                        sendCompleteFlags);
    }
}


/*
 * --------------------------------------------------------------------------
 * Implements filter driver's FilterSendNetBufferListsComplete function.
 * --------------------------------------------------------------------------
 */
VOID
OvsExtSendNBLComplete(NDIS_HANDLE filterModuleContext,
                      PNET_BUFFER_LIST netBufferLists,
                      ULONG sendCompleteFlags)
{
    OvsCompleteNBLIngress((POVS_SWITCH_CONTEXT)filterModuleContext,
                          netBufferLists, sendCompleteFlags);
}


VOID
OvsFinalizeCompletionList(OvsCompletionList *completionList)
{
    if (completionList->dropNbl != NULL) {
        OvsCompleteNBLIngress(completionList->switchContext,
                              completionList->dropNbl,
                              completionList->sendCompleteFlags);

        completionList->dropNbl = NULL;
        completionList->dropNblNext = &completionList->dropNbl;
    }
}

/*
 * --------------------------------------------------------------------------
 * Implements filter driver's FilterCancelSendNetBufferLists function.
 *
 * "If a filter driver specifies a FilterSendNetBufferLists function and it
 * queues send requests, it must also specify a
 * FilterCancelSendNetBufferLists function."
 *
 * http://msdn.microsoft.com/en-us/library/windows/hardware/
 * ff549966(v=vs.85).aspx
 * --------------------------------------------------------------------------
 */
VOID
OvsExtCancelSendNBL(NDIS_HANDLE filterModuleContext,
                    PVOID CancelId)
{
    UNREFERENCED_PARAMETER(filterModuleContext);
    UNREFERENCED_PARAMETER(CancelId);

    /* All send requests get completed synchronously, so there is no need to
     * implement this callback. */
}
