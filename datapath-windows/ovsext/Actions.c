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

#include "Switch.h"
#include "Vport.h"
#include "Event.h"
#include "User.h"
#include "NetProto.h"
#include "Flow.h"
#include "Vxlan.h"
#include "Checksum.h"
#include "PacketIO.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_ACTION
#include "Debug.h"

typedef struct _OVS_ACTION_STATS {
    UINT64 rxVxlan;
    UINT64 txVxlan;
    UINT64 flowMiss;
    UINT64 flowUserspace;
    UINT64 txTcp;
    UINT32 failedFlowMiss;
    UINT32 noVport;
    UINT32 failedFlowExtract;
    UINT32 noResource;
    UINT32 noCopiedNbl;
    UINT32 failedEncap;
    UINT32 failedDecap;
    UINT32 cannotGrowDest;
    UINT32 zeroActionLen;
    UINT32 failedChecksum;
} OVS_ACTION_STATS, *POVS_ACTION_STATS;

OVS_ACTION_STATS ovsActionStats;

/*
 * There a lot of data that needs to be maintained while executing the pipeline
 * as dictated by the actions of a flow, across different functions at different
 * levels. Such data is put together in a 'context' structure. Care should be
 * exercised while adding new members to the structure - only add ones that get
 * used across multiple stages in the pipeline/get used in multiple functions.
 */
#define OVS_DEST_PORTS_ARRAY_MIN_SIZE 2
typedef struct OvsForwardingContext {
    POVS_SWITCH_CONTEXT switchContext;
    /* The NBL currently used in the pipeline. */
    PNET_BUFFER_LIST curNbl;
    /* NDIS forwarding detail for 'curNbl'. */
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail;
    /* Array of destination ports for 'curNbl'. */
    PNDIS_SWITCH_FORWARDING_DESTINATION_ARRAY destinationPorts;
    /* send flags while sending 'curNbl' into NDIS. */
    ULONG sendFlags;
    /* Total number of output ports, used + unused, in 'curNbl'. */
    UINT32 destPortsSizeIn;
    /* Total number of used output ports in 'curNbl'. */
    UINT32 destPortsSizeOut;
    /*
     * If 'curNbl' is not owned by OVS, they need to be tracked, if they need to
     * be freed/completed.
     */
    OvsCompletionList *completionList;
    /*
     * vport number of 'curNbl' when it is passed from the PIF bridge to the INT
     * bridge. ie. during tunneling on the Rx side.
     */
    UINT32 srcVportNo;

    /*
     * Tunnel key:
     * - specified in actions during tunneling Tx
     * - extracted from an NBL during tunneling Rx
     */
    OvsIPv4TunnelKey tunKey;

     /*
     * Tunneling - Tx:
     * To store the output port, when it is a tunneled port. We don't foresee
     * multiple tunneled ports as outport for any given NBL.
     */
    POVS_VPORT_ENTRY tunnelTxNic;

    /*
     * Tunneling - Rx:
     * Points to the Internal port on the PIF Bridge, if the packet needs to be
     * de-tunneled.
     */
    POVS_VPORT_ENTRY tunnelRxNic;

    /* header information */
    OVS_PACKET_HDR_INFO layers;
} OvsForwardingContext;


/*
 * --------------------------------------------------------------------------
 * OvsInitForwardingCtx --
 *     Function to init/re-init the 'ovsFwdCtx' context as the actions pipeline
 *     is being executed.
 *
 * Result:
 *     NDIS_STATUS_SUCCESS on success
 *     Other NDIS_STATUS upon failure. Upon failure, it is safe to call
 *     OvsCompleteNBLForwardingCtx(), since 'ovsFwdCtx' has been initialized
 *     enough for OvsCompleteNBLForwardingCtx() to do its work.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsInitForwardingCtx(OvsForwardingContext *ovsFwdCtx,
                     POVS_SWITCH_CONTEXT switchContext,
                     PNET_BUFFER_LIST curNbl,
                     UINT32 srcVportNo,
                     ULONG sendFlags,
                     PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail,
                     OvsCompletionList *completionList,
                     OVS_PACKET_HDR_INFO *layers,
                     BOOLEAN resetTunnelInfo)
{
    ASSERT(ovsFwdCtx);
    ASSERT(switchContext);
    ASSERT(curNbl);
    ASSERT(fwdDetail);

    /*
     * Set values for curNbl and switchContext so upon failures, we have enough
     * information to do cleanup.
     */
    ovsFwdCtx->curNbl = curNbl;
    ovsFwdCtx->switchContext = switchContext;
    ovsFwdCtx->completionList = completionList;
    ovsFwdCtx->fwdDetail = fwdDetail;

    if (fwdDetail->NumAvailableDestinations > 0) {
        /*
         * XXX: even though MSDN says GetNetBufferListDestinations() returns
         * NDIS_STATUS, the header files say otherwise.
         */
        switchContext->NdisSwitchHandlers.GetNetBufferListDestinations(
            switchContext->NdisSwitchContext, curNbl,
            &ovsFwdCtx->destinationPorts);

        ASSERT(ovsFwdCtx->destinationPorts);
        /* Ensure that none of the elements are consumed yet. */
        ASSERT(ovsFwdCtx->destinationPorts->NumElements ==
               fwdDetail->NumAvailableDestinations);
    } else {
        ovsFwdCtx->destinationPorts = NULL;
    }
    ovsFwdCtx->destPortsSizeIn = fwdDetail->NumAvailableDestinations;
    ovsFwdCtx->destPortsSizeOut = 0;
    ovsFwdCtx->srcVportNo = srcVportNo;
    ovsFwdCtx->sendFlags = sendFlags;
    if (layers) {
        ovsFwdCtx->layers = *layers;
    } else {
        RtlZeroMemory(&ovsFwdCtx->layers, sizeof ovsFwdCtx->layers);
    }
    if (resetTunnelInfo) {
        ovsFwdCtx->tunnelTxNic = NULL;
        ovsFwdCtx->tunnelRxNic = NULL;
        RtlZeroMemory(&ovsFwdCtx->tunKey, sizeof ovsFwdCtx->tunKey);
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 * XXX: When we search for the tunnelVport we also need to specify the
 * tunnelling protocol or the L4 protocol as key as well, because there are
 * different protocols that can use the same destination port.
 * --------------------------------------------------------------------------
 * OvsDetectTunnelRxPkt --
 *     Utility function for an RX packet to detect its tunnel type.
 *
 * Result:
 *  True  - if the tunnel type was detected.
 *  False - if not a tunnel packet or tunnel type not supported.
 * --------------------------------------------------------------------------
 */
static __inline BOOLEAN
OvsDetectTunnelRxPkt(OvsForwardingContext *ovsFwdCtx,
                     const OvsFlowKey *flowKey)
{
    POVS_VPORT_ENTRY tunnelVport = NULL;

    /* XXX: we should also check for the length of the UDP payload to pick
     * packets only if they are at least VXLAN header size.
     */
    if (!flowKey->ipKey.nwFrag &&
        flowKey->ipKey.nwProto == IPPROTO_UDP) {
        UINT16 dstPort = htons(flowKey->ipKey.l4.tpDst);
        tunnelVport = OvsFindTunnelVportByDstPort(ovsFwdCtx->switchContext,
                                                  dstPort);
    }

    // We might get tunnel packets even before the tunnel gets initialized.
    if (tunnelVport) {
        ASSERT(ovsFwdCtx->tunnelRxNic == NULL);
        ovsFwdCtx->tunnelRxNic = tunnelVport;
        ovsActionStats.rxVxlan++;
        return TRUE;
    }

    return FALSE;
}

/*
 * --------------------------------------------------------------------------
 * OvsDetectTunnelPkt --
 *     Utility function to detect if a packet is to be subjected to
 *     tunneling (Tx) or de-tunneling (Rx). Various factors such as source
 *     port, destination port, packet contents, and previously setup tunnel
 *     context are used.
 *
 * Result:
 *  True  - If the packet is to be subjected to tunneling.
 *          In case of invalid tunnel context, the tunneling functionality is
 *          a no-op and is completed within this function itself by consuming
 *          all of the tunneling context.
 *  False - If not a tunnel packet or tunnel type not supported. Caller should
 *          process the packet as a non-tunnel packet.
 * --------------------------------------------------------------------------
 */
static __inline BOOLEAN
OvsDetectTunnelPkt(OvsForwardingContext *ovsFwdCtx,
                   const POVS_VPORT_ENTRY dstVport,
                   const OvsFlowKey *flowKey)
{
    if (OvsIsInternalVportType(dstVport->ovsType)) {
        /*
         * Rx:
         * The source of NBL during tunneling Rx could be the external
         * port or if it is being executed from userspace, the source port is
         * default port.
         */
        BOOLEAN validSrcPort =
            (ovsFwdCtx->fwdDetail->SourcePortId ==
                 ovsFwdCtx->switchContext->virtualExternalPortId) ||
            (ovsFwdCtx->fwdDetail->SourcePortId ==
                 NDIS_SWITCH_DEFAULT_PORT_ID);

        if (validSrcPort && OvsDetectTunnelRxPkt(ovsFwdCtx, flowKey)) {
            ASSERT(ovsFwdCtx->tunnelTxNic == NULL);
            ASSERT(ovsFwdCtx->tunnelRxNic != NULL);
            return TRUE;
        }
    } else if (OvsIsTunnelVportType(dstVport->ovsType)) {
        ASSERT(ovsFwdCtx->tunnelTxNic == NULL);
        ASSERT(ovsFwdCtx->tunnelRxNic == NULL);

        /*
         * Tx:
         * The destination port is a tunnel port. Encapsulation must be
         * performed only on packets that originate from:
         * - a VIF port
         * - a bridge-internal port (packets generated from userspace)
         * - no port.
         *
         * If the packet will not be encapsulated, consume the tunnel context
         * by clearing it.
         */
        if (ovsFwdCtx->srcVportNo != OVS_DEFAULT_PORT_NO) {

            POVS_VPORT_ENTRY vport = OvsFindVportByPortNo(
                ovsFwdCtx->switchContext, ovsFwdCtx->srcVportNo);

            if (!vport ||
                (vport->ovsType != OVS_VPORT_TYPE_NETDEV &&
                 !OvsIsBridgeInternalVport(vport))) {
                ovsFwdCtx->tunKey.dst = 0;
            }
        }

        /* Tunnel the packet only if tunnel context is set. */
        if (ovsFwdCtx->tunKey.dst != 0) {
            ovsActionStats.txVxlan++;
            ovsFwdCtx->tunnelTxNic = dstVport;
        }

        return TRUE;
    }

    return FALSE;
}


/*
 * --------------------------------------------------------------------------
 * OvsAddPorts --
 *     Add the specified destination vport into the forwarding context. If the
 *     vport is a VIF/external port, it is added directly to the NBL. If it is
 *     a tunneling port, it is NOT added to the NBL.
 *
 * Result:
 *     NDIS_STATUS_SUCCESS on success
 *     Other NDIS_STATUS upon failure.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsAddPorts(OvsForwardingContext *ovsFwdCtx,
            OvsFlowKey *flowKey,
            NDIS_SWITCH_PORT_ID dstPortId,
            BOOLEAN preserveVLAN,
            BOOLEAN preservePriority)
{
    POVS_VPORT_ENTRY vport;
    PNDIS_SWITCH_PORT_DESTINATION fwdPort;
    NDIS_STATUS status;
    POVS_SWITCH_CONTEXT switchContext = ovsFwdCtx->switchContext;

    /*
     * We hold the dispatch lock that protects the list of vports, so vports
     * validated here can be added as destinations safely before we call into
     * NDIS.
     *
     * Some of the vports can be tunnelled ports as well in which case
     * they should be added to a separate list of tunnelled destination ports
     * instead of the VIF ports. The context for the tunnel is settable
     * in OvsForwardingContext.
     */
    vport = OvsFindVportByPortNo(ovsFwdCtx->switchContext, dstPortId);
    if (vport == NULL || vport->ovsState != OVS_STATE_CONNECTED) {
        /*
         * There may be some latency between a port disappearing, and userspace
         * updating the recalculated flows. In the meantime, handle invalid
         * ports gracefully.
         */
        ovsActionStats.noVport++;
        return NDIS_STATUS_SUCCESS;
    }
    ASSERT(vport->nicState == NdisSwitchNicStateConnected);
    vport->stats.txPackets++;
    vport->stats.txBytes +=
        NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl));

    if (OvsIsBridgeInternalVport(vport)) {
        return NDIS_STATUS_SUCCESS;
    }

    if (OvsDetectTunnelPkt(ovsFwdCtx, vport, flowKey)) {
        return NDIS_STATUS_SUCCESS;
    }

    if (ovsFwdCtx->destPortsSizeOut == ovsFwdCtx->destPortsSizeIn) {
        if (ovsFwdCtx->destPortsSizeIn == 0) {
            ASSERT(ovsFwdCtx->destinationPorts == NULL);
            ASSERT(ovsFwdCtx->fwdDetail->NumAvailableDestinations == 0);
            status =
                switchContext->NdisSwitchHandlers.GrowNetBufferListDestinations(
                    switchContext->NdisSwitchContext, ovsFwdCtx->curNbl,
                    OVS_DEST_PORTS_ARRAY_MIN_SIZE,
                    &ovsFwdCtx->destinationPorts);
            if (status != NDIS_STATUS_SUCCESS) {
                ovsActionStats.cannotGrowDest++;
                return status;
            }
            ovsFwdCtx->destPortsSizeIn =
                ovsFwdCtx->fwdDetail->NumAvailableDestinations;
            ASSERT(ovsFwdCtx->destinationPorts);
        } else {
            ASSERT(ovsFwdCtx->destinationPorts != NULL);
            /*
             * NumElements:
             * A ULONG value that specifies the total number of
             * NDIS_SWITCH_PORT_DESTINATION elements in the
             * NDIS_SWITCH_FORWARDING_DESTINATION_ARRAY structure.
             *
             * NumDestinations:
             * A ULONG value that specifies the number of
             * NDIS_SWITCH_PORT_DESTINATION elements in the
             * NDIS_SWITCH_FORWARDING_DESTINATION_ARRAY structure that
             * specify port destinations.
             *
             * NumAvailableDestinations:
             * A value that specifies the number of unused extensible switch
             * destination ports elements within an NET_BUFFER_LIST structure.
             */
            ASSERT(ovsFwdCtx->destinationPorts->NumElements ==
                   ovsFwdCtx->destPortsSizeIn);
            ASSERT(ovsFwdCtx->destinationPorts->NumDestinations ==
                   ovsFwdCtx->destPortsSizeOut -
                   ovsFwdCtx->fwdDetail->NumAvailableDestinations);
            ASSERT(ovsFwdCtx->fwdDetail->NumAvailableDestinations > 0);
            /*
             * Before we grow the array of destination ports, the current set
             * of ports needs to be committed. Only the ports added since the
             * last commit need to be part of the new update.
             */
            status = switchContext->NdisSwitchHandlers.UpdateNetBufferListDestinations(
                switchContext->NdisSwitchContext, ovsFwdCtx->curNbl,
                ovsFwdCtx->fwdDetail->NumAvailableDestinations,
                ovsFwdCtx->destinationPorts);
            if (status != NDIS_STATUS_SUCCESS) {
                ovsActionStats.cannotGrowDest++;
                return status;
            }
            ASSERT(ovsFwdCtx->destinationPorts->NumElements ==
                   ovsFwdCtx->destPortsSizeIn);
            ASSERT(ovsFwdCtx->destinationPorts->NumDestinations ==
                   ovsFwdCtx->destPortsSizeOut);
            ASSERT(ovsFwdCtx->fwdDetail->NumAvailableDestinations == 0);

            status = switchContext->NdisSwitchHandlers.GrowNetBufferListDestinations(
                switchContext->NdisSwitchContext, ovsFwdCtx->curNbl,
                ovsFwdCtx->destPortsSizeIn, &ovsFwdCtx->destinationPorts);
            if (status != NDIS_STATUS_SUCCESS) {
                ovsActionStats.cannotGrowDest++;
                return status;
            }
            ASSERT(ovsFwdCtx->destinationPorts != NULL);
            ovsFwdCtx->destPortsSizeIn <<= 1;
        }
    }

    ASSERT(ovsFwdCtx->destPortsSizeOut < ovsFwdCtx->destPortsSizeIn);
    fwdPort =
        NDIS_SWITCH_PORT_DESTINATION_AT_ARRAY_INDEX(ovsFwdCtx->destinationPorts,
                                                    ovsFwdCtx->destPortsSizeOut);

    fwdPort->PortId = vport->portId;
    fwdPort->NicIndex = vport->nicIndex;
    fwdPort->IsExcluded = 0;
    fwdPort->PreserveVLAN = preserveVLAN;
    fwdPort->PreservePriority = preservePriority;
    ovsFwdCtx->destPortsSizeOut += 1;

    return NDIS_STATUS_SUCCESS;
}


/*
 * --------------------------------------------------------------------------
 * OvsClearTunTxCtx --
 *     Utility function to clear tx tunneling context.
 * --------------------------------------------------------------------------
 */
static __inline VOID
OvsClearTunTxCtx(OvsForwardingContext *ovsFwdCtx)
{
    ovsFwdCtx->tunnelTxNic = NULL;
    ovsFwdCtx->tunKey.dst = 0;
}


/*
 * --------------------------------------------------------------------------
 * OvsClearTunRxCtx --
 *     Utility function to clear rx tunneling context.
 * --------------------------------------------------------------------------
 */
static __inline VOID
OvsClearTunRxCtx(OvsForwardingContext *ovsFwdCtx)
{
    ovsFwdCtx->tunnelRxNic = NULL;
    ovsFwdCtx->tunKey.dst = 0;
}


/*
 * --------------------------------------------------------------------------
 * OvsCompleteNBLForwardingCtx --
 *     This utility function is responsible for freeing/completing an NBL - either
 *     by adding it to a completion list or by freeing it.
 *
 * Side effects:
 *     It also resets the necessary fields in 'ovsFwdCtx'.
 * --------------------------------------------------------------------------
 */
static __inline VOID
OvsCompleteNBLForwardingCtx(OvsForwardingContext *ovsFwdCtx,
                            PCWSTR dropReason)
{
    NDIS_STRING filterReason;

    RtlInitUnicodeString(&filterReason, dropReason);
    if (ovsFwdCtx->completionList) {
        OvsAddPktCompletionList(ovsFwdCtx->completionList, TRUE,
            ovsFwdCtx->fwdDetail->SourcePortId, ovsFwdCtx->curNbl, 1,
            &filterReason);
        ovsFwdCtx->curNbl = NULL;
    } else {
        /* If there is no completionList, we assume this is ovs created NBL */
        ovsFwdCtx->curNbl = OvsCompleteNBL(ovsFwdCtx->switchContext,
                                           ovsFwdCtx->curNbl, TRUE);
        ASSERT(ovsFwdCtx->curNbl == NULL);
    }
    /* XXX: these can be made debug only to save cycles. Ideally the pipeline
     * using these fields should reset the values at the end of the pipeline. */
    ovsFwdCtx->destPortsSizeOut = 0;
    ovsFwdCtx->tunnelTxNic = NULL;
    ovsFwdCtx->tunnelRxNic = NULL;
}

/*
 * --------------------------------------------------------------------------
 * OvsDoFlowLookupOutput --
 *     Function to be used for the second stage of a tunneling workflow, ie.:
 *     - On the encapsulated packet on Tx path, to do a flow extract, flow
 *       lookup and excuting the actions.
 *     - On the decapsulated packet on Rx path, to do a flow extract, flow
 *       lookup and excuting the actions.
 *
 *     XXX: It is assumed that the NBL in 'ovsFwdCtx' is owned by OVS. This is
 *     until the new buffer management framework is adopted.
 *
 * Side effects:
 *     The NBL in 'ovsFwdCtx' is consumed.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsDoFlowLookupOutput(OvsForwardingContext *ovsFwdCtx)
{
    OvsFlowKey key;
    OvsFlow *flow;
    UINT64 hash;
    NDIS_STATUS status;
    POVS_VPORT_ENTRY vport =
        OvsFindVportByPortNo(ovsFwdCtx->switchContext, ovsFwdCtx->srcVportNo);
    if (vport == NULL || vport->ovsState != OVS_STATE_CONNECTED) {
        ASSERT(FALSE);  // XXX: let's catch this for now
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
            L"OVS-Dropped due to internal/tunnel port removal");
        ovsActionStats.noVport++;
        return NDIS_STATUS_SUCCESS;
    }
    ASSERT(vport->nicState == NdisSwitchNicStateConnected);

    /* Assert that in the Rx direction, key is always setup. */
    ASSERT(ovsFwdCtx->tunnelRxNic == NULL || ovsFwdCtx->tunKey.dst != 0);
    status = OvsExtractFlow(ovsFwdCtx->curNbl, ovsFwdCtx->srcVportNo,
                          &key, &ovsFwdCtx->layers, ovsFwdCtx->tunKey.dst != 0 ?
                                         &ovsFwdCtx->tunKey : NULL);
    if (status != NDIS_STATUS_SUCCESS) {
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                    L"OVS-Flow extract failed");
        ovsActionStats.failedFlowExtract++;
        return status;
    }

    flow = OvsLookupFlow(&ovsFwdCtx->switchContext->datapath, &key, &hash, FALSE);
    if (flow) {
        OvsFlowUsed(flow, ovsFwdCtx->curNbl, &ovsFwdCtx->layers);
        ovsFwdCtx->switchContext->datapath.hits++;
        status = OvsActionsExecute(ovsFwdCtx->switchContext,
                                 ovsFwdCtx->completionList, ovsFwdCtx->curNbl,
                                 ovsFwdCtx->srcVportNo, ovsFwdCtx->sendFlags,
                                 &key, &hash, &ovsFwdCtx->layers,
                                 flow->actions, flow->actionsLen);
        ovsFwdCtx->curNbl = NULL;
    } else {
        LIST_ENTRY missedPackets;
        UINT32 num = 0;
        ovsFwdCtx->switchContext->datapath.misses++;
        InitializeListHead(&missedPackets);
        status = OvsCreateAndAddPackets(NULL, 0, OVS_PACKET_CMD_MISS,
                          ovsFwdCtx->srcVportNo,
                          &key,ovsFwdCtx->curNbl,
                          ovsFwdCtx->tunnelRxNic != NULL, &ovsFwdCtx->layers,
                          ovsFwdCtx->switchContext, &missedPackets, &num);
        if (num) {
            OvsQueuePackets(&missedPackets, num);
        }
        if (status == NDIS_STATUS_SUCCESS) {
            /* Complete the packet since it was copied to user buffer. */
            OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                L"OVS-Dropped since packet was copied to userspace");
            ovsActionStats.flowMiss++;
            status = NDIS_STATUS_SUCCESS;
        } else {
            OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                L"OVS-Dropped due to failure to queue to userspace");
            status = NDIS_STATUS_FAILURE;
            ovsActionStats.failedFlowMiss++;
        }
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsTunnelPortTx --
 *     The start function for Tx tunneling - encapsulates the packet, and
 *     outputs the packet on the PIF bridge.
 *
 * Side effects:
 *     The NBL in 'ovsFwdCtx' is consumed.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsTunnelPortTx(OvsForwardingContext *ovsFwdCtx)
{
    NDIS_STATUS status = NDIS_STATUS_FAILURE;
    PNET_BUFFER_LIST newNbl = NULL;

    /*
     * Setup the source port to be the internal port to as to facilitate the
     * second OvsLookupFlow.
     */
    if (ovsFwdCtx->switchContext->internalVport == NULL) {
        OvsClearTunTxCtx(ovsFwdCtx);
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
            L"OVS-Dropped since internal port is absent");
        return NDIS_STATUS_FAILURE;
    }
    ovsFwdCtx->srcVportNo =
        ((POVS_VPORT_ENTRY)ovsFwdCtx->switchContext->internalVport)->portNo;

    ovsFwdCtx->fwdDetail->SourcePortId = ovsFwdCtx->switchContext->internalPortId;
    ovsFwdCtx->fwdDetail->SourceNicIndex =
        ((POVS_VPORT_ENTRY)ovsFwdCtx->switchContext->internalVport)->nicIndex;

    /* Do the encap. Encap function does not consume the NBL. */
    switch(ovsFwdCtx->tunnelTxNic->ovsType) {
    case OVS_VPORT_TYPE_VXLAN:
        status = OvsEncapVxlan(ovsFwdCtx->curNbl, &ovsFwdCtx->tunKey,
                               ovsFwdCtx->switchContext,
                               (VOID *)ovsFwdCtx->completionList,
                               &ovsFwdCtx->layers, &newNbl);
        break;
    default:
        ASSERT(! "Tx: Unhandled tunnel type");
    }

    /* Reset the tunnel context so that it doesn't get used after this point. */
    OvsClearTunTxCtx(ovsFwdCtx);

    if (status == NDIS_STATUS_SUCCESS) {
        ASSERT(newNbl);
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                    L"Complete after cloning NBL for encapsulation");
        ovsFwdCtx->curNbl = newNbl;
        status = OvsDoFlowLookupOutput(ovsFwdCtx);
        ASSERT(ovsFwdCtx->curNbl == NULL);
    } else {
        /*
        * XXX: Temporary freeing of the packet until we register a
         * callback to IP helper.
         */
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                    L"OVS-Dropped due to encap failure");
        ovsActionStats.failedEncap++;
        status = NDIS_STATUS_SUCCESS;
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsTunnelPortRx --
 *     Decapsulate the incoming NBL based on the tunnel type and goes through
 *     the flow lookup for the inner packet.
 *
 *     Note: IP checksum is validate here, but L4 checksum validation needs
 *     to be done by the corresponding tunnel types.
 *
 * Side effects:
 *     The NBL in 'ovsFwdCtx' is consumed.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsTunnelPortRx(OvsForwardingContext *ovsFwdCtx)
{
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PNET_BUFFER_LIST newNbl = NULL;
    POVS_VPORT_ENTRY tunnelRxVport = ovsFwdCtx->tunnelRxNic;

    if (OvsValidateIPChecksum(ovsFwdCtx->curNbl, &ovsFwdCtx->layers)
            != NDIS_STATUS_SUCCESS) {
        ovsActionStats.failedChecksum++;
        OVS_LOG_INFO("Packet dropped due to IP checksum failure.");
        goto dropNbl;
    }

    switch(tunnelRxVport->ovsType) {
    case OVS_VPORT_TYPE_VXLAN:
        /*
         * OvsDoDecapVxlan should return a new NBL if it was copied, and
         * this new NBL should be setup as the ovsFwdCtx->curNbl.
         */
        status = OvsDoDecapVxlan(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                                                &ovsFwdCtx->tunKey, &newNbl);
        break;
    default:
        OVS_LOG_ERROR("Rx: Unhandled tunnel type: %d\n",
                      tunnelRxVport->ovsType);
        ASSERT(! "Rx: Unhandled tunnel type");
        status = NDIS_STATUS_NOT_SUPPORTED;
    }

    if (status != NDIS_STATUS_SUCCESS) {
        ovsActionStats.failedDecap++;
        goto dropNbl;
    }

    /*
     * tunnelRxNic and other fields will be cleared, re-init the context
     * before usage.
      */
    OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                L"OVS-dropped due to new decap packet");

    /* Decapsulated packet is in a new NBL */
    ovsFwdCtx->tunnelRxNic = tunnelRxVport;
    OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext,
                         newNbl, tunnelRxVport->portNo, 0,
                         NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                         ovsFwdCtx->completionList,
                         &ovsFwdCtx->layers, FALSE);

    /*
     * Set the NBL's SourcePortId and SourceNicIndex to default values to
     * keep NDIS happy when we forward the packet.
     */
    ovsFwdCtx->fwdDetail->SourcePortId = NDIS_SWITCH_DEFAULT_PORT_ID;
    ovsFwdCtx->fwdDetail->SourceNicIndex = 0;

    status = OvsDoFlowLookupOutput(ovsFwdCtx);
    ASSERT(ovsFwdCtx->curNbl == NULL);
    OvsClearTunRxCtx(ovsFwdCtx);

    return status;

dropNbl:
    OvsCompleteNBLForwardingCtx(ovsFwdCtx,
            L"OVS-dropped due to decap failure");
    OvsClearTunRxCtx(ovsFwdCtx);
    return status;
}


/*
 * --------------------------------------------------------------------------
 * OvsOutputForwardingCtx --
 *     This function outputs an NBL to NDIS or to a tunneling pipeline based on
 *     the ports added so far into 'ovsFwdCtx'.
 *
 * Side effects:
 *     This function consumes the NBL - either by forwarding it successfully to
 *     NDIS, or adding it to the completion list in 'ovsFwdCtx', or freeing it.
 *
 *     Also makes sure that the list of destination ports - tunnel or otherwise is
 *     drained.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsOutputForwardingCtx(OvsForwardingContext *ovsFwdCtx)
{
    NDIS_STATUS status = STATUS_SUCCESS;
    POVS_SWITCH_CONTEXT switchContext = ovsFwdCtx->switchContext;
    PCWSTR dropReason;

    /*
     * Handle the case where the some of the destination ports are tunneled
     * ports - the non-tunneled ports get a unmodified copy of the NBL, and the
     * tunneling pipeline starts when we output the packet to tunneled port.
     */
    if (ovsFwdCtx->destPortsSizeOut > 0) {
        PNET_BUFFER_LIST newNbl = NULL;
        PNET_BUFFER nb;
        UINT32 portsToUpdate =
            ovsFwdCtx->fwdDetail->NumAvailableDestinations -
            (ovsFwdCtx->destPortsSizeIn - ovsFwdCtx->destPortsSizeOut);

        ASSERT(ovsFwdCtx->destinationPorts != NULL);

        /*
         * Create a copy of the packet in order to do encap on it later. Also,
         * don't copy the offload context since the encap'd packet has a
         * different set of headers. This will change when we implement offloads
         * before doing encapsulation.
         */
        if (ovsFwdCtx->tunnelTxNic != NULL || ovsFwdCtx->tunnelRxNic != NULL) {
            nb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
            newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                                       0, 0, TRUE /*copy NBL info*/);
            if (newNbl == NULL) {
                status = NDIS_STATUS_RESOURCES;
                ovsActionStats.noCopiedNbl++;
                dropReason = L"Dropped due to failure to create NBL copy.";
                goto dropit;
            }
        }

        /* It does not seem like we'll get here unless 'portsToUpdate' > 0. */
        ASSERT(portsToUpdate > 0);
        status = switchContext->NdisSwitchHandlers.UpdateNetBufferListDestinations(
            switchContext->NdisSwitchContext, ovsFwdCtx->curNbl,
            portsToUpdate, ovsFwdCtx->destinationPorts);
        if (status != NDIS_STATUS_SUCCESS) {
            OvsCompleteNBL(ovsFwdCtx->switchContext, newNbl, TRUE);
            ovsActionStats.cannotGrowDest++;
            dropReason = L"Dropped due to failure to update destinations.";
            goto dropit;
        }

        OvsSendNBLIngress(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                          ovsFwdCtx->sendFlags);
        /* End this pipeline by resetting the corresponding context. */
        ovsFwdCtx->destPortsSizeOut = 0;
        ovsFwdCtx->curNbl = NULL;
        if (newNbl) {
            status = OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext,
                                          newNbl, ovsFwdCtx->srcVportNo, 0,
                                          NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                                          ovsFwdCtx->completionList,
                                          &ovsFwdCtx->layers, FALSE);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"Dropped due to resouces.";
                goto dropit;
            }
        }
    }

    if (ovsFwdCtx->tunnelTxNic != NULL) {
        status = OvsTunnelPortTx(ovsFwdCtx);
        ASSERT(ovsFwdCtx->tunnelTxNic == NULL);
        ASSERT(ovsFwdCtx->tunKey.dst == 0);
    } else if (ovsFwdCtx->tunnelRxNic != NULL) {
        status = OvsTunnelPortRx(ovsFwdCtx);
        ASSERT(ovsFwdCtx->tunnelRxNic == NULL);
        ASSERT(ovsFwdCtx->tunKey.dst == 0);
    }
    ASSERT(ovsFwdCtx->curNbl == NULL);

    return status;

dropit:
    if (status != NDIS_STATUS_SUCCESS) {
        OvsCompleteNBLForwardingCtx(ovsFwdCtx, dropReason);
    }

    return status;
}


/*
 * --------------------------------------------------------------------------
 * OvsLookupFlowOutput --
 *     Utility function for external callers to do flow extract, lookup,
 *     actions execute on a given NBL.
 *
 *     Note: If this is being used from a callback function, make sure that the
 *     arguments specified are still valid in the asynchronous context.
 *
 * Side effects:
 *     This function consumes the NBL.
 * --------------------------------------------------------------------------
 */
VOID
OvsLookupFlowOutput(POVS_SWITCH_CONTEXT switchContext,
                    VOID *compList,
                    PNET_BUFFER_LIST curNbl)
{
    NDIS_STATUS status;
    OvsForwardingContext ovsFwdCtx;
    POVS_VPORT_ENTRY internalVport =
        (POVS_VPORT_ENTRY)switchContext->internalVport;

    /* XXX: make sure comp list was not a stack variable previously. */
    OvsCompletionList *completionList = (OvsCompletionList *)compList;

    /*
     * XXX: can internal port disappear while we are busy doing ARP resolution?
     * It could, but will we get this callback from IP helper in that case. Need
     * to check.
     */
    ASSERT(switchContext->internalVport);
    status = OvsInitForwardingCtx(&ovsFwdCtx, switchContext, curNbl,
                                  internalVport->portNo, 0,
                                  NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(curNbl),
                                  completionList, NULL, TRUE);
    if (status != NDIS_STATUS_SUCCESS) {
        OvsCompleteNBLForwardingCtx(&ovsFwdCtx,
                                    L"OVS-Dropped due to resources");
        return;
    }

    ASSERT(FALSE);
    /*
     * XXX: We need to acquire the dispatch lock and the datapath lock.
     */

    OvsDoFlowLookupOutput(&ovsFwdCtx);
}


/*
 * --------------------------------------------------------------------------
 * OvsOutputBeforeSetAction --
 *     Function to be called to complete one set of actions on an NBL, before
 *     we start the next one.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsOutputBeforeSetAction(OvsForwardingContext *ovsFwdCtx)
{
    PNET_BUFFER_LIST newNbl;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PNET_BUFFER nb;

    /*
     * Create a copy and work on the copy after this point. The original NBL is
     * forwarded. One reason to not use the copy for forwarding is that
     * ports have already been added to the original NBL, and it might be
     * inefficient/impossible to remove/re-add them to the copy. There's no
     * notion of removing the ports, the ports need to be marked as
     * "isExcluded". There's seems no real advantage to retaining the original
     * and sending out the copy instead.
     *
     * XXX: We are copying the offload context here. This is to handle actions
     * such as:
     * outport, pop_vlan(), outport, push_vlan(), outport
     *
     * copy size needs to include inner ether + IP + TCP, need to revisit
     * if we support IP options.
     * XXX Head room needs to include the additional encap.
     * XXX copySize check is not considering multiple NBs.
     */
    nb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
    newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               0, 0, TRUE /*copy NBL info*/);

    ASSERT(ovsFwdCtx->destPortsSizeOut > 0 ||
           ovsFwdCtx->tunnelTxNic != NULL || ovsFwdCtx->tunnelRxNic != NULL);

    /* Send the original packet out */
    status = OvsOutputForwardingCtx(ovsFwdCtx);
    ASSERT(ovsFwdCtx->curNbl == NULL);
    ASSERT(ovsFwdCtx->destPortsSizeOut == 0);
    ASSERT(ovsFwdCtx->tunnelRxNic == NULL);
    ASSERT(ovsFwdCtx->tunnelTxNic == NULL);

    /* If we didn't make a copy, can't continue. */
    if (newNbl == NULL) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_RESOURCES;
    }

    /* Finish the remaining actions with the new NBL */
    if (status != NDIS_STATUS_SUCCESS) {
        OvsCompleteNBL(ovsFwdCtx->switchContext, newNbl, TRUE);
    } else {
        status = OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext,
                                      newNbl, ovsFwdCtx->srcVportNo, 0,
                                      NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                                      ovsFwdCtx->completionList,
                                      &ovsFwdCtx->layers, FALSE);
    }

    return status;
}


/*
 * --------------------------------------------------------------------------
 * OvsPopVlanInPktBuf --
 *     Function to pop a VLAN tag when the tag is in the packet buffer.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsPopVlanInPktBuf(OvsForwardingContext *ovsFwdCtx)
{
    PNET_BUFFER curNb;
    PMDL curMdl;
    PUINT8 bufferStart;
    ULONG dataLength = sizeof (DL_EUI48) + sizeof (DL_EUI48);
    UINT32 packetLen, mdlLen;
    PNET_BUFFER_LIST newNbl;
    NDIS_STATUS status;

    /*
     * Declare a dummy vlanTag structure since we need to compute the size
     * of shiftLength. The NDIS one is a unionized structure.
     */
    NDIS_PACKET_8021Q_INFO vlanTag = {0};
    ULONG shiftLength = sizeof (vlanTag.TagHeader);
    PUINT8 tempBuffer[sizeof (DL_EUI48) + sizeof (DL_EUI48)];

    newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               0, 0, TRUE /* copy NBL info */);
    if (!newNbl) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_RESOURCES;
    }

    /* Complete the original NBL and create a copy to modify. */
    OvsCompleteNBLForwardingCtx(ovsFwdCtx, L"OVS-Dropped due to copy");

    status = OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext,
                                  newNbl, ovsFwdCtx->srcVportNo, 0,
                                  NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                                  NULL, &ovsFwdCtx->layers, FALSE);
    if (status != NDIS_STATUS_SUCCESS) {
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                    L"Dropped due to resouces");
        return NDIS_STATUS_RESOURCES;
    }

    curNb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
    packetLen = NET_BUFFER_DATA_LENGTH(curNb);
    ASSERT(curNb->Next == NULL);
    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    NdisQueryMdl(curMdl, &bufferStart, &mdlLen, LowPagePriority);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }
    mdlLen -= NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    /* Bail out if L2 + VLAN header is not contiguous in the first buffer. */
    if (MIN(packetLen, mdlLen) < sizeof (EthHdr) + shiftLength) {
        ASSERT(FALSE);
        return NDIS_STATUS_FAILURE;
    }
    bufferStart += NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    RtlCopyMemory(tempBuffer, bufferStart, dataLength);
    RtlCopyMemory(bufferStart + shiftLength, tempBuffer, dataLength);
    NdisAdvanceNetBufferDataStart(curNb, shiftLength, FALSE, NULL);

    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsTunnelAttrToIPv4TunnelKey --
 *      Convert tunnel attribute to OvsIPv4TunnelKey.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsTunnelAttrToIPv4TunnelKey(PNL_ATTR attr,
                             OvsIPv4TunnelKey *tunKey)
{
   PNL_ATTR a;
   INT rem;

   tunKey->attr[0] = 0;
   tunKey->attr[1] = 0;
   tunKey->attr[2] = 0;
   ASSERT(NlAttrType(attr) == OVS_KEY_ATTR_TUNNEL);

   NL_ATTR_FOR_EACH_UNSAFE (a, rem, NlAttrData(attr),
                            NlAttrGetSize(attr)) {
      switch (NlAttrType(a)) {
      case OVS_TUNNEL_KEY_ATTR_ID:
         tunKey->tunnelId = NlAttrGetBe64(a);
         tunKey->flags |= OVS_TNL_F_KEY;
         break;
      case OVS_TUNNEL_KEY_ATTR_IPV4_SRC:
         tunKey->src = NlAttrGetBe32(a);
         break;
      case OVS_TUNNEL_KEY_ATTR_IPV4_DST:
         tunKey->dst = NlAttrGetBe32(a);
         break;
      case OVS_TUNNEL_KEY_ATTR_TOS:
         tunKey->tos = NlAttrGetU8(a);
         break;
      case OVS_TUNNEL_KEY_ATTR_TTL:
         tunKey->ttl = NlAttrGetU8(a);
         break;
      case OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT:
         tunKey->flags |= OVS_TNL_F_DONT_FRAGMENT;
         break;
      case OVS_TUNNEL_KEY_ATTR_CSUM:
         tunKey->flags |= OVS_TNL_F_CSUM;
         break;
      default:
         ASSERT(0);
      }
   }

   return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateEthHeader --
 *      Updates the ethernet header in ovsFwdCtx.curNbl inline based on the
 *      specified key.
 *----------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsUpdateEthHeader(OvsForwardingContext *ovsFwdCtx,
                   const struct ovs_key_ethernet *ethAttr)
{
    PNET_BUFFER curNb;
    PMDL curMdl;
    PUINT8 bufferStart;
    EthHdr *ethHdr;
    UINT32 packetLen, mdlLen;

    curNb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
    ASSERT(curNb->Next == NULL);
    packetLen = NET_BUFFER_DATA_LENGTH(curNb);
    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    NdisQueryMdl(curMdl, &bufferStart, &mdlLen, LowPagePriority);
    if (!bufferStart) {
        ovsActionStats.noResource++;
        return NDIS_STATUS_RESOURCES;
    }
    mdlLen -= NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    ASSERT(mdlLen > 0);
    /* Bail out if the L2 header is not in a contiguous buffer. */
    if (MIN(packetLen, mdlLen) < sizeof *ethHdr) {
        ASSERT(FALSE);
        return NDIS_STATUS_FAILURE;
    }
    ethHdr = (EthHdr *)(bufferStart + NET_BUFFER_CURRENT_MDL_OFFSET(curNb));

    RtlCopyMemory(ethHdr->Destination, ethAttr->eth_dst,
                   sizeof ethHdr->Destination);
    RtlCopyMemory(ethHdr->Source, ethAttr->eth_src, sizeof ethHdr->Source);

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateIPv4Header --
 *      Updates the IPv4 header in ovsFwdCtx.curNbl inline based on the
 *      specified key.
 *----------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsUpdateIPv4Header(OvsForwardingContext *ovsFwdCtx,
                    const struct ovs_key_ipv4 *ipAttr)
{
    PNET_BUFFER curNb;
    PMDL curMdl;
    ULONG curMdlOffset;
    PUINT8 bufferStart;
    UINT32 mdlLen, hdrSize, packetLen;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    NDIS_STATUS status;
    IPHdr *ipHdr;
    TCPHdr *tcpHdr = NULL;
    UDPHdr *udpHdr = NULL;

    ASSERT(layers->value != 0);

    /*
     * Peek into the MDL to get a handle to the IP header and if required
     * the TCP/UDP header as well. We check if the required headers are in one
     * contiguous MDL, and if not, we copy them over to one MDL.
     */
    curNb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
    ASSERT(curNb->Next == NULL);
    packetLen = NET_BUFFER_DATA_LENGTH(curNb);
    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    NdisQueryMdl(curMdl, &bufferStart, &mdlLen, LowPagePriority);
    if (!bufferStart) {
        ovsActionStats.noResource++;
        return NDIS_STATUS_RESOURCES;
    }
    curMdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    mdlLen -= curMdlOffset;
    ASSERT((INT)mdlLen >= 0);

    if (layers->isTcp || layers->isUdp) {
        hdrSize = layers->l4Offset +
                  layers->isTcp ? sizeof (*tcpHdr) : sizeof (*udpHdr);
    } else {
        hdrSize = layers->l3Offset + sizeof (*ipHdr);
    }

    /* Count of number of bytes of valid data there are in the first MDL. */
    mdlLen = MIN(packetLen, mdlLen);
    if (mdlLen < hdrSize) {
        PNET_BUFFER_LIST newNbl;
        newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                                   hdrSize, 0, TRUE /*copy NBL info*/);
        if (!newNbl) {
            ovsActionStats.noCopiedNbl++;
            return NDIS_STATUS_RESOURCES;
        }
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                    L"Complete after partial copy.");

        status = OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext,
                                      newNbl, ovsFwdCtx->srcVportNo, 0,
                                      NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                                      NULL, &ovsFwdCtx->layers, FALSE);
        if (status != NDIS_STATUS_SUCCESS) {
            OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                        L"OVS-Dropped due to resources");
            return NDIS_STATUS_RESOURCES;
        }

        curNb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
        ASSERT(curNb->Next == NULL);
        curMdl = NET_BUFFER_CURRENT_MDL(curNb);
        NdisQueryMdl(curMdl, &bufferStart, &mdlLen, LowPagePriority);
        if (!curMdl) {
            ovsActionStats.noResource++;
            return NDIS_STATUS_RESOURCES;
        }
        curMdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
        mdlLen -= curMdlOffset;
        ASSERT(mdlLen >= hdrSize);
    }

    ipHdr = (IPHdr *)(bufferStart + curMdlOffset + layers->l3Offset);

    if (layers->isTcp) {
        tcpHdr = (TCPHdr *)(bufferStart + curMdlOffset + layers->l4Offset);
    } else if (layers->isUdp) {
        udpHdr = (UDPHdr *)(bufferStart + curMdlOffset + layers->l4Offset);
    }

    /*
     * Adjust the IP header inline as dictated by the action, nad also update
     * the IP and the TCP checksum for the data modified.
     *
     * In the future, this could be optimized to make one call to
     * ChecksumUpdate32(). Ignoring this for now, since for the most common
     * case, we only update the TTL.
     */
    if (ipHdr->saddr != ipAttr->ipv4_src) {
        if (tcpHdr) {
            tcpHdr->check = ChecksumUpdate32(tcpHdr->check, ipHdr->saddr,
                                             ipAttr->ipv4_src);
        } else if (udpHdr && udpHdr->check) {
            udpHdr->check = ChecksumUpdate32(udpHdr->check, ipHdr->saddr,
                                             ipAttr->ipv4_src);
        }

        if (ipHdr->check != 0) {
            ipHdr->check = ChecksumUpdate32(ipHdr->check, ipHdr->saddr,
                                            ipAttr->ipv4_src);
        }
        ipHdr->saddr = ipAttr->ipv4_src;
    }
    if (ipHdr->daddr != ipAttr->ipv4_dst) {
        if (tcpHdr) {
            tcpHdr->check = ChecksumUpdate32(tcpHdr->check, ipHdr->daddr,
                                             ipAttr->ipv4_dst);
        } else if (udpHdr && udpHdr->check) {
            udpHdr->check = ChecksumUpdate32(udpHdr->check, ipHdr->daddr,
                                             ipAttr->ipv4_dst);
        }

        if (ipHdr->check != 0) {
            ipHdr->check = ChecksumUpdate32(ipHdr->check, ipHdr->daddr,
                                            ipAttr->ipv4_dst);
        }
        ipHdr->daddr = ipAttr->ipv4_dst;
    }
    if (ipHdr->protocol != ipAttr->ipv4_proto) {
        UINT16 oldProto = (ipHdr->protocol << 16) & 0xff00;
        UINT16 newProto = (ipAttr->ipv4_proto << 16) & 0xff00;
        if (tcpHdr) {
            tcpHdr->check = ChecksumUpdate16(tcpHdr->check, oldProto, newProto);
        } else if (udpHdr && udpHdr->check) {
            udpHdr->check = ChecksumUpdate16(udpHdr->check, oldProto, newProto);
        }

        if (ipHdr->check != 0) {
            ipHdr->check = ChecksumUpdate16(ipHdr->check, oldProto, newProto);
        }
        ipHdr->protocol = ipAttr->ipv4_proto;
    }
    if (ipHdr->ttl != ipAttr->ipv4_ttl) {
        UINT16 oldTtl = (ipHdr->ttl) & 0xff;
        UINT16 newTtl = (ipAttr->ipv4_ttl) & 0xff;
        if (ipHdr->check != 0) {
            ipHdr->check = ChecksumUpdate16(ipHdr->check, oldTtl, newTtl);
        }
        ipHdr->ttl = ipAttr->ipv4_ttl;
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsExecuteSetAction --
 *      Executes a set() action, but storing the actions into 'ovsFwdCtx'
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsExecuteSetAction(OvsForwardingContext *ovsFwdCtx,
                    OvsFlowKey *key,
                    UINT64 *hash,
                    const PNL_ATTR a)
{
    enum ovs_key_attr type = NlAttrType(a);
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;

    switch (type) {
    case OVS_KEY_ATTR_ETHERNET:
        status = OvsUpdateEthHeader(ovsFwdCtx,
            NlAttrGetUnspec(a, sizeof(struct ovs_key_ethernet)));
        break;

    case OVS_KEY_ATTR_IPV4:
        status = OvsUpdateIPv4Header(ovsFwdCtx,
            NlAttrGetUnspec(a, sizeof(struct ovs_key_ipv4)));
        break;

    case OVS_KEY_ATTR_TUNNEL:
    {
        OvsIPv4TunnelKey tunKey;

		status = OvsTunnelAttrToIPv4TunnelKey((PNL_ATTR)a, &tunKey);
        ASSERT(status == NDIS_STATUS_SUCCESS);
        tunKey.flow_hash = (uint16)(hash ? *hash : OvsHashFlow(key));
        tunKey.dst_port = key->ipKey.l4.tpDst;
        RtlCopyMemory(&ovsFwdCtx->tunKey, &tunKey, sizeof ovsFwdCtx->tunKey);

        break;
    }
    case OVS_KEY_ATTR_SKB_MARK:
    /* XXX: Not relevant to Hyper-V. Return OK */
    break;
    case OVS_KEY_ATTR_UNSPEC:
    case OVS_KEY_ATTR_ENCAP:
    case OVS_KEY_ATTR_ETHERTYPE:
    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_VLAN:
    case OVS_KEY_ATTR_ICMP:
    case OVS_KEY_ATTR_ICMPV6:
    case OVS_KEY_ATTR_ARP:
    case OVS_KEY_ATTR_ND:
    case __OVS_KEY_ATTR_MAX:
    default:
    OVS_LOG_INFO("Unhandled attribute %#x", type);
    ASSERT(FALSE);
    }
    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsActionsExecute --
 *     Interpret and execute the specified 'actions' on the specifed packet
 *     'curNbl'. The expectation is that if the packet needs to be dropped
 *     (completed) for some reason, it is added to 'completionList' so that the
 *     caller can complete the packet. If 'completionList' is NULL, the NBL is
 *     assumed to be generated by OVS and freed up. Otherwise, the function
 *     consumes the NBL by generating a NDIS send indication for the packet.
 *
 *     There are one or more of "clone" NBLs that may get generated while
 *     executing the actions. Upon any failures, the "cloned" NBLs are freed up,
 *     and the caller does not have to worry about them.
 *
 *     Success or failure is returned based on whether the specified actions
 *     were executed successfully on the packet or not.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsActionsExecute(POVS_SWITCH_CONTEXT switchContext,
                  OvsCompletionList *completionList,
                  PNET_BUFFER_LIST curNbl,
                  UINT32 portNo,
                  ULONG sendFlags,
                  OvsFlowKey *key,
                  UINT64 *hash,
                  OVS_PACKET_HDR_INFO *layers,
                  const PNL_ATTR actions,
                  INT actionsLen)
{
    PNL_ATTR a;
    INT rem;
    UINT32 dstPortID;
    OvsForwardingContext ovsFwdCtx;
    PCWSTR dropReason = L"";
    NDIS_STATUS status;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail =
        NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(curNbl);

    /* XXX: ASSERT that the flow table lock is held. */
    status = OvsInitForwardingCtx(&ovsFwdCtx, switchContext, curNbl, portNo,
                                  sendFlags, fwdDetail, completionList,
                                  layers, TRUE);
    if (status != NDIS_STATUS_SUCCESS) {
        dropReason = L"OVS-initing destination port list failed";
        goto dropit;
    }

    if (actionsLen == 0) {
        dropReason = L"OVS-Dropped due to Flow action";
        ovsActionStats.zeroActionLen++;
        goto dropit;
    }

    NL_ATTR_FOR_EACH_UNSAFE (a, rem, actions, actionsLen) {
        switch(NlAttrType(a)) {
        case OVS_ACTION_ATTR_OUTPUT:
            dstPortID = NlAttrGetU32(a);
            status = OvsAddPorts(&ovsFwdCtx, key, dstPortID,
                                              TRUE, TRUE);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-adding destination port failed";
                goto dropit;
            }
            break;

        case OVS_ACTION_ATTR_PUSH_VLAN:
        {
            struct ovs_action_push_vlan *vlan;
            PVOID vlanTagValue;
            PNDIS_NET_BUFFER_LIST_8021Q_INFO vlanTag;

            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            vlanTagValue = NET_BUFFER_LIST_INFO(ovsFwdCtx.curNbl,
                                                Ieee8021QNetBufferListInfo);
            if (vlanTagValue != NULL) {
                /*
                 * XXX: We don't support double VLAN tag offload. In such cases,
                 * we need to insert the existing one into the packet buffer,
                 * and add the new one as offload. This will take care of
                 * guest tag-in-tag case as well as OVS rules that specify
                 * tag-in-tag.
                 */
            } else {
                 vlanTagValue = 0;
                 vlanTag = (PNDIS_NET_BUFFER_LIST_8021Q_INFO)(PVOID *)&vlanTagValue;
                 vlan = (struct ovs_action_push_vlan *)NlAttrGet((const PNL_ATTR)a);
                 vlanTag->TagHeader.VlanId = ntohs(vlan->vlan_tci) & 0xfff;
                 vlanTag->TagHeader.UserPriority = ntohs(vlan->vlan_tci) >> 13;

                 NET_BUFFER_LIST_INFO(ovsFwdCtx.curNbl,
                                      Ieee8021QNetBufferListInfo) = vlanTagValue;
            }
            break;
        }

        case OVS_ACTION_ATTR_POP_VLAN:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            if (NET_BUFFER_LIST_INFO(ovsFwdCtx.curNbl,
                                     Ieee8021QNetBufferListInfo) != 0) {
                NET_BUFFER_LIST_INFO(ovsFwdCtx.curNbl,
                                     Ieee8021QNetBufferListInfo) = 0;
            } else {
                /*
                 * The VLAN tag is inserted into the packet buffer. Pop the tag
                 * by packet buffer modification.
                 */
                status = OvsPopVlanInPktBuf(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-pop vlan action failed";
                    goto dropit;
                }
            }
            break;
        }

        case OVS_ACTION_ATTR_USERSPACE:
        {
            PNL_ATTR userdataAttr;
            PNL_ATTR queueAttr;
            POVS_PACKET_QUEUE_ELEM elem;
            BOOLEAN isRecv = FALSE;

            POVS_VPORT_ENTRY vport = OvsFindVportByPortNo(switchContext,
                portNo);

            if (vport) {
                if (vport->isExternal ||
                    OvsIsTunnelVportType(vport->ovsType)) {
                    isRecv = TRUE;
                }
            }

            queueAttr = NlAttrFindNested(a, OVS_USERSPACE_ATTR_PID);
            userdataAttr = NlAttrFindNested(a, OVS_USERSPACE_ATTR_USERDATA);

            elem = OvsCreateQueueNlPacket((PVOID)userdataAttr,
                                    userdataAttr->nlaLen,
                                    OVS_PACKET_CMD_ACTION,
                                    portNo, key,ovsFwdCtx.curNbl,
                                    NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx.curNbl),
                                    isRecv,
                                    layers);
            if (elem) {
                LIST_ENTRY missedPackets;
                InitializeListHead(&missedPackets);
                InsertTailList(&missedPackets, &elem->link);
                OvsQueuePackets(&missedPackets, 1);
                dropReason = L"OVS-Completed since packet was copied to "
                             L"userspace";
            } else {
                dropReason = L"OVS-Dropped due to failure to queue to "
                             L"userspace";
                goto dropit;
            }
            break;
        }
        case OVS_ACTION_ATTR_SET:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            status = OvsExecuteSetAction(&ovsFwdCtx, key, hash,
                                         (const PNL_ATTR)NlAttrGet
                                         ((const PNL_ATTR)a));
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-set action failed";
                goto dropit;
            }
            break;
        }
        case OVS_ACTION_ATTR_SAMPLE:
        default:
            status = NDIS_STATUS_NOT_SUPPORTED;
            break;
        }
    }

    if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
        || ovsFwdCtx.tunnelRxNic != NULL) {
        status = OvsOutputForwardingCtx(&ovsFwdCtx);
        ASSERT(ovsFwdCtx.curNbl == NULL);
    }

    ASSERT(ovsFwdCtx.destPortsSizeOut == 0);
    ASSERT(ovsFwdCtx.tunnelRxNic == NULL);
    ASSERT(ovsFwdCtx.tunnelTxNic == NULL);

dropit:
    /*
     * If curNbl != NULL, it implies the NBL has not been not freed up so far.
     */
    if (ovsFwdCtx.curNbl) {
        OvsCompleteNBLForwardingCtx(&ovsFwdCtx, dropReason);
    }

    return status;
}
