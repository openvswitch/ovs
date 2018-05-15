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

#include "precomp.h"

#include "Actions.h"
#include "Conntrack.h"
#include "Debug.h"
#include "Event.h"
#include "Flow.h"
#include "Gre.h"
#include "Jhash.h"
#include "Mpls.h"
#include "NetProto.h"
#include "Offload.h"
#include "PacketIO.h"
#include "Recirc.h"
#include "Stt.h"
#include "Switch.h"
#include "User.h"
#include "Vport.h"
#include "Vxlan.h"
#include "Geneve.h"
#include "IpFragment.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_ACTION

#define OVS_DEST_PORTS_ARRAY_MIN_SIZE 2

typedef struct _OVS_ACTION_STATS {
    UINT64 rxGre;
    UINT64 txGre;
    UINT64 rxVxlan;
    UINT64 txVxlan;
    UINT64 rxStt;
    UINT64 txStt;
    UINT64 rxGeneve;
    UINT64 txGeneve;
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
    UINT32 deferredActionsQueueFull;
    UINT32 deferredActionsExecLimit;
} OVS_ACTION_STATS, *POVS_ACTION_STATS;

OVS_ACTION_STATS ovsActionStats;

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
 * --------------------------------------------------------------------------
 * OvsDoFragmentNbl --
 *     Utility function to Fragment nbl based on mru.
 * --------------------------------------------------------------------------
 */
static __inline VOID
OvsDoFragmentNbl(OvsForwardingContext *ovsFwdCtx, UINT16 mru)
{
    PNET_BUFFER_LIST fragNbl = NULL;
    fragNbl = OvsFragmentNBL(ovsFwdCtx->switchContext,
                             ovsFwdCtx->curNbl,
                             &(ovsFwdCtx->layers),
                             mru, 0, TRUE);

   if (fragNbl != NULL) {
        OvsCompleteNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl, TRUE);
        ovsFwdCtx->curNbl = fragNbl;
    } else {
        OVS_LOG_INFO("Fragment NBL failed for MRU = %u", mru);
    }
}

/*
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

    /*
     * For some of the tunnel types such as GRE, the dstPort is not applicable
     * since GRE does not have a L4 port. We use '0' for convenience.
     */
    if (!flowKey->ipKey.nwFrag) {
        UINT16 dstPort = htons(flowKey->ipKey.l4.tpDst);

        ASSERT(flowKey->ipKey.nwProto != IPPROTO_GRE || dstPort == 0);

        tunnelVport =
            OvsFindTunnelVportByDstPortAndNWProto(ovsFwdCtx->switchContext,
                                                  dstPort,
                                                  flowKey->ipKey.nwProto);
        if (tunnelVport) {
            switch(tunnelVport->ovsType) {
            case OVS_VPORT_TYPE_STT:
                ovsActionStats.rxStt++;
                break;
            case OVS_VPORT_TYPE_VXLAN:
                ovsActionStats.rxVxlan++;
                break;
            case OVS_VPORT_TYPE_GENEVE:
                ovsActionStats.rxGeneve++;
                break;
            case OVS_VPORT_TYPE_GRE:
                ovsActionStats.rxGre++;
                break;
            }
        }
    }

    // We might get tunnel packets even before the tunnel gets initialized.
    if (tunnelVport) {
        ASSERT(ovsFwdCtx->tunnelRxNic == NULL);
        ovsFwdCtx->tunnelRxNic = tunnelVport;
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
            (OvsIsExternalVportByPortId(ovsFwdCtx->switchContext,
                 ovsFwdCtx->fwdDetail->SourcePortId)) ||
            (ovsFwdCtx->fwdDetail->SourcePortId ==
                 NDIS_SWITCH_DEFAULT_PORT_ID);

        if (validSrcPort && OvsDetectTunnelRxPkt(ovsFwdCtx, flowKey)) {
            ASSERT(ovsFwdCtx->tunnelTxNic == NULL);
            ASSERT(ovsFwdCtx->tunnelRxNic != NULL);
            return TRUE;
        }
    } else if (OvsIsTunnelVportType(dstVport->ovsType)) {
        ASSERT(ovsFwdCtx->tunnelRxNic == NULL);

        /*
         * Tx:
         * The destination port is a tunnel port. Encapsulation must be
         * performed only on packets that originate from:
         * - a VIF port
         * - a bridge-internal port (packets generated from userspace)
         * - no port.
         * - tunnel port
         * If the packet will not be encapsulated, consume the tunnel context
         * by clearing it.
         */
        if (ovsFwdCtx->srcVportNo != OVS_DPPORT_NUMBER_INVALID) {

            POVS_VPORT_ENTRY vport = OvsFindVportByPortNo(
                ovsFwdCtx->switchContext, ovsFwdCtx->srcVportNo);

            if (!vport ||
                (vport->ovsType != OVS_VPORT_TYPE_NETDEV &&
                 vport->ovsType != OVS_VPORT_TYPE_INTERNAL &&
                 !OvsIsTunnelVportType(vport->ovsType))) {
                ovsFwdCtx->tunKey.dst = 0;
            }
        }

        /* Tunnel the packet only if tunnel context is set. */
        if (ovsFwdCtx->tunKey.dst != 0) {
            switch(dstVport->ovsType) {
            case OVS_VPORT_TYPE_GRE:
                ovsActionStats.txGre++;
                break;
            case OVS_VPORT_TYPE_VXLAN:
                ovsActionStats.txVxlan++;
                break;
            case OVS_VPORT_TYPE_STT:
                ovsActionStats.txStt++;
                break;
            case OVS_VPORT_TYPE_GENEVE:
               ovsActionStats.txGeneve++;
               break;
            }
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
    OvsFlowKey key = { 0 };
    OvsFlow *flow = NULL;
    UINT64 hash = 0;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    POVS_VPORT_ENTRY vport =
        OvsFindVportByPortNo(ovsFwdCtx->switchContext, ovsFwdCtx->srcVportNo);
    if (vport == NULL || vport->ovsState != OVS_STATE_CONNECTED) {
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
            L"OVS-Dropped due to internal/tunnel port removal");
        ovsActionStats.noVport++;
        return NDIS_STATUS_SUCCESS;
    }
    ASSERT(vport->nicState == NdisSwitchNicStateConnected);

    /* Assert that in the Rx direction, key is always setup. */
    ASSERT(ovsFwdCtx->tunnelRxNic == NULL || ovsFwdCtx->tunKey.dst != 0);
    status =
        OvsExtractFlow(ovsFwdCtx->curNbl, ovsFwdCtx->srcVportNo,
                       &key, &ovsFwdCtx->layers,
                       ovsFwdCtx->tunKey.dst != 0 ? &ovsFwdCtx->tunKey : NULL);
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
        status = OvsDoExecuteActions(ovsFwdCtx->switchContext,
                                     ovsFwdCtx->completionList,
                                     ovsFwdCtx->curNbl,
                                     ovsFwdCtx->srcVportNo,
                                     ovsFwdCtx->sendFlags,
                                     &key, &hash, &ovsFwdCtx->layers,
                                     flow->actions, flow->actionsLen);
        ovsFwdCtx->curNbl = NULL;
    } else {
        LIST_ENTRY missedPackets;
        UINT32 num = 0;
        ovsFwdCtx->switchContext->datapath.misses++;
        InitializeListHead(&missedPackets);
        status = OvsCreateAndAddPackets(NULL, 0, OVS_PACKET_CMD_MISS, vport,
                          &key,ovsFwdCtx->curNbl,
                          FALSE, &ovsFwdCtx->layers,
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
    UINT32 srcVportNo;
    NDIS_SWITCH_NIC_INDEX srcNicIndex;
    NDIS_SWITCH_PORT_ID srcPortId;
    POVS_BUFFER_CONTEXT ctx;

    /*
     * Setup the source port to be the internal port to as to facilitate the
     * second OvsLookupFlow.
     */
    if (ovsFwdCtx->switchContext->countInternalVports <= 0 ||
        ovsFwdCtx->switchContext->virtualExternalVport == NULL) {
        OvsClearTunTxCtx(ovsFwdCtx);
        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
            L"OVS-Dropped since either internal or external port is absent");
        return NDIS_STATUS_FAILURE;
    }

    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(ovsFwdCtx->curNbl);
    if (ctx->mru != 0) {
        OvsDoFragmentNbl(ovsFwdCtx, ctx->mru);
    }
    OVS_FWD_INFO switchFwdInfo = { 0 };
    /* Apply the encapsulation. The encapsulation will not consume the NBL. */
    switch(ovsFwdCtx->tunnelTxNic->ovsType) {
    case OVS_VPORT_TYPE_GRE:
        status = OvsEncapGre(ovsFwdCtx->tunnelTxNic, ovsFwdCtx->curNbl,
                             &ovsFwdCtx->tunKey, ovsFwdCtx->switchContext,
                             &ovsFwdCtx->layers, &newNbl, &switchFwdInfo);
        break;
    case OVS_VPORT_TYPE_VXLAN:
        status = OvsEncapVxlan(ovsFwdCtx->tunnelTxNic, ovsFwdCtx->curNbl,
                               &ovsFwdCtx->tunKey, ovsFwdCtx->switchContext,
                               &ovsFwdCtx->layers, &newNbl, &switchFwdInfo);
        break;
    case OVS_VPORT_TYPE_STT:
        status = OvsEncapStt(ovsFwdCtx->tunnelTxNic, ovsFwdCtx->curNbl,
                             &ovsFwdCtx->tunKey, ovsFwdCtx->switchContext,
                             &ovsFwdCtx->layers, &newNbl, &switchFwdInfo);
        break;
    case OVS_VPORT_TYPE_GENEVE:
        status = OvsEncapGeneve(ovsFwdCtx->tunnelTxNic, ovsFwdCtx->curNbl,
                                &ovsFwdCtx->tunKey, ovsFwdCtx->switchContext,
                                &ovsFwdCtx->layers, &newNbl, &switchFwdInfo);
        break;
    default:
        ASSERT(! "Tx: Unhandled tunnel type");
    }

    /* Reset the tunnel context so that it doesn't get used after this point. */
    OvsClearTunTxCtx(ovsFwdCtx);

    if (status == NDIS_STATUS_SUCCESS && switchFwdInfo.vport != NULL) {
        ASSERT(newNbl);
        /*
         * Save the 'srcVportNo', 'srcPortId', 'srcNicIndex' so that
         * this can be applied to the new NBL later on.
         */
        srcVportNo = switchFwdInfo.vport->portNo;
        srcPortId = switchFwdInfo.vport->portId;
        srcNicIndex = switchFwdInfo.vport->nicIndex;

        OvsCompleteNBLForwardingCtx(ovsFwdCtx,
                                    L"Complete after cloning NBL for encapsulation");
        status = OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext,
                                      newNbl, srcVportNo, 0,
                                      NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                                      ovsFwdCtx->completionList,
                                      &ovsFwdCtx->layers, FALSE);
        ovsFwdCtx->curNbl = newNbl;
        /* Update the forwarding detail for the new NBL */
        ovsFwdCtx->fwdDetail->SourcePortId = srcPortId;
        ovsFwdCtx->fwdDetail->SourceNicIndex = srcNicIndex;
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
    PCWSTR dropReason = L"OVS-dropped due to new decap packet";

    if (OvsValidateIPChecksum(ovsFwdCtx->curNbl, &ovsFwdCtx->layers)
            != NDIS_STATUS_SUCCESS) {
        ovsActionStats.failedChecksum++;
        OVS_LOG_INFO("Packet dropped due to IP checksum failure.");
        goto dropNbl;
    }

    /*
     * Decap port functions should return a new NBL if it was copied, and
     * this new NBL should be setup as the ovsFwdCtx->curNbl.
     */

    switch(tunnelRxVport->ovsType) {
    case OVS_VPORT_TYPE_GRE:
        status = OvsDecapGre(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                             &ovsFwdCtx->tunKey, &newNbl);
        break;
    case OVS_VPORT_TYPE_VXLAN:
        status = OvsDecapVxlan(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               &ovsFwdCtx->tunKey, &newNbl);
        break;
    case OVS_VPORT_TYPE_STT:
        status = OvsDecapStt(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                             &ovsFwdCtx->tunKey, &newNbl);
        if (status == NDIS_STATUS_SUCCESS && newNbl == NULL) {
            /* This was an STT-LSO Fragment */
            dropReason = L"OVS-STT segment is cached";
        }
        break;
    case OVS_VPORT_TYPE_GENEVE:
        status = OvsDecapGeneve(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
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
    OvsCompleteNBLForwardingCtx(ovsFwdCtx, dropReason);

    if (newNbl) {
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
    }
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
    POVS_BUFFER_CONTEXT ctx;

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
            POVS_BUFFER_CONTEXT oldCtx, newCtx;
            nb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
            oldCtx = (POVS_BUFFER_CONTEXT)
                NET_BUFFER_LIST_CONTEXT_DATA_START(ovsFwdCtx->curNbl);
            newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext,
                                       ovsFwdCtx->curNbl,
                                       0, 0, TRUE /*copy NBL info*/);
            if (newNbl == NULL) {
                status = NDIS_STATUS_RESOURCES;
                ovsActionStats.noCopiedNbl++;
                dropReason = L"Dropped due to failure to create NBL copy.";
                goto dropit;
            }
            newCtx = (POVS_BUFFER_CONTEXT)
                NET_BUFFER_LIST_CONTEXT_DATA_START(newNbl);
            newCtx->mru = oldCtx->mru;
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

        ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(ovsFwdCtx->curNbl);
        if (ctx->mru != 0) {
            OvsDoFragmentNbl(ovsFwdCtx, ctx->mru);
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
                    PNET_BUFFER_LIST curNbl,
                    POVS_VPORT_ENTRY internalVport)
{
    NDIS_STATUS status;
    OvsForwardingContext ovsFwdCtx;

    /* XXX: make sure comp list was not a stack variable previously. */
    OvsCompletionList *completionList = (OvsCompletionList *)compList;

    /*
     * XXX: can internal port disappear while we are busy doing ARP resolution?
     * It could, but will we get this callback from IP helper in that case. Need
     * to check.
     */
    ASSERT(switchContext->countInternalVports > 0);
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
    NDIS_STATUS status;

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
    newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               0, 0, TRUE /*copy NBL info*/);

    ASSERT(ovsFwdCtx->destPortsSizeOut > 0 ||
           ovsFwdCtx->tunnelTxNic != NULL || ovsFwdCtx->tunnelRxNic != NULL);

    /* Send the original packet out and save the original source port number */
    UINT32 tempVportNo = ovsFwdCtx->srcVportNo;
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
                                      newNbl, tempVportNo, 0,
                                      NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(newNbl),
                                      ovsFwdCtx->completionList,
                                      &ovsFwdCtx->layers, FALSE);
    }

    return status;
}


/*
 * --------------------------------------------------------------------------
 * OvsPopFieldInPacketBuf --
 *     Function to pop a specified field of length 'shiftLength' located at
 *     'shiftOffset' from the Ethernet header. The data on the left of the
 *     'shiftOffset' is right shifted.
 *
 *     Returns a pointer to the new start in 'bufferData'.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsPopFieldInPacketBuf(OvsForwardingContext *ovsFwdCtx,
                       UINT32 shiftOffset,
                       UINT32 shiftLength,
                       PUINT8 *bufferData)
{
    PNET_BUFFER curNb;
    PMDL curMdl;
    PUINT8 bufferStart;
    UINT32 packetLen, mdlLen;
    PNET_BUFFER_LIST newNbl;
    NDIS_STATUS status;

    newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               0, 0, TRUE /* copy NBL info */);
    if (!newNbl) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_RESOURCES;
    }

    /* Complete the original NBL and create a copy to modify. */
    OvsCompleteNBLForwardingCtx(ovsFwdCtx, L"OVS-Dropped due to copy");

    status = OvsInitForwardingCtx(ovsFwdCtx, ovsFwdCtx->switchContext, newNbl,
                                  ovsFwdCtx->srcVportNo, 0,
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
    /* Bail out if L2 + shiftLength is not contiguous in the first buffer. */
    if (MIN(packetLen, mdlLen) < sizeof(EthHdr) + shiftLength) {
        ASSERT(FALSE);
        return NDIS_STATUS_FAILURE;
    }
    bufferStart += NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    /* XXX At the momemnt !bufferData means it should be treated as VLAN. We
     * should split the function and refactor. */
    if (!bufferData) {
        EthHdr *ethHdr = (EthHdr *)bufferStart;
        /* If the frame is not VLAN make it a no op */
        if (ethHdr->Type != ETH_TYPE_802_1PQ_NBO) {
            return NDIS_STATUS_SUCCESS;
        }
    }
    RtlMoveMemory(bufferStart + shiftLength, bufferStart, shiftOffset);
    NdisAdvanceNetBufferDataStart(curNb, shiftLength, FALSE, NULL);

    if (bufferData) {
        *bufferData = bufferStart + shiftLength;
    }

    return NDIS_STATUS_SUCCESS;
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
    /*
     * Declare a dummy vlanTag structure since we need to compute the size
     * of shiftLength. The NDIS one is a unionized structure.
     */
    NDIS_PACKET_8021Q_INFO vlanTag = {0};
    UINT32 shiftLength = sizeof(vlanTag.TagHeader);
    UINT32 shiftOffset = sizeof(DL_EUI48) + sizeof(DL_EUI48);

    return OvsPopFieldInPacketBuf(ovsFwdCtx, shiftOffset, shiftLength, NULL);
}


/*
 * --------------------------------------------------------------------------
 * OvsActionMplsPop --
 *     Function to pop the first MPLS label from the current packet.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsActionMplsPop(OvsForwardingContext *ovsFwdCtx,
                 ovs_be16 ethertype)
{
    NDIS_STATUS status;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    EthHdr *ethHdr = NULL;

    status = OvsPopFieldInPacketBuf(ovsFwdCtx, sizeof(*ethHdr),
                                    MPLS_HLEN, (PUINT8*)&ethHdr);
    if (status == NDIS_STATUS_SUCCESS) {
        if (ethHdr && OvsEthertypeIsMpls(ethHdr->Type)) {
            ethHdr->Type = ethertype;
        }

        layers->l3Offset -= MPLS_HLEN;
        layers->l4Offset -= MPLS_HLEN;
    }

    return status;
}


/*
 * --------------------------------------------------------------------------
 * OvsActionMplsPush --
 *     Function to push the MPLS label into the current packet.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsActionMplsPush(OvsForwardingContext *ovsFwdCtx,
                  const struct ovs_action_push_mpls *mpls)
{
    NDIS_STATUS status;
    PNET_BUFFER curNb = NULL;
    PMDL curMdl = NULL;
    PUINT8 bufferStart = NULL;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    EthHdr *ethHdr = NULL;
    MPLSHdr *mplsHdr = NULL;
    UINT32 mdlLen = 0, curMdlOffset = 0;
    PNET_BUFFER_LIST newNbl;

    newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               layers->l3Offset, MPLS_HLEN, TRUE);
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

    status = NdisRetreatNetBufferDataStart(curNb, MPLS_HLEN, 0, NULL);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    NdisQueryMdl(curMdl, &bufferStart, &mdlLen, LowPagePriority);
    if (!curMdl) {
        ovsActionStats.noResource++;
        return NDIS_STATUS_RESOURCES;
    }

    curMdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    mdlLen -= curMdlOffset;
    ASSERT(mdlLen >= MPLS_HLEN);

    ethHdr = (EthHdr *)(bufferStart + curMdlOffset);
    ASSERT(ethHdr);
    RtlMoveMemory(ethHdr, (UINT8*)ethHdr + MPLS_HLEN, sizeof(*ethHdr));
    ethHdr->Type = mpls->mpls_ethertype;

    mplsHdr = (MPLSHdr *)(ethHdr + 1);
    mplsHdr->lse = mpls->mpls_lse;

    layers->l3Offset += MPLS_HLEN;
    layers->l4Offset += MPLS_HLEN;

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
 * OvsGetHeaderBySize --
 *      Tries to retrieve a continuous buffer from 'ovsFwdCtx->curnbl' of size
 *      'size'.
 *      If the original buffer is insufficient it will, try to clone the net
 *      buffer list and force the size.
 *      Returns 'NULL' on failure or a pointer to the first byte of the data
 *      in the first net buffer of the net buffer list 'nbl'.
 *----------------------------------------------------------------------------
 */
PUINT8 OvsGetHeaderBySize(OvsForwardingContext *ovsFwdCtx,
                          UINT32 size)
{
    PNET_BUFFER curNb;
    UINT32 mdlLen, packetLen;
    PMDL curMdl;
    ULONG curMdlOffset;
    PUINT8 start;

    curNb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
    ASSERT(curNb->Next == NULL);
    packetLen = NET_BUFFER_DATA_LENGTH(curNb);
    curMdl = NET_BUFFER_CURRENT_MDL(curNb);
    NdisQueryMdl(curMdl, &start, &mdlLen, LowPagePriority);
    if (!start) {
        ovsActionStats.noResource++;
        return NULL;
    }

    curMdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
    mdlLen -= curMdlOffset;
    ASSERT((INT)mdlLen >= 0);

    /* Count of number of bytes of valid data there are in the first MDL. */
    mdlLen = MIN(packetLen, mdlLen);
    if (mdlLen < size) {
        PNET_BUFFER_LIST newNbl;
        NDIS_STATUS status;
        newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                                   size, 0, TRUE /*copy NBL info*/);
        if (!newNbl) {
            ovsActionStats.noCopiedNbl++;
            return NULL;
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
            return NULL;
        }

        curNb = NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl);
        ASSERT(curNb->Next == NULL);
        curMdl = NET_BUFFER_CURRENT_MDL(curNb);
        NdisQueryMdl(curMdl, &start, &mdlLen, LowPagePriority);
        if (!curMdl) {
            ovsActionStats.noResource++;
            return NULL;
        }
        curMdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(curNb);
        mdlLen -= curMdlOffset;
        ASSERT(mdlLen >= size);
    }

    return start + curMdlOffset;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateUdpPorts --
 *      Updates the UDP source or destination port in ovsFwdCtx.curNbl inline
 *      based on the specified key.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateUdpPorts(OvsForwardingContext *ovsFwdCtx,
                  const struct ovs_key_udp *udpAttr)
{
    PUINT8 bufferStart;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    UDPHdr *udpHdr = NULL;

    ASSERT(layers->value != 0);

    if (!layers->isUdp) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_FAILURE;
    }

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx, layers->l7Offset);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }

    udpHdr = (UDPHdr *)(bufferStart + layers->l4Offset);
    if (udpHdr->check) {
        if (udpHdr->source != udpAttr->udp_src) {
            udpHdr->check = ChecksumUpdate16(udpHdr->check, udpHdr->source,
                                             udpAttr->udp_src);
            udpHdr->source = udpAttr->udp_src;
        }
        if (udpHdr->dest != udpAttr->udp_dst) {
            udpHdr->check = ChecksumUpdate16(udpHdr->check, udpHdr->dest,
                                             udpAttr->udp_dst);
            udpHdr->dest = udpAttr->udp_dst;
        }
    } else {
        udpHdr->source = udpAttr->udp_src;
        udpHdr->dest = udpAttr->udp_dst;
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateTcpPorts --
 *      Updates the TCP source or destination port in ovsFwdCtx.curNbl inline
 *      based on the specified key.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateTcpPorts(OvsForwardingContext *ovsFwdCtx,
                  const struct ovs_key_tcp *tcpAttr)
{
    PUINT8 bufferStart;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    TCPHdr *tcpHdr = NULL;

    ASSERT(layers->value != 0);

    if (!layers->isTcp) {
        ovsActionStats.noCopiedNbl++;
        return NDIS_STATUS_FAILURE;
    }

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx, layers->l7Offset);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }

    tcpHdr = (TCPHdr *)(bufferStart + layers->l4Offset);

    if (tcpHdr->source != tcpAttr->tcp_src) {
        tcpHdr->check = ChecksumUpdate16(tcpHdr->check, tcpHdr->source,
                                         tcpAttr->tcp_src);
        tcpHdr->source = tcpAttr->tcp_src;
    }
    if (tcpHdr->dest != tcpAttr->tcp_dst) {
        tcpHdr->check = ChecksumUpdate16(tcpHdr->check, tcpHdr->dest,
                                         tcpAttr->tcp_dst);
        tcpHdr->dest = tcpAttr->tcp_dst;
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateAddressAndPort --
 *      Updates the source/destination IP and port fields in
 *      ovsFwdCtx.curNbl inline based on the specified key.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateAddressAndPort(OvsForwardingContext *ovsFwdCtx,
                        UINT32 newAddr, UINT16 newPort,
                        BOOLEAN isSource, BOOLEAN isTx)
{
    PUINT8 bufferStart;
    UINT32 hdrSize;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    IPHdr *ipHdr;
    TCPHdr *tcpHdr = NULL;
    UDPHdr *udpHdr = NULL;
    UINT32 *addrField = NULL;
    UINT16 *portField = NULL;
    UINT16 *checkField = NULL;
    BOOLEAN l4Offload = FALSE;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;

    ASSERT(layers->value != 0);

    if (layers->isTcp || layers->isUdp) {
        hdrSize = layers->l4Offset +
                  layers->isTcp ? sizeof (*tcpHdr) : sizeof (*udpHdr);
    } else {
        hdrSize = layers->l3Offset + sizeof (*ipHdr);
    }

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx, hdrSize);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }

    ipHdr = (IPHdr *)(bufferStart + layers->l3Offset);

    if (layers->isTcp) {
        tcpHdr = (TCPHdr *)(bufferStart + layers->l4Offset);
    } else if (layers->isUdp) {
        udpHdr = (UDPHdr *)(bufferStart + layers->l4Offset);
    }

    csumInfo.Value = NET_BUFFER_LIST_INFO(ovsFwdCtx->curNbl,
                                          TcpIpChecksumNetBufferListInfo);
    /*
     * Adjust the IP header inline as dictated by the action, and also update
     * the IP and the TCP checksum for the data modified.
     *
     * In the future, this could be optimized to make one call to
     * ChecksumUpdate32(). Ignoring this for now, since for the most common
     * case, we only update the TTL.
     */

    if (isSource) {
        addrField = &ipHdr->saddr;
        if (tcpHdr) {
            portField = &tcpHdr->source;
            checkField = &tcpHdr->check;
            l4Offload = isTx ? (BOOLEAN)csumInfo.Transmit.TcpChecksum :
                        ((BOOLEAN)csumInfo.Receive.TcpChecksumSucceeded ||
                         (BOOLEAN)csumInfo.Receive.TcpChecksumFailed);
        } else if (udpHdr) {
            portField = &udpHdr->source;
            checkField = &udpHdr->check;
            l4Offload = isTx ? (BOOLEAN)csumInfo.Transmit.UdpChecksum :
                        ((BOOLEAN)csumInfo.Receive.UdpChecksumSucceeded ||
                         (BOOLEAN)csumInfo.Receive.UdpChecksumFailed);
        }
        if (l4Offload) {
            *checkField = IPPseudoChecksum(&newAddr, &ipHdr->daddr,
                tcpHdr ? IPPROTO_TCP : IPPROTO_UDP,
                ntohs(ipHdr->tot_len) - ipHdr->ihl * 4);
        }
    } else {
        addrField = &ipHdr->daddr;
        if (tcpHdr) {
            portField = &tcpHdr->dest;
            checkField = &tcpHdr->check;
        } else if (udpHdr) {
            portField = &udpHdr->dest;
            checkField = &udpHdr->check;
        }
    }

    if (*addrField != newAddr) {
        UINT32 oldAddr = *addrField;
        if (checkField && *checkField != 0 && !l4Offload) {
            /* Recompute total checksum. */
            *checkField = ChecksumUpdate32(*checkField, oldAddr,
                                            newAddr);
        }
        if (ipHdr->check != 0) {
            ipHdr->check = ChecksumUpdate32(ipHdr->check, oldAddr,
                                            newAddr);
        }
        *addrField = newAddr;
    }

    if (portField && *portField != newPort) {
        if (checkField && !l4Offload) {
            /* Recompute total checksum. */
            *checkField = ChecksumUpdate16(*checkField, *portField,
                                           newPort);
        }
        *portField = newPort;
    }
    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsUpdateIPv4Header --
 *      Updates the IPv4 header in ovsFwdCtx.curNbl inline based on the
 *      specified key.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsUpdateIPv4Header(OvsForwardingContext *ovsFwdCtx,
                    const struct ovs_key_ipv4 *ipAttr)
{
    PUINT8 bufferStart;
    UINT32 hdrSize;
    OVS_PACKET_HDR_INFO *layers = &ovsFwdCtx->layers;
    IPHdr *ipHdr;
    TCPHdr *tcpHdr = NULL;
    UDPHdr *udpHdr = NULL;

    ASSERT(layers->value != 0);

    if (layers->isTcp || layers->isUdp) {
        hdrSize = layers->l4Offset +
                  layers->isTcp ? sizeof (*tcpHdr) : sizeof (*udpHdr);
    } else {
        hdrSize = layers->l3Offset + sizeof (*ipHdr);
    }

    bufferStart = OvsGetHeaderBySize(ovsFwdCtx, hdrSize);
    if (!bufferStart) {
        return NDIS_STATUS_RESOURCES;
    }

    ipHdr = (IPHdr *)(bufferStart + layers->l3Offset);

    if (layers->isTcp) {
        tcpHdr = (TCPHdr *)(bufferStart + layers->l4Offset);
    } else if (layers->isUdp) {
        udpHdr = (UDPHdr *)(bufferStart + layers->l4Offset);
    }

    /*
     * Adjust the IP header inline as dictated by the action, and also update
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
        tunKey.flow_hash = (uint16)(hash ? *hash : OvsHashFlow(key));
        tunKey.dst_port = key->ipKey.l4.tpDst;
        NTSTATUS convertStatus = OvsTunnelAttrToIPv4TunnelKey((PNL_ATTR)a, &tunKey);
        status = SUCCEEDED(convertStatus) ? NDIS_STATUS_SUCCESS : NDIS_STATUS_FAILURE;
        ASSERT(status == NDIS_STATUS_SUCCESS);
        RtlCopyMemory(&ovsFwdCtx->tunKey, &tunKey, sizeof ovsFwdCtx->tunKey);
        break;
    }

    case OVS_KEY_ATTR_UDP:
        status = OvsUpdateUdpPorts(ovsFwdCtx,
            NlAttrGetUnspec(a, sizeof(struct ovs_key_udp)));
        break;

    case OVS_KEY_ATTR_TCP:
        status = OvsUpdateTcpPorts(ovsFwdCtx,
            NlAttrGetUnspec(a, sizeof(struct ovs_key_tcp)));
        break;

    default:
        OVS_LOG_INFO("Unhandled attribute %#x", type);
        break;
    }
    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsExecuteRecirc --
 *     The function adds a deferred action to allow the current packet, nbl,
 *     to re-enter datapath packet processing.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsExecuteRecirc(OvsForwardingContext *ovsFwdCtx,
                 OvsFlowKey *key,
                 const PNL_ATTR actions,
                 int rem)
{
    POVS_DEFERRED_ACTION deferredAction = NULL;
    PNET_BUFFER_LIST newNbl = NULL;

    if (!NlAttrIsLast(actions, rem)) {
        /*
         * Recirc action is the not the last action of the action list, so we
         * need to clone the packet.
         */
        newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                                   0, 0, TRUE /*copy NBL info*/);
        /*
         * Skip the recirc action when out of memory, but continue on with the
         * rest of the action list.
         */
        if (newNbl == NULL) {
            ovsActionStats.noCopiedNbl++;
            return NDIS_STATUS_SUCCESS;
        }
    }

    if (newNbl) {
        deferredAction = OvsAddDeferredActions(newNbl, key, NULL);
    } else {
        deferredAction = OvsAddDeferredActions(ovsFwdCtx->curNbl, key, NULL);
    }

    if (deferredAction) {
        deferredAction->key.recircId = NlAttrGetU32(actions);
    } else {
        if (newNbl) {
            ovsActionStats.deferredActionsQueueFull++;
            OvsCompleteNBL(ovsFwdCtx->switchContext, newNbl, TRUE);
        }
    }

    return NDIS_STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsExecuteHash --
 *     The function updates datapath hash read from userspace.
 * --------------------------------------------------------------------------
 */
VOID
OvsExecuteHash(OvsFlowKey *key,
               const PNL_ATTR attr)
{
    struct ovs_action_hash *hash_act = NlAttrData(attr);
    UINT32 hash = 0;

    hash = (UINT32)OvsHashFlow(key);
    hash = OvsJhashWords(&hash, 1, hash_act->hash_basis);
    if (!hash)
        hash = 1;

    key->dpHash = hash;
}

/*
 * --------------------------------------------------------------------------
 * OvsOutputUserspaceAction --
 *      This function sends the packet to userspace according to nested
 *      %OVS_USERSPACE_ATTR_* attributes.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsOutputUserspaceAction(OvsForwardingContext *ovsFwdCtx,
                         OvsFlowKey *key,
                         const PNL_ATTR attr)
{
    NTSTATUS status = NDIS_STATUS_SUCCESS;
    PNL_ATTR userdataAttr;
    PNL_ATTR queueAttr;
    POVS_PACKET_QUEUE_ELEM elem;
    POVS_PACKET_HDR_INFO layers = &ovsFwdCtx->layers;
    BOOLEAN isRecv = FALSE;

    POVS_VPORT_ENTRY vport = OvsFindVportByPortNo(ovsFwdCtx->switchContext,
                                                  ovsFwdCtx->srcVportNo);

    if (vport) {
        if (vport->isExternal ||
            OvsIsTunnelVportType(vport->ovsType)) {
            isRecv = TRUE;
        }
    }

    queueAttr = NlAttrFindNested(attr, OVS_USERSPACE_ATTR_PID);
    userdataAttr = NlAttrFindNested(attr, OVS_USERSPACE_ATTR_USERDATA);

    elem = OvsCreateQueueNlPacket(NlAttrData(userdataAttr),
                                  NlAttrGetSize(userdataAttr),
                                  OVS_PACKET_CMD_ACTION,
                                  vport, key, ovsFwdCtx->curNbl,
                                  NET_BUFFER_LIST_FIRST_NB(ovsFwdCtx->curNbl),
                                  isRecv,
                                  layers);
    if (elem) {
        LIST_ENTRY missedPackets;
        InitializeListHead(&missedPackets);
        InsertTailList(&missedPackets, &elem->link);
        OvsQueuePackets(&missedPackets, 1);
    } else {
        status = NDIS_STATUS_FAILURE;
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsExecuteSampleAction --
 *      Executes actions based on probability, as specified in the nested
 *      %OVS_SAMPLE_ATTR_* attributes.
 * --------------------------------------------------------------------------
 */
static __inline NDIS_STATUS
OvsExecuteSampleAction(OvsForwardingContext *ovsFwdCtx,
                       OvsFlowKey *key,
                       const PNL_ATTR attr)
{
    PNET_BUFFER_LIST newNbl = NULL;
    PNL_ATTR actionsList = NULL;
    PNL_ATTR a = NULL;
    INT rem = 0;

    SRand();
    NL_ATTR_FOR_EACH_UNSAFE(a, rem, NlAttrData(attr), NlAttrGetSize(attr)) {
        switch (NlAttrType(a)) {
        case OVS_SAMPLE_ATTR_PROBABILITY:
        {
            UINT32 probability = NlAttrGetU32(a);

            if (!probability || Rand() > probability) {
                return 0;
            }
            break;
        }
        case OVS_SAMPLE_ATTR_ACTIONS:
            actionsList = a;
            break;
        }
    }

    if (actionsList) {
        rem = NlAttrGetSize(actionsList);
        a = (PNL_ATTR)NlAttrData(actionsList);
    }

    if (!rem) {
        /* Actions list is empty, do nothing */
        return STATUS_SUCCESS;
    }

    /*
     * The only known usage of sample action is having a single user-space
     * action. Treat this usage as a special case.
     */
    if (NlAttrType(a) == OVS_ACTION_ATTR_USERSPACE &&
        NlAttrIsLast(a, rem)) {
        return OvsOutputUserspaceAction(ovsFwdCtx, key, a);
    }

    newNbl = OvsPartialCopyNBL(ovsFwdCtx->switchContext, ovsFwdCtx->curNbl,
                               0, 0, TRUE /*copy NBL info*/);
    if (newNbl == NULL) {
        /*
         * Skip the sample action when out of memory, but continue on with the
         * rest of the action list.
         */
        ovsActionStats.noCopiedNbl++;
        return STATUS_SUCCESS;
    }

    if (!OvsAddDeferredActions(newNbl, key, a)) {
        OVS_LOG_INFO(
            "Deferred actions limit reached, dropping sample action.");
        OvsCompleteNBL(ovsFwdCtx->switchContext, newNbl, TRUE);
    }

    return STATUS_SUCCESS;
}

/*
 * --------------------------------------------------------------------------
 * OvsDoExecuteActions --
 *     Interpret and execute the specified 'actions' on the specified packet
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
OvsDoExecuteActions(POVS_SWITCH_CONTEXT switchContext,
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
                 vlanTag->TagHeader.CanonicalFormatId = (ntohs(vlan->vlan_tci) >> 12) & 0x1;

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

        case OVS_ACTION_ATTR_PUSH_MPLS:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            status = OvsActionMplsPush(&ovsFwdCtx,
                                       (struct ovs_action_push_mpls *)NlAttrGet
                                       ((const PNL_ATTR)a));
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-push MPLS action failed";
                goto dropit;
            }
            layers->l3Offset += MPLS_HLEN;
            layers->l4Offset += MPLS_HLEN;
            break;
        }

        case OVS_ACTION_ATTR_POP_MPLS:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            status = OvsActionMplsPop(&ovsFwdCtx, NlAttrGetBe16(a));
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-pop MPLS action failed";
                goto dropit;
            }
            layers->l3Offset -= MPLS_HLEN;
            layers->l4Offset -= MPLS_HLEN;
            break;
        }

        case OVS_ACTION_ATTR_HASH:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            OvsExecuteHash(key, (const PNL_ATTR)a);

            break;
        }

        case OVS_ACTION_ATTR_CT:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0
                || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            PNET_BUFFER_LIST oldNbl = ovsFwdCtx.curNbl;
            status = OvsExecuteConntrackAction(&ovsFwdCtx, key,
                                               (const PNL_ATTR)a);
            if (status != NDIS_STATUS_SUCCESS) {
                /* Pending NBLs are consumed by Defragmentation. */
                if (status != NDIS_STATUS_PENDING) {
                    OVS_LOG_ERROR("CT Action failed status = %lu", status);
                    dropReason = L"OVS-conntrack action failed";
                } else {
                    /* We added a new pending NBL to be consumed later.
                     * Report to the userspace that the action applied
                     * successfully */
                    status = NDIS_STATUS_SUCCESS;
                }
                goto dropit;
            } else if (oldNbl != ovsFwdCtx.curNbl) {
                /*
                 * OvsIpv4Reassemble consumes the original NBL and creates a
                 * new one and assigns it to the curNbl of ovsFwdCtx.
                 */
                OvsInitForwardingCtx(&ovsFwdCtx,
                                     ovsFwdCtx.switchContext,
                                     ovsFwdCtx.curNbl,
                                     ovsFwdCtx.srcVportNo,
                                     ovsFwdCtx.sendFlags,
                                     NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(ovsFwdCtx.curNbl),
                                     ovsFwdCtx.completionList,
                                     &ovsFwdCtx.layers, FALSE);
                key->ipKey.nwFrag = OVS_FRAG_TYPE_NONE;
            }
            break;
        }

        case OVS_ACTION_ATTR_RECIRC:
        {
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            status = OvsExecuteRecirc(&ovsFwdCtx, key, (const PNL_ATTR)a, rem);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-recirculation action failed";
                goto dropit;
            }

            if (NlAttrIsLast(a, rem)) {
                goto exit;
            }
            break;
        }

        case OVS_ACTION_ATTR_USERSPACE:
        {
            status = OvsOutputUserspaceAction(&ovsFwdCtx, key,
                                              (const PNL_ATTR)a);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-Dropped due to failure to queue to "
                             L"userspace";
                goto dropit;
            }
            dropReason = L"OVS-Completed since packet was copied to "
                         L"userspace";
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
        {
            if (ovsFwdCtx.destPortsSizeOut > 0 || ovsFwdCtx.tunnelTxNic != NULL
                || ovsFwdCtx.tunnelRxNic != NULL) {
                status = OvsOutputBeforeSetAction(&ovsFwdCtx);
                if (status != NDIS_STATUS_SUCCESS) {
                    dropReason = L"OVS-adding destination failed";
                    goto dropit;
                }
            }

            status = OvsExecuteSampleAction(&ovsFwdCtx, key,
                                            (const PNL_ATTR)a);
            if (status != NDIS_STATUS_SUCCESS) {
                dropReason = L"OVS-sample action failed";
                goto dropit;
            }
            break;
        }
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

exit:
    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsActionsExecute --
 *     The function interprets and executes the specified 'actions' on the
 *     specified packet 'curNbl'. See 'OvsDoExecuteActions' description for
 *     more details.
 *
 *     Also executes deferred actions added by recirculation or sample
 *     actions.
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
    NDIS_STATUS status;

    status = OvsDoExecuteActions(switchContext, completionList, curNbl,
                                 portNo, sendFlags, key, hash, layers,
                                 actions, actionsLen);

    if (status == STATUS_SUCCESS) {
        status = OvsProcessDeferredActions(switchContext, completionList,
                                           portNo, sendFlags, layers);
    }

    return status;
}

/*
 * --------------------------------------------------------------------------
 * OvsDoRecirc --
 *     The function processes the packet 'curNbl' that re-entered datapath
 *     packet processing after a recirculation action.
 * --------------------------------------------------------------------------
 */
NDIS_STATUS
OvsDoRecirc(POVS_SWITCH_CONTEXT switchContext,
            OvsCompletionList *completionList,
            PNET_BUFFER_LIST curNbl,
            OvsFlowKey *key,
            UINT32 srcPortNo,
            OVS_PACKET_HDR_INFO *layers)
{
    NDIS_STATUS status;
    OvsFlow *flow;
    OvsForwardingContext ovsFwdCtx = { 0 };
    UINT64 hash = 0;
    ASSERT(layers);

    OvsInitForwardingCtx(&ovsFwdCtx, switchContext, curNbl,
                         srcPortNo, 0,
                         NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(curNbl),
                         completionList, layers, TRUE);
    ASSERT(ovsFwdCtx.switchContext);

    flow = OvsLookupFlow(&ovsFwdCtx.switchContext->datapath, key, &hash, FALSE);
    if (flow) {
        UINT32 level = OvsDeferredActionsLevelGet();

        if (level > DEFERRED_ACTION_EXEC_LEVEL) {
            OvsCompleteNBLForwardingCtx(&ovsFwdCtx,
                L"OVS-Dropped due to deferred actions execution level limit \
                  reached");
            ovsActionStats.deferredActionsExecLimit++;
            ovsFwdCtx.curNbl = NULL;
            return NDIS_STATUS_FAILURE;
        }

        OvsFlowUsed(flow, ovsFwdCtx.curNbl, &ovsFwdCtx.layers);
        ovsFwdCtx.switchContext->datapath.hits++;

        OvsDeferredActionsLevelInc();

        status = OvsDoExecuteActions(ovsFwdCtx.switchContext,
                                     ovsFwdCtx.completionList,
                                     ovsFwdCtx.curNbl,
                                     ovsFwdCtx.srcVportNo,
                                     ovsFwdCtx.sendFlags,
                                     key, &hash, &ovsFwdCtx.layers,
                                     flow->actions, flow->actionsLen);
        ovsFwdCtx.curNbl = NULL;

        OvsDeferredActionsLevelDec();
    } else {
        POVS_VPORT_ENTRY vport = NULL;
        LIST_ENTRY missedPackets;
        UINT32 num = 0;

        ovsFwdCtx.switchContext->datapath.misses++;
        InitializeListHead(&missedPackets);
        vport = OvsFindVportByPortNo(switchContext, srcPortNo);
        if (vport == NULL || vport->ovsState != OVS_STATE_CONNECTED) {
            OvsCompleteNBLForwardingCtx(&ovsFwdCtx,
                L"OVS-Dropped due to port removal");
            ovsActionStats.noVport++;
            return NDIS_STATUS_SUCCESS;
        }
        status = OvsCreateAndAddPackets(NULL, 0, OVS_PACKET_CMD_MISS,
                                        vport, key, ovsFwdCtx.curNbl,
                                        OvsIsExternalVportByPortId(switchContext,
                                            vport->portId),
                                        &ovsFwdCtx.layers,
                                        ovsFwdCtx.switchContext,
                                        &missedPackets, &num);
        if (num) {
            OvsQueuePackets(&missedPackets, num);
        }
        if (status == NDIS_STATUS_SUCCESS) {
            /* Complete the packet since it was copied to user buffer. */
            OvsCompleteNBLForwardingCtx(&ovsFwdCtx,
                L"OVS-Dropped since packet was copied to userspace");
            ovsActionStats.flowMiss++;
        } else {
            OvsCompleteNBLForwardingCtx(&ovsFwdCtx,
                L"OVS-Dropped due to failure to queue to userspace");
            ovsActionStats.failedFlowMiss++;
            status = NDIS_STATUS_FAILURE;
        }
    }

    return status;
}
