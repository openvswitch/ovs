/*
 * Copyright (c) 2016 Cloudbase Solutions Srl
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

#ifndef __ACTIONS_H_
#define __ACTIONS_H_ 1

#include "Switch.h"
#include "PacketIO.h"


/*
 * There a lot of data that needs to be maintained while executing the pipeline
 * as dictated by the actions of a flow, across different functions at different
 * levels. Such data is put together in a 'context' structure. Care should be
 * exercised while adding new members to the structure - only add ones that get
 * used across multiple stages in the pipeline/get used in multiple functions.
 */
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

NDIS_STATUS
OvsActionsExecute(POVS_SWITCH_CONTEXT switchContext,
                  OvsCompletionList *completionList,
                  PNET_BUFFER_LIST curNbl,
                  UINT32 srcVportNo,
                  ULONG sendFlags,
                  OvsFlowKey *key,
                  UINT64 *hash,
                  OVS_PACKET_HDR_INFO *layers,
                  const PNL_ATTR actions,
                  int actionsLen);

NDIS_STATUS
OvsDoExecuteActions(POVS_SWITCH_CONTEXT switchContext,
                    OvsCompletionList *completionList,
                    PNET_BUFFER_LIST curNbl,
                    UINT32 srcVportNo,
                    ULONG sendFlags,
                    OvsFlowKey *key,
                    UINT64 *hash,
                    OVS_PACKET_HDR_INFO *layers,
                    const PNL_ATTR actions,
                    int actionsLen);

NDIS_STATUS
OvsDoRecirc(POVS_SWITCH_CONTEXT switchContext,
            OvsCompletionList *completionList,
            PNET_BUFFER_LIST curNbl,
            OvsFlowKey *key,
            UINT32 srcPortNo,
            OVS_PACKET_HDR_INFO *layers);

PUINT8 OvsGetHeaderBySize(OvsForwardingContext *ovsFwdCtx,
                          UINT32 size);

NDIS_STATUS
OvsUpdateUdpPorts(OvsForwardingContext *ovsFwdCtx,
                  const struct ovs_key_udp *udpAttr);

NDIS_STATUS
OvsUpdateTcpPorts(OvsForwardingContext *ovsFwdCtx,
                  const struct ovs_key_tcp *tcpAttr);

NDIS_STATUS
OvsUpdateIPv4Header(OvsForwardingContext *ovsFwdCtx,
                    const struct ovs_key_ipv4 *ipAttr);

NDIS_STATUS
OvsUpdateAddressAndPort(OvsForwardingContext *ovsFwdCtx,
                        UINT32 newAddr, UINT16 newPort,
                        BOOLEAN isSource, BOOLEAN isTx);

#endif /* __ACTIONS_H_ */
