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
 * OvsTunnel.c
 *  WFP Classified callback function and Action code for injecting a packet to the vswitch
 */

#include "precomp.h"

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union
#include <fwpsk.h>
#pragma warning(pop)

#pragma warning( push )
#pragma warning( disable:4127 )

#include <fwpmk.h>
#include "Tunnel.h"
#include "Switch.h"
#include "Vport.h"
#include "Event.h"
#include "User.h"
#include "Vxlan.h"
#include "PacketIO.h"
#include "NetProto.h"
#include "Flow.h"

extern POVS_SWITCH_CONTEXT gOvsSwitchContext;

static NTSTATUS
OvsInjectPacketThroughActions(PNET_BUFFER_LIST pNbl,
                              OVS_TUNNEL_PENDED_PACKET *packet);

VOID OvsAcquireDatapathRead(OVS_DATAPATH *datapath,
                            LOCK_STATE_EX *lockState,
                            BOOLEAN dispatch);
VOID OvsAcquireDatapathWrite(OVS_DATAPATH *datapath,
                             LOCK_STATE_EX *lockState,
                             BOOLEAN dispatch);
VOID OvsReleaseDatapath(OVS_DATAPATH *datapath,
                        LOCK_STATE_EX *lockState);


NTSTATUS
OvsTunnelNotify(FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                const GUID *filterKey,
                const FWPS_FILTER *filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}

static NTSTATUS
OvsTunnelAnalyzePacket(OVS_TUNNEL_PENDED_PACKET *packet)
{
    NTSTATUS status = STATUS_SUCCESS;
    UINT32 packetLength = 0;
    ULONG bytesCopied = 0;
    NET_BUFFER_LIST *copiedNBL = NULL;
    NET_BUFFER *netBuffer;
    NDIS_STATUS ndisStatus;

    /*
     * For inbound net buffer list, we can assume it contains only one
     * net buffer (unless it was an re-assembeled fragments). in both cases
     * the first net buffer should include all headers, we assert if the retreat fails
     */
    netBuffer = NET_BUFFER_LIST_FIRST_NB(packet->netBufferList);

    /* Drop the packet from the host stack */
    packet->classifyOut->actionType = FWP_ACTION_BLOCK;
    packet->classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

    /* Adjust the net buffer list offset to the start of the IP header */
    ndisStatus = NdisRetreatNetBufferDataStart(netBuffer,
                                               packet->ipHeaderSize +
                                               packet->transportHeaderSize,
                                               0, NULL);
    ASSERT(ndisStatus == NDIS_STATUS_SUCCESS);

    /* Single NBL element for WFP */
    ASSERT(packet->netBufferList->Next == NULL);

    /* Note that the copy will inherit the original net buffer list's offset */
    packetLength = NET_BUFFER_DATA_LENGTH(netBuffer);
    copiedNBL = OvsAllocateVariableSizeNBL(gOvsSwitchContext, packetLength,
                                           OVS_DEFAULT_HEADROOM_SIZE);

    if (copiedNBL == NULL) {
        goto analyzeDone;
    }

    status = NdisCopyFromNetBufferToNetBuffer(NET_BUFFER_LIST_FIRST_NB(copiedNBL),
                                              0, packetLength,
                                              netBuffer, 0, &bytesCopied);
    if (status != NDIS_STATUS_SUCCESS || packetLength != bytesCopied) {
        goto analyzeFreeNBL;
    }

    status = OvsInjectPacketThroughActions(copiedNBL,
                                           packet);
    goto analyzeDone;

    /* Undo the adjustment on the original net buffer list */
analyzeFreeNBL:
    OvsCompleteNBL(gOvsSwitchContext, copiedNBL, TRUE);
analyzeDone:
    NdisAdvanceNetBufferDataStart(netBuffer,
                                  packet->transportHeaderSize + packet->ipHeaderSize,
                                  FALSE,
                                  NULL);
    return status;
}


/*
 * --------------------------------------------------------------------------
 * This is the classifyFn function of the datagram-data callout. It
 * allocates a packet structure to store the classify and meta data and
 * it references the net buffer list for out-of-band modification and
 * re-injection. The packet structure will be queued to the global packet
 * queue. The worker thread will then be signaled, if idle, to process
 * the queue.
 * --------------------------------------------------------------------------
 */
VOID
OvsTunnelClassify(const FWPS_INCOMING_VALUES *inFixedValues,
                  const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
                  VOID *layerData,
                  const VOID *classifyContext,
                  const FWPS_FILTER *filter,
                  UINT64 flowContext,
                  FWPS_CLASSIFY_OUT *classifyOut)
{
    OVS_TUNNEL_PENDED_PACKET packetStorage;
    OVS_TUNNEL_PENDED_PACKET *packet = &packetStorage;
    FWP_DIRECTION  direction;

    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    ASSERT(layerData != NULL);

    /* We don't have the necessary right to alter the packet flow */
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        /* XXX TBD revisit protect against other filters owning this packet */
        ASSERT(FALSE);
        goto Exit;
    }

    RtlZeroMemory(packet, sizeof(OVS_TUNNEL_PENDED_PACKET));

    /* classifyOut cannot be accessed from a different thread context */
    packet->classifyOut = classifyOut;

    if (inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V4) {
        direction =
            inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].\
            value.uint32;
    }
    else {
        ASSERT(inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V6);
        direction =
            inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION].\
            value.uint32;
    }

    packet->netBufferList = layerData;

    ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
        FWPS_METADATA_FIELD_COMPARTMENT_ID));

    ASSERT(direction == FWP_DIRECTION_INBOUND);

    ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(
        inMetaValues,
        FWPS_METADATA_FIELD_IP_HEADER_SIZE));
    ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(
        inMetaValues,
        FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE));

    packet->ipHeaderSize = inMetaValues->ipHeaderSize;
    packet->transportHeaderSize = inMetaValues->transportHeaderSize;

    ASSERT(inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8 == IPPROTO_UDP );
    OvsTunnelAnalyzePacket(packet);

Exit:
    ;
}


static NTSTATUS
OvsInjectPacketThroughActions(PNET_BUFFER_LIST pNbl,
                              OVS_TUNNEL_PENDED_PACKET *packet)
{
    NTSTATUS status = STATUS_SUCCESS;
    OvsIPv4TunnelKey tunnelKey;
    NET_BUFFER *pNb;
    ULONG sendCompleteFlags = 0;
    BOOLEAN dispatch;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail;
    LOCK_STATE_EX lockState, dpLockState;
    LIST_ENTRY missedPackets;
    OvsCompletionList completionList;
    KIRQL irql;
    ULONG SendFlags = NDIS_SEND_FLAGS_SWITCH_DESTINATION_GROUP;
    OVS_DATAPATH *datapath = NULL;

    ASSERT(gOvsSwitchContext);
    datapath = &gOvsSwitchContext->datapath;

    /* Fill the tunnel key */
    status = OvsSlowPathDecapVxlan(pNbl, &tunnelKey);

    if(!NT_SUCCESS(status)) {
        goto dropit;
    }

    pNb = NET_BUFFER_LIST_FIRST_NB(pNbl);

    NdisAdvanceNetBufferDataStart(pNb,
                                  packet->transportHeaderSize + packet->ipHeaderSize +
                                  sizeof(VXLANHdr),
                                  FALSE,
                                  NULL);

    /* Most likely (always) dispatch irql */
    irql = KeGetCurrentIrql();

    /* dispatch is used for datapath lock as well */
    dispatch = (irql == DISPATCH_LEVEL) ?  NDIS_RWL_AT_DISPATCH_LEVEL : 0;
    if (dispatch) {
        sendCompleteFlags |=  NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL;
    }

    InitializeListHead(&missedPackets);
    OvsInitCompletionList(&completionList, gOvsSwitchContext,
                          sendCompleteFlags);

    {
        POVS_VPORT_ENTRY vport;
        UINT32 portNo;
        OVS_PACKET_HDR_INFO layers;
        OvsFlowKey key;
        UINT64 hash;
        PNET_BUFFER curNb;
        OvsFlow *flow;

        fwdDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(pNbl);

        /*
         * XXX WFP packets contain a single NBL structure.
         * Reassembeled packet "may" have multiple NBs, however, a simple test shows
         * that the packet still has a single NB (after reassemble)
         * We still need to check if the Ethernet header of the innet packet is in a single MD
         */

        curNb = NET_BUFFER_LIST_FIRST_NB(pNbl);
        ASSERT(curNb->Next == NULL);

        NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState, dispatch);

        /* Lock the flowtable for the duration of accessing the flow */
        OvsAcquireDatapathRead(datapath, &dpLockState, NDIS_RWL_AT_DISPATCH_LEVEL);

        SendFlags |= NDIS_SEND_FLAGS_DISPATCH_LEVEL;

        vport = OvsFindTunnelVportByDstPort(gOvsSwitchContext,
                                            htons(tunnelKey.dst_port));

        if (vport == NULL){
            status = STATUS_UNSUCCESSFUL;
            goto unlockAndDrop;
        }

        ASSERT(vport->ovsType == OVS_VPORT_TYPE_VXLAN);

        portNo = vport->portNo;

        status = OvsExtractFlow(pNbl, portNo, &key, &layers, &tunnelKey);
        if (status != NDIS_STATUS_SUCCESS) {
            goto unlockAndDrop;
        }

        flow = OvsLookupFlow(datapath, &key, &hash, FALSE);
        if (flow) {
            OvsFlowUsed(flow, pNbl, &layers);
            datapath->hits++;

            OvsActionsExecute(gOvsSwitchContext, &completionList, pNbl,
                            portNo, SendFlags, &key, &hash, &layers,
                            flow->actions, flow->actionsLen);

            OvsReleaseDatapath(datapath, &dpLockState);
        } else {
            POVS_PACKET_QUEUE_ELEM elem;

            datapath->misses++;
            elem = OvsCreateQueueNlPacket(NULL, 0, OVS_PACKET_CMD_MISS,
                                        portNo, &key, pNbl, curNb,
                                        TRUE, &layers);
            if (elem) {
                /* Complete the packet since it was copied to user buffer. */
                InsertTailList(&missedPackets, &elem->link);
                OvsQueuePackets(&missedPackets, 1);
            } else {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            goto unlockAndDrop;
        }

        NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);

    }

    return status;

unlockAndDrop:
    OvsReleaseDatapath(datapath, &dpLockState);
    NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
dropit:
    pNbl = OvsCompleteNBL(gOvsSwitchContext, pNbl, TRUE);
    ASSERT(pNbl == NULL);
    return status;
}

#pragma warning(pop)
