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
 * OvsUser.c
 *      Manage packet queue for packet miss for userAction.
 */


#include "precomp.h"

#include "Datapath.h"
#include "Switch.h"
#include "Vport.h"
#include "Event.h"
#include "User.h"
#include "PacketIO.h"
#include "Checksum.h"
#include "NetProto.h"
#include "Flow.h"
#include "TunnelIntf.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_USER
#include "Debug.h"

OVS_USER_PACKET_QUEUE ovsPacketQueues[OVS_MAX_NUM_PACKET_QUEUES];

POVS_PACKET_QUEUE_ELEM OvsGetNextPacket(POVS_OPEN_INSTANCE instance);
extern PNDIS_SPIN_LOCK gOvsCtrlLock;
extern POVS_SWITCH_CONTEXT gOvsSwitchContext;
OVS_USER_STATS ovsUserStats;


NTSTATUS
OvsUserInit()
{
    UINT32 i;
    POVS_USER_PACKET_QUEUE queue;
    for (i = 0; i < OVS_MAX_NUM_PACKET_QUEUES; i++) {
        queue = &ovsPacketQueues[i];
        RtlZeroMemory(queue, sizeof (*queue));
        InitializeListHead(&queue->packetList);
        NdisAllocateSpinLock(&queue->queueLock);
    }
    return STATUS_SUCCESS;
}

VOID
OvsUserCleanup()
{
    UINT32 i;
    POVS_USER_PACKET_QUEUE queue;
    for (i = 0; i < OVS_MAX_NUM_PACKET_QUEUES; i++) {
        queue = &ovsPacketQueues[i];
        ASSERT(IsListEmpty(&queue->packetList));
        ASSERT(queue->instance == NULL);
        ASSERT(queue->pendingIrp == NULL);
        NdisFreeSpinLock(&queue->queueLock);
    }
}

static VOID
OvsPurgePacketQueue(POVS_USER_PACKET_QUEUE queue,
                    POVS_OPEN_INSTANCE instance)
{
    PLIST_ENTRY link, next;
    LIST_ENTRY tmp;
    POVS_PACKET_QUEUE_ELEM elem;

    InitializeListHead(&tmp);
    NdisAcquireSpinLock(&queue->queueLock);
    if (queue->instance != instance) {
        NdisReleaseSpinLock(&queue->queueLock);
        return;
    }

    if (queue->numPackets) {
        OvsAppendList(&tmp, &queue->packetList);
        queue->numPackets = 0;
    }
    NdisReleaseSpinLock(&queue->queueLock);
    LIST_FORALL_SAFE(&tmp, link, next) {
        RemoveEntryList(link);
        elem = CONTAINING_RECORD(link, OVS_PACKET_QUEUE_ELEM, link);
        OvsFreeMemory(elem);
    }
}


VOID
OvsCleanupPacketQueue(POVS_OPEN_INSTANCE instance)
{
    POVS_USER_PACKET_QUEUE queue;
    POVS_PACKET_QUEUE_ELEM elem;
    PLIST_ENTRY link, next;
    LIST_ENTRY tmp;
    PIRP irp = NULL;

    InitializeListHead(&tmp);
    queue = (POVS_USER_PACKET_QUEUE)instance->packetQueue;
    if (queue) {
        PDRIVER_CANCEL cancelRoutine;
        NdisAcquireSpinLock(&queue->queueLock);
        if (queue->instance != instance) {
            NdisReleaseSpinLock(&queue->queueLock);
            return;
        }

        if (queue->numPackets) {
            OvsAppendList(&tmp, &queue->packetList);
            queue->numPackets = 0;
        }
        queue->instance = NULL;
        queue->queueId = OVS_MAX_NUM_PACKET_QUEUES;
        instance->packetQueue = NULL;
        irp = queue->pendingIrp;
        queue->pendingIrp = NULL;
        if (irp) {
            cancelRoutine = IoSetCancelRoutine(irp, NULL);
            if (cancelRoutine == NULL) {
                irp = NULL;
            }
        }
        NdisReleaseSpinLock(&queue->queueLock);
    }
    LIST_FORALL_SAFE(&tmp, link, next) {
        RemoveEntryList(link);
        elem = CONTAINING_RECORD(link, OVS_PACKET_QUEUE_ELEM, link);
        OvsFreeMemory(elem);
    }
    if (irp) {
        OvsCompleteIrpRequest(irp, 0, STATUS_SUCCESS);
    }
}

NTSTATUS
OvsSubscribeDpIoctl(PFILE_OBJECT fileObject,
                    PVOID inputBuffer,
                    UINT32 inputLength)
{
    POVS_OPEN_INSTANCE instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    UINT32 queueId;
    POVS_USER_PACKET_QUEUE queue;
    if (inputLength < sizeof (UINT32)) {
        return STATUS_INVALID_PARAMETER;
    }
    queueId = *(UINT32 *)inputBuffer;
    if (instance->packetQueue && queueId >= OVS_MAX_NUM_PACKET_QUEUES) {
        /*
         * unsubscribe
         */
        OvsCleanupPacketQueue(instance);
    } else if (instance->packetQueue == NULL &&
               queueId < OVS_MAX_NUM_PACKET_QUEUES) {
        queue = &ovsPacketQueues[queueId];
        NdisAcquireSpinLock(&queue->queueLock);
        if (ovsPacketQueues[queueId].instance) {
             if (ovsPacketQueues[queueId].instance != instance) {
                 NdisReleaseSpinLock(&queue->queueLock);
                 return STATUS_INSUFFICIENT_RESOURCES;
             } else {
                 NdisReleaseSpinLock(&queue->queueLock);
                 return STATUS_SUCCESS;
             }
        }
        queue->queueId = queueId;
        queue->instance = instance;
        instance->packetQueue = queue;
        ASSERT(IsListEmpty(&queue->packetList));
        NdisReleaseSpinLock(&queue->queueLock);
    } else {
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}


NTSTATUS
OvsReadDpIoctl(PFILE_OBJECT fileObject,
               PVOID outputBuffer,
               UINT32 outputLength,
               UINT32 *replyLen)
{
    POVS_OPEN_INSTANCE instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    POVS_PACKET_QUEUE_ELEM elem;
    UINT32 len;

#define TCP_CSUM_OFFSET  16
#define UDP_CSUM_OFFSET  6
    ASSERT(instance);

    if (instance->packetQueue == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (outputLength < (sizeof (OVS_PACKET_INFO) + OVS_MIN_PACKET_SIZE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    elem = OvsGetNextPacket(instance);
    if (elem) {
        /*
         * XXX revisit this later
         */
        len = elem->packet.totalLen > outputLength ? outputLength :
                 elem->packet.totalLen;

        if ((elem->hdrInfo.tcpCsumNeeded || elem->hdrInfo.udpCsumNeeded) &&
            len == elem->packet.totalLen) {
            UINT16 sum, *ptr;
            UINT16 size = (UINT16)(elem->packet.userDataLen +
                                   elem->hdrInfo.l4Offset +
                                   (UINT16)sizeof (OVS_PACKET_INFO));
            RtlCopyMemory(outputBuffer, &elem->packet, size);
            ASSERT(len - size >=  elem->hdrInfo.l4PayLoad);
            sum = CopyAndCalculateChecksum((UINT8 *)outputBuffer + size,
                                           (UINT8 *)&elem->packet + size,
                                           elem->hdrInfo.l4PayLoad, 0);
            ptr =(UINT16 *)((UINT8 *)outputBuffer + size +
                            (elem->hdrInfo.tcpCsumNeeded ?
                             TCP_CSUM_OFFSET : UDP_CSUM_OFFSET));
            *ptr = sum;
            ovsUserStats.l4Csum++;
        } else {
            RtlCopyMemory(outputBuffer, &elem->packet, len);
        }

        *replyLen = len;
        OvsFreeMemory(elem);
    }
    return STATUS_SUCCESS;
}

/* Helper function to allocate a Forwarding Context for an NBL */
NTSTATUS
OvsAllocateForwardingContextForNBL(POVS_SWITCH_CONTEXT switchContext,
                                   PNET_BUFFER_LIST nbl)
{
    return switchContext->NdisSwitchHandlers.
        AllocateNetBufferListForwardingContext(
            switchContext->NdisSwitchContext, nbl);
}

/*
 * --------------------------------------------------------------------------
 * This function allocates all the stuff necessary for creating an NBL from the
 * input buffer of specified length, namely, a nonpaged data buffer of size
 * length, an MDL from it, and a NB and NBL from it. It does not allocate an NBL
 * context yet. It also copies data from the specified buffer to the NBL.
 * --------------------------------------------------------------------------
 */
PNET_BUFFER_LIST
OvsAllocateNBLForUserBuffer(POVS_SWITCH_CONTEXT switchContext,
                            PVOID userBuffer,
                            ULONG length)
{
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
    data = (PUINT8)MmGetSystemAddressForMdlSafe(mdl, LowPagePriority) +
                    NET_BUFFER_CURRENT_MDL_OFFSET(nb);
    if (!data) {
        OvsCompleteNBL(switchContext, nbl, TRUE);
        return NULL;
    }

    NdisMoveMemory(data, userBuffer, length);

    return nbl;
}

/*
 *----------------------------------------------------------------------------
 *  OvsNlExecuteCmdHandler --
 *    Handler for OVS_PACKET_CMD_EXECUTE command.
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsNlExecuteCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                       UINT32 *replyLen)
{
    NTSTATUS rc = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(usrParamsCtx);
    UNREFERENCED_PARAMETER(replyLen);

    return rc;
}

NTSTATUS
OvsExecuteDpIoctl(PVOID inputBuffer,
                  UINT32 inputLength,
                  UINT32 outputLength)
{
    NTSTATUS                    status = STATUS_SUCCESS;
    NTSTATUS                    ndisStatus;
    OvsPacketExecute            *execute;
    LOCK_STATE_EX               lockState;
    PNET_BUFFER_LIST pNbl;
    PNL_ATTR actions;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail;
    OvsFlowKey key;
    OVS_PACKET_HDR_INFO layers;
    POVS_VPORT_ENTRY vport;

    if (inputLength < sizeof(*execute) || outputLength != 0) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    NdisAcquireSpinLock(gOvsCtrlLock);
    if (gOvsSwitchContext == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto unlock;
    }

    execute = (struct OvsPacketExecute *) inputBuffer;

    if (execute->packetLen == 0) {
        status = STATUS_INVALID_PARAMETER;
        goto unlock;
    }

    if (inputLength != sizeof (*execute) +
                       execute->actionsLen + execute->packetLen) {
        status = STATUS_INFO_LENGTH_MISMATCH;
        goto unlock;
    }
    actions = (PNL_ATTR)((PCHAR)&execute->actions + execute->packetLen);

    /*
     * Allocate the NBL, copy the data from the userspace buffer. Allocate
     * also, the forwarding context for the packet.
     */
    pNbl = OvsAllocateNBLForUserBuffer(gOvsSwitchContext, &execute->packetBuf,
                                       execute->packetLen);
    if (pNbl == NULL) {
        status = STATUS_NO_MEMORY;
        goto unlock;
    }

    fwdDetail = NET_BUFFER_LIST_SWITCH_FORWARDING_DETAIL(pNbl);
    vport = OvsFindVportByPortNo(gOvsSwitchContext, execute->inPort);
    if (vport) {
        fwdDetail->SourcePortId = vport->portId;
        fwdDetail->SourceNicIndex = vport->nicIndex;
    } else {
        fwdDetail->SourcePortId = NDIS_SWITCH_DEFAULT_PORT_ID;
        fwdDetail->SourceNicIndex = 0;
    }
    // XXX: Figure out if any of the other members of fwdDetail need to be set.

    ndisStatus = OvsExtractFlow(pNbl, fwdDetail->SourcePortId, &key, &layers,
                              NULL);
    if (ndisStatus == NDIS_STATUS_SUCCESS) {
        ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
        NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState,
                              NDIS_RWL_AT_DISPATCH_LEVEL);
        ndisStatus = OvsActionsExecute(gOvsSwitchContext, NULL, pNbl,
                                       vport ? vport->portNo :
                                               OVS_DEFAULT_PORT_NO,
                                       NDIS_SEND_FLAGS_SWITCH_DESTINATION_GROUP,
                                       &key, NULL, &layers, actions,
                                       execute->actionsLen);
        pNbl = NULL;
        NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
    }
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        status = STATUS_UNSUCCESSFUL;
    }

    if (pNbl) {
        OvsCompleteNBL(gOvsSwitchContext, pNbl, TRUE);
    }
unlock:
    NdisReleaseSpinLock(gOvsCtrlLock);
    return status;
}


NTSTATUS
OvsPurgeDpIoctl(PFILE_OBJECT fileObject)
{
    POVS_OPEN_INSTANCE instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    POVS_USER_PACKET_QUEUE queue = (POVS_USER_PACKET_QUEUE)instance->packetQueue;

    if (queue == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    OvsPurgePacketQueue(queue, instance);
    return STATUS_SUCCESS;
}

VOID
OvsCancelIrpDatapath(PDEVICE_OBJECT deviceObject,
                     PIRP irp)
{
    PIO_STACK_LOCATION irpSp;
    PFILE_OBJECT fileObject;
    POVS_OPEN_INSTANCE instance;
    POVS_USER_PACKET_QUEUE queue = NULL;

    UNREFERENCED_PARAMETER(deviceObject);

    IoReleaseCancelSpinLock(irp->CancelIrql);
    irpSp = IoGetCurrentIrpStackLocation(irp);
    fileObject = irpSp->FileObject;

    if (fileObject == NULL) {
        goto done;
    }
    NdisAcquireSpinLock(gOvsCtrlLock);
    instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    if (instance) {
        queue = instance->packetQueue;
    }
    if (instance == NULL || queue == NULL) {
        NdisReleaseSpinLock(gOvsCtrlLock);
        goto done;
    }
    NdisReleaseSpinLock(gOvsCtrlLock);
    NdisAcquireSpinLock(&queue->queueLock);
    if (queue->pendingIrp == irp) {
        queue->pendingIrp = NULL;
    }
    NdisReleaseSpinLock(&queue->queueLock);
done:
    OvsCompleteIrpRequest(irp, 0, STATUS_CANCELLED);
}


NTSTATUS
OvsWaitDpIoctl(PIRP irp, PFILE_OBJECT fileObject)
{
    POVS_OPEN_INSTANCE instance = (POVS_OPEN_INSTANCE)fileObject->FsContext;
    POVS_USER_PACKET_QUEUE queue =
               (POVS_USER_PACKET_QUEUE)instance->packetQueue;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN cancelled = FALSE;

    if (queue == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    NdisAcquireSpinLock(&queue->queueLock);
    if (queue->instance != instance) {
        NdisReleaseSpinLock(&queue->queueLock);
        return STATUS_INVALID_PARAMETER;
    }
    if (queue->pendingIrp) {
        NdisReleaseSpinLock(&queue->queueLock);
        return STATUS_DEVICE_BUSY;
    }
    if (queue->numPackets == 0) {
        PDRIVER_CANCEL cancelRoutine;
        IoMarkIrpPending(irp);
        IoSetCancelRoutine(irp, OvsCancelIrpDatapath);
        if (irp->Cancel) {
            cancelRoutine = IoSetCancelRoutine(irp, NULL);
            if (cancelRoutine) {
                cancelled = TRUE;
            }
        } else {
            queue->pendingIrp = irp;
        }
        status = STATUS_PENDING;
    }
    NdisReleaseSpinLock(&queue->queueLock);
    if (cancelled) {
        OvsCompleteIrpRequest(irp, 0, STATUS_CANCELLED);
        OVS_LOG_INFO("Datapath IRP cancelled: %p", irp);
    }
    return status;
}


POVS_PACKET_QUEUE_ELEM
OvsGetNextPacket(POVS_OPEN_INSTANCE instance)
{
    POVS_USER_PACKET_QUEUE queue;
    PLIST_ENTRY link;
    queue = (POVS_USER_PACKET_QUEUE)instance->packetQueue;
    if (queue == NULL) {
        return NULL;
    }
    NdisAcquireSpinLock(&queue->queueLock);
    if (queue->instance != instance || queue->numPackets == 0) {
        NdisReleaseSpinLock(&queue->queueLock);
        return NULL;
    }
    link = RemoveHeadList(&queue->packetList);
    queue->numPackets--;
    NdisReleaseSpinLock(&queue->queueLock);
    return CONTAINING_RECORD(link, OVS_PACKET_QUEUE_ELEM, link);
}


POVS_USER_PACKET_QUEUE
OvsGetQueue(UINT32 queueId)
{
    POVS_USER_PACKET_QUEUE queue;
    if (queueId >= OVS_MAX_NUM_PACKET_QUEUES) {
        return NULL;
    }
    queue = &ovsPacketQueues[queueId];
    return queue->instance != NULL ? queue : NULL;
}

VOID
OvsQueuePackets(UINT32 queueId,
                PLIST_ENTRY packetList,
                UINT32 numElems)
{
    POVS_USER_PACKET_QUEUE queue = OvsGetQueue(queueId);
    POVS_PACKET_QUEUE_ELEM elem;
    PIRP irp = NULL;
    PLIST_ENTRY  link;
    UINT32 num = 0;

    OVS_LOG_LOUD("Enter: queueId %u, numELems: %u",
                  queueId, numElems);
    if (queue == NULL) {
        goto cleanup;
    }

    NdisAcquireSpinLock(&queue->queueLock);
    if (queue->instance == NULL) {
        NdisReleaseSpinLock(&queue->queueLock);
        goto cleanup;
    } else {
        OvsAppendList(&queue->packetList, packetList);
        queue->numPackets += numElems;
    }
    if (queue->pendingIrp) {
        PDRIVER_CANCEL cancelRoutine;
        irp = queue->pendingIrp;
        queue->pendingIrp = NULL;
        cancelRoutine = IoSetCancelRoutine(irp, NULL);
        if (cancelRoutine == NULL) {
            irp = NULL;
        }
    }
    NdisReleaseSpinLock(&queue->queueLock);
    if (irp) {
        OvsCompleteIrpRequest(irp, 0, STATUS_SUCCESS);
    }

cleanup:
    while (!IsListEmpty(packetList)) {
        link = RemoveHeadList(packetList);
        elem = CONTAINING_RECORD(link, OVS_PACKET_QUEUE_ELEM, link);
        OvsFreeMemory(elem);
        num++;
    }
    OVS_LOG_LOUD("Exit: drop %u packets", num);
}


/*
 *----------------------------------------------------------------------------
 * OvsCreateAndAddPackets --
 *
 *  Create a packet and forwarded to user space.
 *
 *  This function would fragment packet if needed, and queue
 *  each segment to user space.
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsCreateAndAddPackets(PVOID userData,
                       UINT32 userDataLen,
                       UINT32 cmd,
                       UINT32 inPort,
                       OvsFlowKey *key,
                       PNET_BUFFER_LIST nbl,
                       BOOLEAN isRecv,
                       POVS_PACKET_HDR_INFO hdrInfo,
                       POVS_SWITCH_CONTEXT switchContext,
                       LIST_ENTRY *list,
                       UINT32 *num)
{
    POVS_PACKET_QUEUE_ELEM elem;
    PNET_BUFFER_LIST newNbl = NULL;
    PNET_BUFFER nb;

    if (hdrInfo->isTcp) {
        NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO tsoInfo;
        UINT32 packetLength;

        tsoInfo.Value = NET_BUFFER_LIST_INFO(nbl, TcpLargeSendNetBufferListInfo);
        nb = NET_BUFFER_LIST_FIRST_NB(nbl);
        packetLength = NET_BUFFER_DATA_LENGTH(nb);

        OVS_LOG_TRACE("MSS %u packet len %u",
                tsoInfo.LsoV1Transmit.MSS, packetLength);
        if (tsoInfo.LsoV1Transmit.MSS) {
            OVS_LOG_TRACE("l4Offset %d", hdrInfo->l4Offset);
            newNbl = OvsTcpSegmentNBL(switchContext, nbl, hdrInfo,
                    tsoInfo.LsoV1Transmit.MSS , 0);
            if (newNbl == NULL) {
                return NDIS_STATUS_FAILURE;
            }
            nbl = newNbl;
        }
    }

    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    while (nb) {
        elem = OvsCreateQueueNlPacket(userData, userDataLen,
                                    cmd, inPort, key, nbl, nb,
                                    isRecv, hdrInfo);
        if (elem) {
            InsertTailList(list, &elem->link);
            (*num)++;
        }
        nb = NET_BUFFER_NEXT_NB(nb);
    }
    if (newNbl) {
        OvsCompleteNBL(switchContext, newNbl, TRUE);
    }
    return NDIS_STATUS_SUCCESS;
}

static __inline UINT32
OvsGetUpcallMsgSize(PVOID userData,
                    UINT32 userDataLen,
                    OvsIPv4TunnelKey *tunnelKey,
                    UINT32 payload)
{
    UINT32 size = NLMSG_ALIGN(sizeof(struct ovs_header)) +
                  NlAttrSize(payload) +
                  NlAttrSize(OvsFlowKeyAttrSize());

    /* OVS_PACKET_ATTR_USERDATA */
    if (userData) {
        size += NlAttrTotalSize(userDataLen);
    }
    /* OVS_PACKET_ATTR_EGRESS_TUN_KEY */
    /* Is it included in the the flwo key attr XXX */
    if (tunnelKey) {
        size += NlAttrTotalSize(OvsTunKeyAttrSize());
    }
    return size;
}

/*
 *----------------------------------------------------------------------------
 * This function completes the IP Header csum. record the L4 payload offset and
 * if there is a need to calculate the TCP or UDP csum. The actual csum will be
 * caluculated simopultaneossly with the copy of the payload to the destination
 * buffer when the packet is read.
 *----------------------------------------------------------------------------
 */
static VOID
OvsCompletePacketHeader(UINT8 *packet,
                        BOOLEAN isRecv,
                        NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo,
                        POVS_PACKET_HDR_INFO hdrInfoIn,
                        POVS_PACKET_HDR_INFO hdrInfoOut)
{
    if ((isRecv && csumInfo.Receive.IpChecksumValueInvalid) ||
        (!isRecv && csumInfo.Transmit.IsIPv4 &&
        csumInfo.Transmit.IpHeaderChecksum)) {
        PIPV4_HEADER ipHdr = (PIPV4_HEADER)(packet + hdrInfoOut->l3Offset);
        ASSERT(hdrInfoIn->isIPv4);
        ASSERT(ipHdr->Version == 4);
        ipHdr->HeaderChecksum = IPChecksum((UINT8 *)ipHdr,
            ipHdr->HeaderLength << 2,
            (UINT16)~ipHdr->HeaderChecksum);
        ovsUserStats.ipCsum++;
    }
    ASSERT(hdrInfoIn->tcpCsumNeeded == 0 && hdrInfoOut->udpCsumNeeded == 0);
    /*
     * calculate TCP/UDP pseudo checksum
     */
    if (isRecv && csumInfo.Receive.TcpChecksumValueInvalid) {
        /*
         * Only this case, we need to reclaculate pseudo checksum
         * all other cases, it is assumed the pseudo checksum is
         * filled already.
         *
         */
        PTCP_HDR tcpHdr = (PTCP_HDR)(packet + hdrInfoIn->l4Offset);
        if (hdrInfoIn->isIPv4) {
            PIPV4_HEADER ipHdr = (PIPV4_HEADER)(packet + hdrInfoIn->l3Offset);
            hdrInfoOut->l4PayLoad = (UINT16)(ntohs(ipHdr->TotalLength) -
                                    (ipHdr->HeaderLength << 2));
            tcpHdr->th_sum = IPPseudoChecksum((UINT32 *)&ipHdr->SourceAddress,
                                         (UINT32 *)&ipHdr->DestinationAddress,
                                         IPPROTO_TCP, hdrInfoOut->l4PayLoad);
        } else {
            PIPV6_HEADER ipv6Hdr = (PIPV6_HEADER)(packet + hdrInfoIn->l3Offset);
            hdrInfoOut->l4PayLoad =
                (UINT16)(ntohs(ipv6Hdr->PayloadLength) +
                hdrInfoIn->l3Offset + sizeof(IPV6_HEADER)-
                hdrInfoIn->l4Offset);
            ASSERT(hdrInfoIn->isIPv6);
            tcpHdr->th_sum =
                IPv6PseudoChecksum((UINT32 *)&ipv6Hdr->SourceAddress,
                (UINT32 *)&ipv6Hdr->DestinationAddress,
                IPPROTO_TCP, hdrInfoOut->l4PayLoad);
        }
        hdrInfoOut->tcpCsumNeeded = 1;
        ovsUserStats.recalTcpCsum++;
    } else if (!isRecv) {
        if (csumInfo.Transmit.TcpChecksum) {
            hdrInfoOut->tcpCsumNeeded = 1;
        } else if (csumInfo.Transmit.UdpChecksum) {
            hdrInfoOut->udpCsumNeeded = 1;
        }
        if (hdrInfoOut->tcpCsumNeeded || hdrInfoOut->udpCsumNeeded) {
#ifdef DBG
            UINT16 sum, *ptr;
            UINT8 proto =
                hdrInfoOut->tcpCsumNeeded ? IPPROTO_TCP : IPPROTO_UDP;
#endif
            if (hdrInfoIn->isIPv4) {
                PIPV4_HEADER ipHdr = (PIPV4_HEADER)(packet + hdrInfoIn->l3Offset);
                hdrInfoOut->l4PayLoad = (UINT16)(ntohs(ipHdr->TotalLength) -
                    (ipHdr->HeaderLength << 2));
#ifdef DBG
                sum = IPPseudoChecksum((UINT32 *)&ipHdr->SourceAddress,
                    (UINT32 *)&ipHdr->DestinationAddress,
                    proto, hdrInfoOut->l4PayLoad);
#endif
            } else {
                PIPV6_HEADER ipv6Hdr = (PIPV6_HEADER)(packet +
                    hdrInfoIn->l3Offset);
                hdrInfoOut->l4PayLoad =
                    (UINT16)(ntohs(ipv6Hdr->PayloadLength) +
                    hdrInfoIn->l3Offset + sizeof(IPV6_HEADER)-
                    hdrInfoIn->l4Offset);
                ASSERT(hdrInfoIn->isIPv6);
#ifdef DBG
                sum = IPv6PseudoChecksum((UINT32 *)&ipv6Hdr->SourceAddress,
                    (UINT32 *)&ipv6Hdr->DestinationAddress,
                    proto, hdrInfoOut->l4PayLoad);
#endif
            }
#ifdef DBG
            ptr = (UINT16 *)(packet + hdrInfoIn->l4Offset +
                (hdrInfoOut->tcpCsumNeeded ?
            TCP_CSUM_OFFSET : UDP_CSUM_OFFSET));
            ASSERT(*ptr == sum);
#endif
        }
    }
}

static NTSTATUS
OvsGetPid(POVS_VPORT_ENTRY vport, PNET_BUFFER nb, UINT32 *pid)
{
    UNREFERENCED_PARAMETER(nb);

    /* XXX select a pid from an array of pids using a flow based hash */
    *pid = vport->upcallPid;
    return STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsCreateQueueNlPacket --
 *
 *  Create a packet which will be forwarded to user space.
 *
 * InputParameter:
 *   userData: when cmd is user action, this field contain
 *      user action data.
 *   userDataLen: as name indicated
 *   cmd: either miss or user action
 *   inPort: datapath port id from which the packet is received.
 *   key: flow Key with a tunnel key if available
 *   nbl:  the NET_BUFFER_LIST which contain the packet
 *   nb: the packet
 *   isRecv: This is used to decide how to interprete the csum info
 *   hdrInfo: include hdr info initialized during flow extraction.
 *
 * Results:
 *    NULL if fail to create the packet
 *    The packet element otherwise
 *----------------------------------------------------------------------------
 */
POVS_PACKET_QUEUE_ELEM
OvsCreateQueueNlPacket(PVOID userData,
                       UINT32 userDataLen,
                       UINT32 cmd,
                       UINT32 inPort,
                       OvsFlowKey *key,
                       PNET_BUFFER_LIST nbl,
                       PNET_BUFFER nb,
                       BOOLEAN isRecv,
                       POVS_PACKET_HDR_INFO hdrInfo)
{
#define VLAN_TAG_SIZE 4
    UINT32 allocLen, dataLen, extraLen;
    POVS_PACKET_QUEUE_ELEM elem;
    UINT8 *src, *dst;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
    NDIS_NET_BUFFER_LIST_8021Q_INFO vlanInfo;
    OvsIPv4TunnelKey *tunnelKey = (OvsIPv4TunnelKey *)&key->tunKey;
    UINT32 pid;
    UINT32 nlMsgSize;
    NL_BUFFER nlBuf;

    /* XXX pass vport in the stack rather than portNo */
    POVS_VPORT_ENTRY vport =
        OvsFindVportByPortNo(gOvsSwitchContext, inPort);

    if (vport == NULL){
        /* Should never happen as dispatch lock is held */
        ASSERT(vport);
        return NULL;
    }

    if (!OvsGetPid(vport, nb, &pid)) {
        /*
         * There is no userspace queue created yet, so there is no point for
         * creating a new packet to be queued.
         */
        return NULL;
    }

    csumInfo.Value = NET_BUFFER_LIST_INFO(nbl, TcpIpChecksumNetBufferListInfo);

    if (isRecv && (csumInfo.Receive.TcpChecksumFailed ||
                  (csumInfo.Receive.UdpChecksumFailed && !hdrInfo->udpCsumZero) ||
                  csumInfo.Receive.IpChecksumFailed)) {
        OVS_LOG_INFO("Packet dropped due to checksum failure.");
        ovsUserStats.dropDuetoChecksum++;
        return NULL;
    }

    vlanInfo.Value = NET_BUFFER_LIST_INFO(nbl, Ieee8021QNetBufferListInfo);
    extraLen = vlanInfo.TagHeader.VlanId ? VLAN_TAG_SIZE : 0;

    dataLen = NET_BUFFER_DATA_LENGTH(nb);

    if (NlAttrSize(dataLen) > MAXUINT16) {
        return NULL;
    }

    nlMsgSize = OvsGetUpcallMsgSize(userData, userDataLen, tunnelKey,
                                    dataLen + extraLen);

    allocLen = sizeof (OVS_PACKET_QUEUE_ELEM) + nlMsgSize;
    elem = (POVS_PACKET_QUEUE_ELEM)OvsAllocateMemory(allocLen);
    if (elem == NULL) {
        ovsUserStats.dropDuetoResource++;
        return NULL;
    }
    elem->hdrInfo.value = hdrInfo->value;
    elem->packet.totalLen = nlMsgSize;
    /* XXX remove queueid */
    elem->packet.queue = 0;
    /* XXX  no need as the length is already in the NL attrib */
    elem->packet.userDataLen = userDataLen;
    elem->packet.inPort = inPort;
    elem->packet.cmd = cmd;
    if (cmd == (UINT32)OVS_PACKET_CMD_MISS) {
        ovsUserStats.miss++;
    } else if (cmd == (UINT32)OVS_PACKET_CMD_ACTION) {
        ovsUserStats.action++;
    } else {
        ASSERT(FALSE);
        goto fail;
    }
    /* XXX Should we have both packetLen and TotalLen*/
    elem->packet.packetLen = dataLen + extraLen;

    NlBufInit(&nlBuf, (PCHAR)elem->packet.data, nlMsgSize);

    /*
     * Initialize the OVS header
     * Since we are pre allocating memory for the NL buffer
     * the attribute settings should not fail
     */
    if (NlFillOvsMsg(&nlBuf, OVS_WIN_NL_PACKET_FAMILY_ID, 0,
                      0, pid, (UINT8)cmd, OVS_PACKET_VERSION,
                      gOvsSwitchContext->dpNo) != STATUS_SUCCESS) {
        goto fail;
    }

    if (MapFlowKeyToNlKey(&nlBuf, key, OVS_PACKET_ATTR_KEY,
                          OVS_KEY_ATTR_TUNNEL) != STATUS_SUCCESS) {
        goto fail;
    }

    /* XXX must send OVS_PACKET_ATTR_EGRESS_TUN_KEY if set by vswtchd */
    if (userData){
        if (!NlMsgPutTailUnspec(&nlBuf, OVS_PACKET_ATTR_USERDATA,
                                userData, (UINT16)userDataLen)) {
            goto fail;
        }
    }

    /*
     * Make space for the payload to be copied and set the attribute
     * XXX Uninit set initilizes the buffer with xero, we don't actually need
     * that the payload to be initailized
     */
    dst = (UINT8 *)NlMsgPutTailUnspecUninit(&nlBuf, OVS_PACKET_ATTR_PACKET,
                                            (UINT16)(dataLen + extraLen));
    if (!dst) {
        goto fail;
    }

    /* Store the payload for csum calculation when packet is read */
    elem->packet.payload = dst;
    dst += extraLen;

    src = NdisGetDataBuffer(nb, dataLen, dst, 1, 0);
    if (src == NULL) {
        ovsUserStats.dropDuetoResource++;
        goto fail;
    }    else if (src != dst) {
        /* Copy the data from the NDIS buffer to dst. */
        RtlCopyMemory(dst, src, dataLen);
    }

    /* Set csum if was offloaded */
    OvsCompletePacketHeader(dst, isRecv, csumInfo, hdrInfo, &elem->hdrInfo);

    /*
     * Finally insert VLAN tag
     */
    if (extraLen) {
        dst = elem->packet.payload;
        src = dst + extraLen;
        ((UINT32 *)dst)[0] = ((UINT32 *)src)[0];
        ((UINT32 *)dst)[1] = ((UINT32 *)src)[1];
        ((UINT32 *)dst)[2] = ((UINT32 *)src)[2];
        dst += 12;
        ((UINT16 *)dst)[0] = htons(0x8100);
        ((UINT16 *)dst)[1] = htons(vlanInfo.TagHeader.VlanId |
            (vlanInfo.TagHeader.UserPriority << 13));
        elem->hdrInfo.l3Offset += VLAN_TAG_SIZE;
        elem->hdrInfo.l4Offset += VLAN_TAG_SIZE;
        ovsUserStats.vlanInsert++;
    }
    return elem;
fail:
    OvsFreeMemory(elem);
    return NULL;
}
