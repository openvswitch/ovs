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
 * OvsUser.c
 *      Manage packet queue for packet miss for userAction.
 */


#include "precomp.h"

#include "Actions.h"
#include "Datapath.h"
#include "Debug.h"
#include "Event.h"
#include "Flow.h"
#include "Jhash.h"
#include "NetProto.h"
#include "Offload.h"
#include "PacketIO.h"
#include "Switch.h"
#include "TunnelIntf.h"
#include "User.h"
#include "Vport.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_USER

POVS_PACKET_QUEUE_ELEM OvsGetNextPacket(POVS_OPEN_INSTANCE instance);
extern PNDIS_SPIN_LOCK gOvsCtrlLock;
extern POVS_SWITCH_CONTEXT gOvsSwitchContext;
OVS_USER_STATS ovsUserStats;

static VOID _MapNlAttrToOvsPktExec(PNL_MSG_HDR nlMsgHdr, PNL_ATTR *nlAttrs,
                                   PNL_ATTR *keyAttrs,
                                   OvsPacketExecute *execute);
extern NL_POLICY nlFlowKeyPolicy[];
extern UINT32 nlFlowKeyPolicyLen;
extern NL_POLICY nlFlowTunnelKeyPolicy[];
extern UINT32 nlFlowTunnelKeyPolicyLen;
DRIVER_CANCEL OvsCancelIrpDatapath;

_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_saves_global_(OldIrql, gOvsSwitchContext->pidHashLock)
_Acquires_lock_(gOvsSwitchContext->pidHashLock)
static __inline VOID
OvsAcquirePidHashLock()
{
    NdisAcquireSpinLock(&(gOvsSwitchContext->pidHashLock));
}

_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_restores_global_(OldIrql, gOvsSwitchContext->pidHashLock)
_Requires_lock_held_(gOvsSwitchContext->pidHashLock)
_Releases_lock_(gOvsSwitchContext->pidHashLock)
static __inline VOID
OvsReleasePidHashLock()
{
    NdisReleaseSpinLock(&(gOvsSwitchContext->pidHashLock));
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
        OvsFreeMemoryWithTag(elem, OVS_USER_POOL_TAG);
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

    ASSERT(instance);
    InitializeListHead(&tmp);
    queue = (POVS_USER_PACKET_QUEUE)instance->packetQueue;
    if (queue) {
        PDRIVER_CANCEL cancelRoutine;
        NdisAcquireSpinLock(&queue->queueLock);
        ASSERT(queue->instance == instance);
        /* XXX Should not happen */
        if (queue->instance != instance) {
            NdisReleaseSpinLock(&queue->queueLock);
            NdisFreeSpinLock(&queue->queueLock);
            return;
        }

        if (queue->numPackets) {
            OvsAppendList(&tmp, &queue->packetList);
            queue->numPackets = 0;
        }
        queue->instance = NULL;
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
        NdisFreeSpinLock(&queue->queueLock);
    }
    LIST_FORALL_SAFE(&tmp, link, next) {
        RemoveEntryList(link);
        elem = CONTAINING_RECORD(link, OVS_PACKET_QUEUE_ELEM, link);
        OvsFreeMemoryWithTag(elem, OVS_USER_POOL_TAG);
    }
    if (irp) {
        OvsCompleteIrpRequest(irp, 0, STATUS_SUCCESS);
    }
    if (queue) {
        OvsFreeMemoryWithTag(queue, OVS_USER_POOL_TAG);
    }

    /* Verify if gOvsSwitchContext exists. */
    if (gOvsSwitchContext) {
        /* Remove the instance from pidHashArray */
        OvsAcquirePidHashLock();
        OvsDelPidInstance(gOvsSwitchContext, instance->pid);
        OvsReleasePidHashLock();
    }
}

NTSTATUS
OvsSubscribeDpIoctl(PVOID instanceP,
                    UINT32 pid,
                    UINT8 join)
{
    POVS_USER_PACKET_QUEUE queue;
    POVS_OPEN_INSTANCE instance = (POVS_OPEN_INSTANCE)instanceP;

    if (instance->packetQueue && !join) {
        /* unsubscribe */
        OvsCleanupPacketQueue(instance);
    } else if (instance->packetQueue == NULL && join) {
        queue = (POVS_USER_PACKET_QUEUE) OvsAllocateMemoryWithTag(
            sizeof *queue, OVS_USER_POOL_TAG);
        if (queue == NULL) {
            return STATUS_NO_MEMORY;
        }
        InitializeListHead(&(instance->pidLink));
        instance->packetQueue = queue;
        RtlZeroMemory(queue, sizeof (*queue));
        NdisAllocateSpinLock(&queue->queueLock);
        NdisAcquireSpinLock(&queue->queueLock);
        InitializeListHead(&queue->packetList);
        queue->pid = pid;
        queue->instance = instance;
        instance->packetQueue = queue;
        NdisReleaseSpinLock(&queue->queueLock);

        OvsAcquirePidHashLock();
        /* Insert the instance to pidHashArray */
        OvsAddPidInstance(gOvsSwitchContext, pid, instance);
        OvsReleasePidHashLock();

    } else {
        /* user mode should call only once for subscribe */
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
            UINT16 size = (UINT16)(elem->packet.payload - elem->packet.data +
                                  elem->hdrInfo.l4Offset);
            RtlCopyMemory(outputBuffer, &elem->packet.data, size);
            ASSERT(len - size >= elem->hdrInfo.l4PayLoad);
            sum = CopyAndCalculateChecksum((UINT8 *)outputBuffer + size,
                                           (UINT8 *)&elem->packet.data + size,
                                           elem->hdrInfo.l4PayLoad, 0);
            ptr =(UINT16 *)((UINT8 *)outputBuffer + size +
                            (elem->hdrInfo.tcpCsumNeeded ?
                             TCP_CSUM_OFFSET : UDP_CSUM_OFFSET));
            *ptr = sum;
            ovsUserStats.l4Csum++;
        } else {
            RtlCopyMemory(outputBuffer, &elem->packet.data, len);
        }

        *replyLen = len;
        OvsFreeMemoryWithTag(elem, OVS_USER_POOL_TAG);
    }
    return STATUS_SUCCESS;
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
    NTSTATUS status = STATUS_SUCCESS;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
    PNL_MSG_HDR nlMsgHdr = &(msgIn->nlMsg);
    PGENL_MSG_HDR genlMsgHdr = &(msgIn->genlMsg);
    POVS_HDR ovsHdr = &(msgIn->ovsHdr);

    PNL_ATTR nlAttrs[__OVS_PACKET_ATTR_MAX];
    PNL_ATTR keyAttrs[__OVS_KEY_ATTR_MAX] = {NULL};

    UINT32 attrOffset = NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN;
    UINT32 keyAttrOffset = 0;
    OvsPacketExecute execute;
    NL_ERROR nlError = NL_ERROR_SUCCESS;
    NL_BUFFER nlBuf;

    static const NL_POLICY nlPktExecPolicy[] = {
        [OVS_PACKET_ATTR_PACKET] = {.type = NL_A_UNSPEC, .optional = FALSE},
        [OVS_PACKET_ATTR_KEY] = {.type = NL_A_UNSPEC, .optional = FALSE},
        [OVS_PACKET_ATTR_ACTIONS] = {.type = NL_A_UNSPEC, .optional = FALSE},
        [OVS_PACKET_ATTR_USERDATA] = {.type = NL_A_UNSPEC, .optional = TRUE},
        [OVS_PACKET_ATTR_EGRESS_TUN_KEY] = {.type = NL_A_UNSPEC,
                                            .optional = TRUE},
        [OVS_PACKET_ATTR_MRU] = { .type = NL_A_U16, .optional = TRUE }
    };

    RtlZeroMemory(&execute, sizeof(OvsPacketExecute));

    /* Get all the top level Flow attributes */
    if ((NlAttrParse(nlMsgHdr, attrOffset, NlMsgAttrsLen(nlMsgHdr),
                     nlPktExecPolicy, ARRAY_SIZE(nlPktExecPolicy),
                     nlAttrs, ARRAY_SIZE(nlAttrs)))
                     != TRUE) {
        OVS_LOG_ERROR("Attr Parsing failed for msg: %p",
                       nlMsgHdr);
        status = STATUS_UNSUCCESSFUL;
        goto done;
    }

    keyAttrOffset = (UINT32)((PCHAR)nlAttrs[OVS_PACKET_ATTR_KEY] -
                    (PCHAR)nlMsgHdr);

    /* Get flow keys attributes */
    if ((NlAttrParseNested(nlMsgHdr, keyAttrOffset,
                           NlAttrLen(nlAttrs[OVS_PACKET_ATTR_KEY]),
                           nlFlowKeyPolicy, nlFlowKeyPolicyLen,
                           keyAttrs, ARRAY_SIZE(keyAttrs))) != TRUE) {
        OVS_LOG_ERROR("Key Attr Parsing failed for msg: %p", nlMsgHdr);
        status = STATUS_UNSUCCESSFUL;
        goto done;
    }

    execute.dpNo = ovsHdr->dp_ifindex;

    _MapNlAttrToOvsPktExec(nlMsgHdr, nlAttrs, keyAttrs, &execute);

    status = OvsExecuteDpIoctl(&execute);

    /* Default reply that we want to send */
    if (status == STATUS_SUCCESS) {
        BOOLEAN ok;

        NlBufInit(&nlBuf, usrParamsCtx->outputBuffer,
                  usrParamsCtx->outputLength);

        /* Prepare nl Msg headers */
        ok = NlFillOvsMsg(&nlBuf, nlMsgHdr->nlmsgType, 0,
                 nlMsgHdr->nlmsgSeq, nlMsgHdr->nlmsgPid,
                 genlMsgHdr->cmd, OVS_PACKET_VERSION,
                 ovsHdr->dp_ifindex);

        if (ok) {
            *replyLen = msgOut->nlMsg.nlmsgLen;
        } else {
            status = STATUS_INVALID_BUFFER_SIZE;
        }
    } else {
        /* Map NTSTATUS to NL_ERROR */
        nlError = NlMapStatusToNlErr(status);

        /* As of now there are no transactional errors in the implementation.
         * Once we have them then we need to map status to correct
         * nlError value, so that below mentioned code gets hit. */
        if ((nlError != NL_ERROR_SUCCESS) &&
            (usrParamsCtx->outputBuffer)) {

            POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
                                           usrParamsCtx->outputBuffer;

            ASSERT(msgError);
            NlBuildErrorMsg(msgIn, msgError, nlError, replyLen);
            status = STATUS_SUCCESS;
            goto done;
        }
    }

done:
    return status;
}

/*
 *----------------------------------------------------------------------------
 *  _MapNlAttrToOvsPktExec --
 *    Maps input Netlink attributes to OvsPacketExecute.
 *----------------------------------------------------------------------------
 */
static VOID
_MapNlAttrToOvsPktExec(PNL_MSG_HDR nlMsgHdr, PNL_ATTR *nlAttrs,
                       PNL_ATTR *keyAttrs, OvsPacketExecute *execute)
{
    execute->packetBuf = NlAttrGet(nlAttrs[OVS_PACKET_ATTR_PACKET]);
    execute->packetLen = NlAttrGetSize(nlAttrs[OVS_PACKET_ATTR_PACKET]);

    execute->nlMsgHdr = nlMsgHdr;

    execute->actions = NlAttrGet(nlAttrs[OVS_PACKET_ATTR_ACTIONS]);
    execute->actionsLen = NlAttrGetSize(nlAttrs[OVS_PACKET_ATTR_ACTIONS]);

    ASSERT(keyAttrs[OVS_KEY_ATTR_IN_PORT]);
    execute->inPort = NlAttrGetU32(keyAttrs[OVS_KEY_ATTR_IN_PORT]);
    execute->keyAttrs = keyAttrs;

    if (nlAttrs[OVS_PACKET_ATTR_MRU]) {
        execute->mru = NlAttrGetU16(nlAttrs[OVS_PACKET_ATTR_MRU]);
    }
}

NTSTATUS
OvsExecuteDpIoctl(OvsPacketExecute *execute)
{
    NTSTATUS                    status = STATUS_SUCCESS;
    NTSTATUS                    ndisStatus = STATUS_SUCCESS;
    LOCK_STATE_EX               lockState;
    PNET_BUFFER_LIST            pNbl = NULL;
    PNL_ATTR                    actions = NULL;
    PNDIS_SWITCH_FORWARDING_DETAIL_NET_BUFFER_LIST_INFO fwdDetail;
    OvsFlowKey                  key = { 0 };
    OVS_PACKET_HDR_INFO         layers = { 0 };
    POVS_VPORT_ENTRY            vport = NULL;
    PNL_ATTR tunnelAttrs[__OVS_TUNNEL_KEY_ATTR_MAX];
    OvsFlowKey tempTunKey = {0};
    POVS_BUFFER_CONTEXT ctx;

    if (execute->packetLen == 0) {
        status = STATUS_INVALID_PARAMETER;
        goto exit;
    }

    actions = execute->actions;

    ASSERT(actions);

    /*
     * Allocate the NBL, copy the data from the userspace buffer. Allocate
     * also, the forwarding context for the packet.
     */
    pNbl = OvsAllocateNBLFromBuffer(gOvsSwitchContext, execute->packetBuf,
                                    execute->packetLen);
    if (pNbl == NULL) {
        status = STATUS_NO_MEMORY;
        goto exit;
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

    status = OvsGetFlowMetadata(&key, execute->keyAttrs);
    if (status != STATUS_SUCCESS) {
        goto dropit;
    }

    if (execute->keyAttrs[OVS_KEY_ATTR_TUNNEL]) {
        UINT32 tunnelKeyAttrOffset;

        tunnelKeyAttrOffset = (UINT32)((PCHAR)
                              (execute->keyAttrs[OVS_KEY_ATTR_TUNNEL])
                              - (PCHAR)execute->nlMsgHdr);

        /* Get tunnel keys attributes */
        if ((NlAttrParseNested(execute->nlMsgHdr, tunnelKeyAttrOffset,
                               NlAttrLen(execute->keyAttrs[OVS_KEY_ATTR_TUNNEL]),
                               nlFlowTunnelKeyPolicy, nlFlowTunnelKeyPolicyLen,
                               tunnelAttrs, ARRAY_SIZE(tunnelAttrs)))
                               != TRUE) {
            OVS_LOG_ERROR("Tunnel key Attr Parsing failed for msg: %p",
                           execute->nlMsgHdr);
            status = STATUS_INVALID_PARAMETER;
            goto dropit;
        }

        MapTunAttrToFlowPut(execute->keyAttrs, tunnelAttrs, &tempTunKey);
    }

    ndisStatus = OvsExtractFlow(pNbl, execute->inPort, &key, &layers,
                     tempTunKey.tunKey.dst == 0 ? NULL : &tempTunKey.tunKey);

    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        /* Invalid network header */
        goto dropit;
    }

    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(pNbl);
    ctx->mru = execute->mru;

    if (ndisStatus == NDIS_STATUS_SUCCESS) {
        NdisAcquireRWLockRead(gOvsSwitchContext->dispatchLock, &lockState, 0);
        ndisStatus = OvsActionsExecute(gOvsSwitchContext, NULL, pNbl,
                                       vport ? vport->portNo :
                                               OVS_DPPORT_NUMBER_INVALID,
                                       NDIS_SEND_FLAGS_SWITCH_DESTINATION_GROUP,
                                       &key, NULL, &layers, actions,
                                       execute->actionsLen);
        pNbl = NULL;
        NdisReleaseRWLock(gOvsSwitchContext->dispatchLock, &lockState);
    }
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        if (ndisStatus == NDIS_STATUS_NOT_SUPPORTED) {
            status = STATUS_NOT_SUPPORTED;
        } else {
            status = STATUS_UNSUCCESSFUL;
        }
    }

dropit:
    if (pNbl) {
        OvsCompleteNBL(gOvsSwitchContext, pNbl, TRUE);
    }
exit:
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

/*
 * ---------------------------------------------------------------------------
 * Given a pid, returns the corresponding USER_PACKET_QUEUE.
 * ---------------------------------------------------------------------------
 */
POVS_USER_PACKET_QUEUE
OvsGetQueue(UINT32 pid)
{
    POVS_OPEN_INSTANCE instance;
    POVS_USER_PACKET_QUEUE ret = NULL;

    instance = OvsGetPidInstance(gOvsSwitchContext, pid);

    if (instance) {
        ret = instance->packetQueue;
    }

    return ret;
}

/*
 * ---------------------------------------------------------------------------
 * Given a pid, returns the corresponding instance.
 * pidHashLock must be acquired before calling this API.
 * ---------------------------------------------------------------------------
 */
POVS_OPEN_INSTANCE
OvsGetPidInstance(POVS_SWITCH_CONTEXT switchContext, UINT32 pid)
{
    POVS_OPEN_INSTANCE instance;
    PLIST_ENTRY head, link;
    UINT32 hash = OvsJhashBytes((const VOID *)&pid, sizeof(pid),
                                OVS_HASH_BASIS);
    head = &(switchContext->pidHashArray[hash & OVS_PID_MASK]);
    LIST_FORALL(head, link) {
        instance = CONTAINING_RECORD(link, OVS_OPEN_INSTANCE, pidLink);
        if (instance->pid == pid) {
            return instance;
        }
    }
    return NULL;
}

/*
 * ---------------------------------------------------------------------------
 * Given a pid and an instance. This API adds instance to pidHashArray.
 * pidHashLock must be acquired before calling this API.
 * ---------------------------------------------------------------------------
 */
VOID
OvsAddPidInstance(POVS_SWITCH_CONTEXT switchContext, UINT32 pid,
                  POVS_OPEN_INSTANCE instance)
{
    PLIST_ENTRY head;
    UINT32 hash = OvsJhashBytes((const VOID *)&pid, sizeof(pid),
                                OVS_HASH_BASIS);
    head = &(switchContext->pidHashArray[hash & OVS_PID_MASK]);
    InsertHeadList(head, &(instance->pidLink));
}

/*
 * ---------------------------------------------------------------------------
 * Given a pid and an instance. This API removes instance from pidHashArray.
 * pidHashLock must be acquired before calling this API.
 * ---------------------------------------------------------------------------
 */
VOID
OvsDelPidInstance(POVS_SWITCH_CONTEXT switchContext, UINT32 pid)
{
    POVS_OPEN_INSTANCE instance = OvsGetPidInstance(switchContext, pid);

    if (instance) {
        RemoveEntryList(&(instance->pidLink));
    }
}

VOID
OvsQueuePackets(PLIST_ENTRY packetList,
                UINT32 numElems)
{
    POVS_USER_PACKET_QUEUE upcallQueue = NULL;
    POVS_PACKET_QUEUE_ELEM elem;
    PLIST_ENTRY  link;
    UINT32 num = 0;
    LIST_ENTRY dropPackets;

    OVS_LOG_LOUD("Enter: numELems: %u", numElems);

    InitializeListHead(&dropPackets);

    while (!IsListEmpty(packetList)) {
        link = RemoveHeadList(packetList);
        elem = CONTAINING_RECORD(link, OVS_PACKET_QUEUE_ELEM, link);

        ASSERT(elem);

        OvsAcquirePidHashLock();

        upcallQueue = OvsGetQueue(elem->upcallPid);
        if (!upcallQueue) {
            /* No upcall queue found, drop this packet. */
            InsertTailList(&dropPackets, &elem->link);
        } else {
            NdisAcquireSpinLock(&upcallQueue->queueLock);

            if (upcallQueue->instance == NULL) {
                InsertTailList(&dropPackets, &elem->link);
            } else {
                InsertTailList(&upcallQueue->packetList, &elem->link);
                upcallQueue->numPackets++;
                if (upcallQueue->pendingIrp) {
                    PIRP irp = upcallQueue->pendingIrp;
                    PDRIVER_CANCEL cancelRoutine;
                    upcallQueue->pendingIrp = NULL;
                    cancelRoutine = IoSetCancelRoutine(irp, NULL);
                    if (cancelRoutine != NULL) {
                        OvsCompleteIrpRequest(irp, 0, STATUS_SUCCESS);
                    }
                }
            }
            NdisReleaseSpinLock(&upcallQueue->queueLock);
        }
        OvsReleasePidHashLock();
    }

    while (!IsListEmpty(&dropPackets)) {
        link = RemoveHeadList(&dropPackets);
        elem = CONTAINING_RECORD(link, OVS_PACKET_QUEUE_ELEM, link);
        OvsFreeMemoryWithTag(elem, OVS_USER_POOL_TAG);
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
                       POVS_VPORT_ENTRY vport,
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

        tsoInfo.Value = NET_BUFFER_LIST_INFO(nbl,
                                             TcpLargeSendNetBufferListInfo);
        nb = NET_BUFFER_LIST_FIRST_NB(nbl);
        packetLength = NET_BUFFER_DATA_LENGTH(nb);

        OVS_LOG_TRACE("MSS %u packet len %u",
                tsoInfo.LsoV1Transmit.MSS, packetLength);
        if (tsoInfo.LsoV1Transmit.MSS) {
            OVS_LOG_TRACE("l4Offset %d", hdrInfo->l4Offset);
            newNbl = OvsTcpSegmentNBL(switchContext, nbl, hdrInfo,
                                      tsoInfo.LsoV1Transmit.MSS , 0, FALSE);
            if (newNbl == NULL) {
                return NDIS_STATUS_FAILURE;
            }
            nbl = newNbl;
        }
    }

    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    while (nb) {
        elem = OvsCreateQueueNlPacket(userData, userDataLen,
                                    cmd, vport, key, nbl, nb,
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
    /* Is it included in the flow key attr XXX */
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
            PIPV6_HEADER ipv6Hdr = (PIPV6_HEADER)(packet +
                                                  hdrInfoIn->l3Offset);
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
        if (hdrInfoIn->isTcp && csumInfo.Transmit.TcpChecksum) {
            hdrInfoOut->tcpCsumNeeded = 1;
        } else if (hdrInfoIn->isUdp && csumInfo.Transmit.UdpChecksum) {
            hdrInfoOut->udpCsumNeeded = 1;
        }
        if (hdrInfoOut->tcpCsumNeeded || hdrInfoOut->udpCsumNeeded) {
#ifdef DBG
            UINT16 sum, *ptr;
            UINT8 proto =
                hdrInfoOut->tcpCsumNeeded ? IPPROTO_TCP : IPPROTO_UDP;
#endif
            if (hdrInfoIn->isIPv4) {
                PIPV4_HEADER ipHdr = (PIPV4_HEADER)(packet +
                                                    hdrInfoIn->l3Offset);
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

    ASSERT(vport);

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
                       POVS_VPORT_ENTRY vport,
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
    PNL_MSG_HDR nlMsg;
    POVS_BUFFER_CONTEXT ctx;

    if (vport == NULL){
        /* No vport is not fatal. */
        return NULL;
    }

    OvsGetPid(vport, nb, &pid);

    if (!pid) {
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
    elem = (POVS_PACKET_QUEUE_ELEM)OvsAllocateMemoryWithTag(allocLen,
                                                            OVS_USER_POOL_TAG);
    if (elem == NULL) {
        ovsUserStats.dropDuetoResource++;
        return NULL;
    }
    elem->hdrInfo.value = hdrInfo->value;
    elem->upcallPid = pid;
    elem->packet.totalLen = nlMsgSize;
    /* XXX remove queueid */
    elem->packet.queue = 0;
    /* XXX  no need as the length is already in the NL attrib */
    elem->packet.userDataLen = userDataLen;
    elem->packet.inPort = vport->portNo;
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
    if (!NlFillOvsMsg(&nlBuf, OVS_WIN_NL_PACKET_FAMILY_ID, 0,
                      0, pid, (UINT8)cmd, OVS_PACKET_VERSION,
                      gOvsSwitchContext->dpNo)) {
        goto fail;
    }

    if (MapFlowKeyToNlKey(&nlBuf, key, OVS_PACKET_ATTR_KEY,
                          OVS_KEY_ATTR_TUNNEL) != STATUS_SUCCESS) {
        goto fail;
    }

    /* Set MRU attribute */
    ctx = (POVS_BUFFER_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl);
    if (ctx->mru != 0) {
        if (!NlMsgPutTailU16(&nlBuf, OVS_PACKET_ATTR_MRU, (UINT16)ctx->mru)) {
            goto fail;
        }
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

    nlMsg = (PNL_MSG_HDR)NlBufAt(&nlBuf, 0, 0);
    nlMsg->nlmsgLen = NlBufSize(&nlBuf);
    /* 'totalLen' should be size of valid data. */
    elem->packet.totalLen = nlMsg->nlmsgLen;

    return elem;
fail:
    OvsFreeMemoryWithTag(elem, OVS_USER_POOL_TAG);
    return NULL;
}

/*
 * --------------------------------------------------------------------------
 *  Handler for the subscription for a packet queue
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsSubscribePacketCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                             UINT32 *replyLen)
{
    NDIS_STATUS status;
    BOOLEAN rc;
    UINT8 join;
    UINT32 pid;
    const NL_POLICY policy[] =  {
        [OVS_NL_ATTR_PACKET_PID] = {.type = NL_A_U32 },
        [OVS_NL_ATTR_PACKET_SUBSCRIBE] = {.type = NL_A_U8 }
        };
    PNL_ATTR attrs[ARRAY_SIZE(policy)];

    UNREFERENCED_PARAMETER(replyLen);

    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;

    rc = NlAttrParse(&msgIn->nlMsg, sizeof (*msgIn),
         NlMsgAttrsLen((PNL_MSG_HDR)msgIn), policy, ARRAY_SIZE(policy),
                       attrs, ARRAY_SIZE(attrs));
    if (!rc) {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    join = NlAttrGetU8(attrs[OVS_NL_ATTR_PACKET_SUBSCRIBE]);
    pid = NlAttrGetU32(attrs[OVS_NL_ATTR_PACKET_PID]);

    /* The socket subscribed with must be the same socket we perform receive*/
    ASSERT(pid == instance->pid);

    status = OvsSubscribeDpIoctl(instance, pid, join);

    /*
     * XXX Need to add this instance to a global data structure
     * which hold all packet based instances. The data structure (hash)
     * should be searched through the pid field of the instance for
     * placing the missed packet into the correct queue
     */
done:
    return status;
}

/*
 * --------------------------------------------------------------------------
 * Handler for queueing an IRP used for missed packet notification. The IRP is
 * completed when a packet received and mismatched. STATUS_PENDING is returned
 * on success. User mode keep a pending IRP at all times.
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsPendPacketCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                       UINT32 *replyLen)
{
    UNREFERENCED_PARAMETER(replyLen);

    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;

    /*
     * XXX access to packet queue must be through acquiring a lock as user mode
     * could unsubscribe and the instnace will be freed.
     */
    return OvsWaitDpIoctl(usrParamsCtx->irp, instance->fileObject);
}

/*
 * --------------------------------------------------------------------------
 * Handler for reading missed pacckets from the driver event queue. This
 * handler is executed when user modes issues a socket receive on a socket
 * --------------------------------------------------------------------------
 */
NTSTATUS
OvsReadPacketCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                       UINT32 *replyLen)
{
#ifdef DBG
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
#endif
    POVS_OPEN_INSTANCE instance =
        (POVS_OPEN_INSTANCE)usrParamsCtx->ovsInstance;
    NTSTATUS status;

    ASSERT(usrParamsCtx->devOp == OVS_READ_DEV_OP);

    /* Should never read events with a dump socket */
    ASSERT(instance->dumpState.ovsMsg == NULL);

    /* Must have an packet queue */
    ASSERT(instance->packetQueue != NULL);

    /* Output buffer has been validated while validating read dev op. */
    ASSERT(msgOut != NULL && usrParamsCtx->outputLength >= sizeof *msgOut);

    /* Read a packet from the instance queue */
    status = OvsReadDpIoctl(instance->fileObject, usrParamsCtx->outputBuffer,
                            usrParamsCtx->outputLength, replyLen);
    return status;
}
