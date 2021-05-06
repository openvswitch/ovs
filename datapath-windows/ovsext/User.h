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

/* This file contains structures and function definitions necessary for
 * forwarding packet to user space.
 */

#ifndef __USER_H_
#define __USER_H_ 1


#include "Datapath.h"

/*
 * Even we have more cores, I don't think we need
 * more than 32 queues for processing packets to
 * userspace
 */
#define OVS_DEFAULT_PACKET_QUEUE 1
#define OVS_MAX_PACKET_QUEUE_LEN  4096

/*
 * Only when OVS_PER_VPORT_QUEUE_CTRL is defined
 * we will apply this constraint
 */
#define OVS_MAX_PACKETS_PER_VPORT 128
#define OVS_MAX_PACKETS_PER_TUNNEL 1024

typedef struct _OVS_USER_PACKET_QUEUE {
    UINT32 pid;
    UINT32 numPackets;
    LIST_ENTRY  packetList;
    PVOID instance;
    PIRP pendingIrp;
    NDIS_SPIN_LOCK queueLock;
} OVS_USER_PACKET_QUEUE, *POVS_USER_PACKET_QUEUE;

typedef struct _OVS_PACKET_QUEUE_ELEM {
    UINT32  upcallPid;
    LIST_ENTRY link;
    OVS_PACKET_HDR_INFO hdrInfo;
    OVS_PACKET_INFO packet;
} OVS_PACKET_QUEUE_ELEM, *POVS_PACKET_QUEUE_ELEM;

struct _OVS_OPEN_INSTANCE;

typedef struct _OVS_USER_STATS {
    UINT64 miss;
    UINT64 action;
    UINT32 dropDuetoResource;
    UINT32 dropDuetoChecksum;
    UINT32 ipCsum;
    UINT32 recalTcpCsum;
    UINT32 vlanInsert;
    UINT32 l4Csum;
} OVS_USER_STATS, *POVS_USER_STATS;

VOID OvsCleanupPacketQueue(struct _OVS_OPEN_INSTANCE *instance);

POVS_PACKET_QUEUE_ELEM OvsCreateQueueNlPacket(PVOID userData,
                                              UINT32 userDataLen,
                                              UINT32 cmd, 
                                              POVS_VPORT_ENTRY vport,
                                              OvsFlowKey *key,
                                              OvsIPv4TunnelKey *tunnelKey,
                                              PNET_BUFFER_LIST nbl,
                                              PNET_BUFFER nb,
                                              BOOLEAN isRecv,
                                              POVS_PACKET_HDR_INFO hdrInfo);

VOID OvsQueuePackets(PLIST_ENTRY packetList, UINT32 numElems);
NTSTATUS OvsCreateAndAddPackets(PVOID userData,
                                UINT32 userDataLen,
                                UINT32 cmd,
                                POVS_VPORT_ENTRY vport,
                                OvsFlowKey *key,
                                PNET_BUFFER_LIST nbl,
                                BOOLEAN isRecv,
                                POVS_PACKET_HDR_INFO hdrInfo,
                                POVS_SWITCH_CONTEXT switchContext,
                                LIST_ENTRY *list,
                                UINT32 *num);

NTSTATUS OvsSubscribeDpIoctl(PVOID instanceP,
                             UINT32 pid,
                             UINT8 join);

NTSTATUS OvsReadDpIoctl(PFILE_OBJECT fileObject,
                        PVOID outputBuffer,
                        UINT32 outputLength,
                        UINT32 *replyLen);
NTSTATUS OvsExecuteDpIoctl(OvsPacketExecute *execute);
NTSTATUS OvsPurgeDpIoctl(PFILE_OBJECT fileObject);

NTSTATUS OvsWaitDpIoctl(PIRP irp, PFILE_OBJECT fileObject);

NTSTATUS OvsNlExecuteCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                UINT32 *replyLen);

POVS_OPEN_INSTANCE
OvsGetPidInstance(POVS_SWITCH_CONTEXT switchContext, UINT32 pid);

VOID
OvsAddPidInstance(POVS_SWITCH_CONTEXT switchContext, UINT32 pid,
                  POVS_OPEN_INSTANCE instance);

VOID
OvsDelPidInstance(POVS_SWITCH_CONTEXT switchContext, UINT32 pid);

NTSTATUS OvsReadPacketCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                 UINT32 *replyLen);
NTSTATUS OvsSubscribePacketCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                      UINT32 *replyLen);
NTSTATUS OvsPendPacketCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                 UINT32 *replyLen);

#endif /* __USER_H_ */
