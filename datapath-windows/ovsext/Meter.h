/*
 * Copyright (c) 2022 VMware, Inc.
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

#ifndef OVS_METER_H
#define OVS_METER_H

#include "precomp.h"
#include "Switch.h"
#include "User.h"
#include "Datapath.h"
#include "Event.h"
#include "NetProto.h"
#include "Netlink/Netlink.h"
#include "Flow.h"

#define OVS_MAX_BANDS 1
#define OVS_MAX_METERS 32
#define METER_HASH_BUCKET_MAX 1024

typedef struct _DpMeterBand {
    UINT32 type;
    UINT32 rate;
    UINT32 burst_size;
    UINT64 bucket;
    struct ovs_flow_stats stats;
} DpMeterBand;

typedef struct _DpMeter {
    LIST_ENTRY link;
    UINT32 id;
    UINT16 kbps:1;
    UINT16 keepStatus:1;
    UINT16 nBands;
    UINT32 maxDelta;
    UINT64 used;
    struct ovs_flow_stats stats;
    DpMeterBand  bands[OVS_MAX_BANDS];
} DpMeter;

NTSTATUS OvsInitMeter(POVS_SWITCH_CONTEXT context);
NDIS_STATUS OvsNewMeterCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                  UINT32 *replyLen);
NDIS_STATUS OvsMeterFeatureProbe(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
UINT32 *replyLen);

NDIS_STATUS OvsMeterDestroy(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                   UINT32 *replyLen);
DpMeter* OvsMeterLookup(UINT32 meterId);
BOOLEAN
OvsMeterExecute(OvsForwardingContext *fwdCtx, UINT32 meterId);
BOOLEAN
buildOvsMeterReplyMsg(NL_BUFFER *nlBuf, DpMeter *dpMeter);


#endif //OVS_METER_H
