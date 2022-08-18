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

#include "Meter.h"
#include "precomp.h"
#include "Switch.h"
#include "User.h"
#include "Datapath.h"
#include "Event.h"
#include "NetProto.h"
#include "Flow.h"
#include "PacketParser.h"
#include "Util.h"

static PNDIS_RW_LOCK_EX meterGlobalTableLock;
PLIST_ENTRY meterGlobalTable;

const NL_POLICY nlMeterPolicy[OVS_METER_ATTR_MAX + 1] = {
        [OVS_METER_ATTR_ID] = { .type = NL_A_U32, },
        [OVS_METER_ATTR_KBPS] = { .type = NL_A_FLAG, .optional = TRUE },
        [OVS_METER_ATTR_STATS] = { .minLen = sizeof(struct ovs_flow_stats),
                                   .maxLen = sizeof(struct ovs_flow_stats),
                                   .optional = TRUE },
        [OVS_METER_ATTR_BANDS] = { .type = NL_A_NESTED, .optional = TRUE },
        [OVS_METER_ATTR_USED] = { .type = NL_A_U64, .optional = TRUE },
        [OVS_METER_ATTR_CLEAR] = { .type = NL_A_FLAG, .optional = TRUE },
        [OVS_METER_ATTR_MAX_METERS] = { .type = NL_A_U32, .optional = TRUE },
        [OVS_METER_ATTR_MAX_BANDS] = { .type = NL_A_U32,  .optional = TRUE },
};

const NL_POLICY bandPolicy[OVS_BAND_ATTR_MAX + 1] = {
        [OVS_BAND_ATTR_TYPE] = { .type = NL_A_U32, .optional = FALSE },
        [OVS_BAND_ATTR_RATE] = { .type = NL_A_U32, .optional = TRUE },
        [OVS_BAND_ATTR_BURST] = { .type = NL_A_U32,  .optional = TRUE },
        [OVS_BAND_ATTR_STATS] = { .minLen = sizeof(struct ovs_flow_stats),
                                  .maxLen = sizeof(struct ovs_flow_stats),
                                  .optional = TRUE },
};

NTSTATUS
OvsInitMeter(POVS_SWITCH_CONTEXT context)
{
    UINT32 maxEntry = METER_HASH_BUCKET_MAX;

    meterGlobalTableLock = NdisAllocateRWLock(context->NdisFilterHandle);
    if (meterGlobalTableLock == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    meterGlobalTable = OvsAllocateMemoryWithTag(sizeof(LIST_ENTRY) * maxEntry,
                                                OVS_METER_TAG);
    if (!meterGlobalTable) {
        NdisFreeRWLock(meterGlobalTableLock);
        return NDIS_STATUS_RESOURCES;
    }

    for (UINT32 index = 0; index < maxEntry; index++) {
        InitializeListHead(&meterGlobalTable[index]);
    }

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
FillBandIntoMeter(PNL_ATTR meterAttrs[], DpMeter *meter, PNL_MSG_HDR nlMsgHdr)
{
    PNL_ATTR a = NULL;
    INT rem = 0;
    UINT32 bandMaxDelta = 0;
    UINT32 attrOffset = 0;
    DpMeterBand *band = NULL;
    PNL_ATTR bandAttrs[OVS_BAND_ATTR_MAX + 1];
    UINT16 nBands = 0;

    band = meter->bands;
    NL_ATTR_FOR_EACH(a, rem, NlAttrData(meterAttrs[OVS_METER_ATTR_BANDS]),
                     NlAttrGetSize(meterAttrs[OVS_METER_ATTR_BANDS])) {
        RtlZeroMemory(bandAttrs, sizeof(bandAttrs));
        attrOffset = (UINT32)((PCHAR)NlAttrData(a) - (PCHAR)nlMsgHdr);
        if (!NlAttrParse(nlMsgHdr,
                         attrOffset,
                         NlAttrGetSize(a),
                         bandPolicy, ARRAY_SIZE(bandPolicy),
                         bandAttrs, ARRAY_SIZE(bandAttrs))) {
            return STATUS_INVALID_PARAMETER;
        }

        if (bandAttrs[OVS_BAND_ATTR_TYPE]) {
            band->type = NlAttrGetU32(bandAttrs[OVS_BAND_ATTR_TYPE]);
        }

        if (bandAttrs[OVS_BAND_ATTR_RATE]) {
            band->rate = NlAttrGetU32(bandAttrs[OVS_BAND_ATTR_RATE]);
        }

        if (bandAttrs[OVS_BAND_ATTR_BURST]) {
            band->burst_size = NlAttrGetU32(bandAttrs[OVS_BAND_ATTR_BURST]);
        }

        band->bucket = (band->burst_size + band->rate) * 1000;
        bandMaxDelta = (UINT32)((band->bucket / band->rate)  / 10);
        if (bandMaxDelta > meter->maxDelta) {
            meter->maxDelta = bandMaxDelta;
        }

        nBands++;
        band++;
    }

    meter->nBands = nBands;
    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
OvsNewMeterCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                      UINT32 *replyLen)
{
    DpMeter *meter = NULL;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    PNL_MSG_HDR nlMsgHdr = &(msgIn->nlMsg);
    PGENL_MSG_HDR genlMsgHdr = &(msgIn->genlMsg);
    POVS_HDR ovsHdr = &(msgIn->ovsHdr);
    LOCK_STATE_EX lockState;
    PNL_ATTR meterAttrs[ARRAY_SIZE(nlMeterPolicy)];
    ASSERT(usrParamsCtx->inputBuffer != NULL);
    PNL_MSG_HDR nlMsgOutHdr = NULL;
    NL_BUFFER nlBuf;
    NL_ERROR nlError = NL_ERROR_SUCCESS;

    if (!NlAttrParse((PNL_MSG_HDR)msgIn,
                     NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN,
                     NlMsgAttrsLen((PNL_MSG_HDR)msgIn),
                     nlMeterPolicy, ARRAY_SIZE(nlMeterPolicy),
                     meterAttrs, ARRAY_SIZE(meterAttrs))) {
        nlError = NL_ERROR_NOMSG;
        goto Done;
    }

    meter = OvsAllocateMemoryWithTag(sizeof(*meter), OVS_METER_TAG);
    if (!meter) {
        nlError = NL_ERROR_NOMEM;
        goto Done;
    }

    RtlZeroMemory(meter, sizeof(*meter));
    meter->id = NlAttrGetU32(meterAttrs[OVS_METER_ATTR_ID]);
    meter->kbps = meterAttrs[OVS_METER_ATTR_KBPS] ? 1 : 0;
    meter->keepStatus = meterAttrs[OVS_METER_ATTR_CLEAR] ? 1 : 0;
    if (meter->keepStatus && meterAttrs[OVS_METER_ATTR_STATS]) {
        meter->stats = *(struct ovs_flow_stats *)NlAttrData(
                        meterAttrs[OVS_METER_ATTR_STATS]);
    }

    if (FillBandIntoMeter(meterAttrs, meter, nlMsgHdr) != NDIS_STATUS_SUCCESS) {
        nlError = NL_ERROR_NOMSG;
        OvsFreeMemoryWithTag(meter, OVS_METER_TAG);
        goto Done;
    }

    NdisAcquireRWLockWrite(meterGlobalTableLock, &lockState, 0);
    InsertHeadList(&meterGlobalTable[meter->id & (METER_HASH_BUCKET_MAX - 1)],
                   &(meter->link));
    NdisReleaseRWLock(meterGlobalTableLock, &lockState);

    NlBufInit(&nlBuf, usrParamsCtx->outputBuffer, usrParamsCtx->outputLength);
    nlMsgOutHdr = (PNL_MSG_HDR)(NlBufAt(&nlBuf, 0, 0));
    if (!NlFillOvsMsg(&nlBuf, nlMsgHdr->nlmsgType, 0,
                     nlMsgHdr->nlmsgSeq, nlMsgHdr->nlmsgPid,
                     genlMsgHdr->cmd, OVS_METER_CMD_GET,
                     ovsHdr->dp_ifindex)) {
        nlError = NL_ERROR_NOMSG;
        goto Done;
    }

    if (!buildOvsMeterReplyMsg(&nlBuf, meter)) {
        nlError = NL_ERROR_NOMEM;
        goto Done;
    }

    NlMsgSetSize(nlMsgOutHdr, NlBufSize(&nlBuf));
    NlMsgAlignSize(nlMsgOutHdr);
    *replyLen += NlMsgSize(nlMsgOutHdr);

Done:
    if (nlError != NL_ERROR_SUCCESS) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
                usrParamsCtx->outputBuffer;

        ASSERT(msgError);
        NlBuildErrorMsg(msgIn, msgError, nlError, replyLen);
        ASSERT(*replyLen != 0);
    }

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS OvsMeterFeatureProbe(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                 UINT32 *replyLen)
{
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    PNL_MSG_HDR nlMsgHdr = &(msgIn->nlMsg);
    POVS_HDR ovsHdr = &(msgIn->ovsHdr);
    PNL_MSG_HDR nlMsgOutHdr = NULL;
    BOOLEAN ok = FALSE;
    PGENL_MSG_HDR genlMsgHdr = &(msgIn->genlMsg);
    NL_BUFFER nlBuf;
    NL_ERROR nlError = NL_ERROR_SUCCESS;
    UINT32 bandsOffset = 0;
    UINT32 bandAttrOffset = 0;

    NlBufInit(&nlBuf, usrParamsCtx->outputBuffer, usrParamsCtx->outputLength);
    nlMsgOutHdr = (PNL_MSG_HDR)(NlBufAt(&nlBuf, 0, 0));
    ok = NlFillOvsMsg(&nlBuf, nlMsgHdr->nlmsgType, 0,
                      nlMsgHdr->nlmsgSeq, nlMsgHdr->nlmsgPid,
                      genlMsgHdr->cmd, OVS_METER_CMD_FEATURES,
                      ovsHdr->dp_ifindex);
    if (!ok) {
        nlError = NL_ERROR_NOMSG;
        goto Done;
    }

    if (!NlMsgPutTailU32(&nlBuf, OVS_METER_ATTR_MAX_METERS, UINT32_MAX)) {
        nlError = NL_ERROR_NOMSG;
        goto Done;
    }

    if (!NlMsgPutTailU32(&nlBuf, OVS_METER_ATTR_MAX_BANDS, OVS_MAX_BANDS)) {
        nlError = NL_ERROR_NOMSG;
        goto Done;
    }

    bandsOffset = NlMsgStartNested(&nlBuf, OVS_METER_ATTR_BANDS);
    bandAttrOffset = NlMsgStartNested(&nlBuf, OVS_METER_ATTR_UNSPEC);
    if (!NlMsgPutTailU32(&nlBuf, OVS_BAND_ATTR_TYPE,
                         OVS_METER_BAND_TYPE_DROP)) {
        nlError = NL_ERROR_NOMSG;
        goto Done;

    }
    NlMsgEndNested(&nlBuf, bandAttrOffset);
    NlMsgEndNested(&nlBuf, bandsOffset);

    NlMsgSetSize(nlMsgOutHdr, NlBufSize(&nlBuf));
    NlMsgAlignSize(nlMsgOutHdr);
    *replyLen += NlMsgSize(nlMsgOutHdr);

Done:
    if (nlError != NL_ERROR_SUCCESS) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
                usrParamsCtx->outputBuffer;

        ASSERT(msgError);
        NlBuildErrorMsg(msgIn, msgError, nlError, replyLen);
        ASSERT(*replyLen != 0);
    }

    return STATUS_SUCCESS;
}

BOOLEAN
buildOvsMeterReplyMsg(NL_BUFFER *nlBuf, DpMeter *dpMeter)
{
    BOOLEAN ok = FALSE;
    UINT32 bandAttrOffset;
    UINT32 bandsOffset;

    /* Add meter element. */
    ok = NlMsgPutTailU32(nlBuf, OVS_METER_ATTR_ID, dpMeter->id);
    if (!ok) {
        OVS_LOG_ERROR("Could not add meter id %d.", dpMeter->id);
        return ok;
    }

    ok = NlMsgPutTailUnspec(nlBuf, OVS_METER_ATTR_STATS,
                            (PCHAR)&(dpMeter->stats),
                            sizeof(dpMeter->stats));
    if (!ok) {
        OVS_LOG_ERROR("Could not add ovs meter stats.");
        return ok;
    }

    bandsOffset = NlMsgStartNested(nlBuf, OVS_METER_ATTR_BANDS);
    for (int index = 0; index < dpMeter->nBands; index++) {
        bandAttrOffset = NlMsgStartNested(nlBuf, OVS_BAND_ATTR_UNSPEC);
        ok = NlMsgPutTailUnspec(nlBuf, OVS_BAND_ATTR_STATS,
                                (PCHAR)&(dpMeter->bands[index].stats),
                                sizeof(dpMeter->bands[index].stats));
        NlMsgEndNested(nlBuf, bandAttrOffset);
        if (!ok) {
            break;
        }
    }

    NlMsgEndNested(nlBuf, bandsOffset);
    return ok;
}

NDIS_STATUS
OvsMeterGet(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
            UINT32 *replyLen)
{
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    PNL_MSG_HDR nlMsgHdr = &(msgIn->nlMsg);
    POVS_HDR ovsHdr = &(msgIn->ovsHdr);
    PNL_MSG_HDR nlMsgOutHdr = NULL;
    PNL_ATTR meterAttrs[ARRAY_SIZE(nlMeterPolicy)];
    UINT32 meterId = 0;
    DpMeter *dpMeter = NULL;
    BOOLEAN ok = FALSE;
    PGENL_MSG_HDR genlMsgHdr = &(msgIn->genlMsg);
    NL_BUFFER nlBuf;
    NL_ERROR nlError = NL_ERROR_SUCCESS;
    LOCK_STATE_EX lockState;

    if (!NlAttrParse((PNL_MSG_HDR)msgIn,
                     NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN,
                     NlMsgAttrsLen((PNL_MSG_HDR)msgIn),
                     nlMeterPolicy, ARRAY_SIZE(nlMeterPolicy),
                     meterAttrs, ARRAY_SIZE(meterAttrs))) {
        nlError = NL_ERROR_NOMSG;
        goto Done;
    }

    NlBufInit(&nlBuf, usrParamsCtx->outputBuffer, usrParamsCtx->outputLength);
    meterId = NlAttrGetU32(meterAttrs[OVS_METER_ATTR_ID]);

    /* Reply message header */
    nlMsgOutHdr = (PNL_MSG_HDR)(NlBufAt(&nlBuf, 0, 0));
    ok = NlFillOvsMsg(&nlBuf, nlMsgHdr->nlmsgType, 0,
                      nlMsgHdr->nlmsgSeq, nlMsgHdr->nlmsgPid,
                      genlMsgHdr->cmd, OVS_METER_CMD_GET,
                      ovsHdr->dp_ifindex);
    if (!ok) {
        nlError = NL_ERROR_NOMSG;
        goto Done;
    }

    NdisAcquireRWLockRead(meterGlobalTableLock, &lockState, 0);
    dpMeter = OvsMeterLookup(meterId);
    if (!dpMeter) {
        OVS_LOG_WARN("Has not find %d associated meter", meterId);
        nlError = NL_ERROR_EXIST;
        NdisReleaseRWLock(meterGlobalTableLock, &lockState);
        goto Done;
    }

    if (!buildOvsMeterReplyMsg(&nlBuf, dpMeter)) {
        nlError = NL_ERROR_NOMEM;
        OVS_LOG_ERROR("Could not build ovs meter reply msg.");
        NdisReleaseRWLock(meterGlobalTableLock, &lockState);
        goto Done;
    }

    NdisReleaseRWLock(meterGlobalTableLock, &lockState);
    NlMsgSetSize(nlMsgOutHdr, NlBufSize(&nlBuf));
    NlMsgAlignSize(nlMsgOutHdr);
    *replyLen += NlMsgSize(nlMsgOutHdr);

Done:
    if (nlError != NL_ERROR_SUCCESS) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
                usrParamsCtx->outputBuffer;

        ASSERT(msgError);
        NlBuildErrorMsg(msgIn, msgError, nlError, replyLen);
        ASSERT(*replyLen != 0);
    }

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
OvsMeterDestroy(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                UINT32 *replyLen)
{
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    PNL_MSG_HDR nlMsgHdr = &(msgIn->nlMsg);
    POVS_HDR ovsHdr = &(msgIn->ovsHdr);
    PNL_MSG_HDR nlMsgOutHdr = NULL;
    PNL_ATTR meterAttrs[ARRAY_SIZE(nlMeterPolicy)];
    PGENL_MSG_HDR genlMsgHdr = &(msgIn->genlMsg);
    LOCK_STATE_EX lockState;
    UINT32 meterId = 0;
    BOOLEAN ok;
    NL_BUFFER nlBuf;
    NL_ERROR nlError = NL_ERROR_SUCCESS;

    if (!NlAttrParse((PNL_MSG_HDR)msgIn,
                     NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN,
                     NlMsgAttrsLen((PNL_MSG_HDR)msgIn),
                     nlMeterPolicy, ARRAY_SIZE(nlMeterPolicy),
            meterAttrs, ARRAY_SIZE(meterAttrs))) {
        return STATUS_INVALID_PARAMETER;
    }

    NlBufInit(&nlBuf, usrParamsCtx->outputBuffer, usrParamsCtx->outputLength);

    meterId = NlAttrGetU32(meterAttrs[OVS_METER_ATTR_ID]);
    nlMsgOutHdr = (PNL_MSG_HDR)(NlBufAt(&nlBuf, 0, 0));
    ok = NlFillOvsMsg(&nlBuf, nlMsgHdr->nlmsgType, 0,
                      nlMsgHdr->nlmsgSeq, nlMsgHdr->nlmsgPid,
                      genlMsgHdr->cmd, OVS_METER_CMD_DEL,
                      ovsHdr->dp_ifindex);
    if (!ok) {
        nlError = NL_ERROR_NOMEM;
        goto Done;
    }

    NdisAcquireRWLockWrite(meterGlobalTableLock, &lockState, 0);
    PLIST_ENTRY head = &meterGlobalTable[meterId & (METER_HASH_BUCKET_MAX - 1)];
    PLIST_ENTRY link, next;
    DpMeter *entry = NULL;

    LIST_FORALL_SAFE(head, link, next) {
        entry = CONTAINING_RECORD(link, DpMeter, link);
        if (entry->id == meterId) {
            if (!buildOvsMeterReplyMsg(&nlBuf, entry)) {
                nlError = NL_ERROR_NOMEM;
                NdisReleaseRWLock(meterGlobalTableLock, &lockState);
                goto Done;
            }
            RemoveEntryList(&entry->link);
            OvsFreeMemoryWithTag(entry, OVS_METER_TAG);
            break;
        }
    }

    NdisReleaseRWLock(meterGlobalTableLock, &lockState);
    NlMsgSetSize(nlMsgOutHdr, NlBufSize(&nlBuf));
    NlMsgAlignSize(nlMsgOutHdr);
    *replyLen += NlMsgSize(nlMsgOutHdr);

Done:
    if (nlError != NL_ERROR_SUCCESS) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
                usrParamsCtx->outputBuffer;

        ASSERT(msgError);
        NlBuildErrorMsg(msgIn, msgError, nlError, replyLen);
        ASSERT(*replyLen != 0);
    }

    return NDIS_STATUS_SUCCESS;
}



DpMeter*
OvsMeterLookup(UINT32 meterId)
{
    PLIST_ENTRY head = &meterGlobalTable[meterId & (METER_HASH_BUCKET_MAX - 1)];
    PLIST_ENTRY link, next;
    DpMeter *entry = NULL;

    LIST_FORALL_SAFE(head, link, next) {
        entry = CONTAINING_RECORD(link, DpMeter, link);
        if (entry->id == meterId) {
            return entry;
        }
    }

    return NULL;
}

BOOLEAN
OvsMeterExecute(OvsForwardingContext *fwdCtx, UINT32 meterId)
{
    DpMeter *dpMeter;
    DpMeterBand *band;
    UINT32 longDeltaMs;
    UINT32 deltaMs;
    UINT64 currentTime;
    LOCK_STATE_EX lockState;
    UINT32 cost;
    UINT32 bandExceededRate = 0;
    INT32 bandExceedIndex = -1;
    UINT64 maxBucketSize = 0;

    NdisAcquireRWLockRead(meterGlobalTableLock, &lockState, 0);
    dpMeter = OvsMeterLookup(meterId);
    if (!dpMeter) {
        OVS_LOG_ERROR("Not found meter id %d associated meter.", meterId);
        NdisReleaseRWLock(meterGlobalTableLock, &lockState);
        return FALSE;
    }

    NdisGetCurrentSystemTime((LARGE_INTEGER *)&currentTime);
    /* currentTime represent count of 100-nanosecond intervals, to convert it to
     * ms, we need to divide 10000. */
    longDeltaMs = (UINT32)((currentTime - dpMeter->used) / 10000);
    deltaMs = longDeltaMs > dpMeter->maxDelta ? dpMeter->maxDelta :
                longDeltaMs;
    dpMeter->used = currentTime;
    dpMeter->stats.n_packets += 1;
    dpMeter->stats.n_bytes += OvsPacketLenNBL(fwdCtx->curNbl);
    cost = dpMeter->kbps ? OvsPacketLenNBL(fwdCtx->curNbl) * 8 : 1000;
    for (int index = 0; index < dpMeter->nBands; index++) {
        band = &(dpMeter->bands[index]);
        maxBucketSize = (band->burst_size + band->rate) * 1000LL;
        band->bucket += deltaMs * band->rate;
        if (band->bucket > maxBucketSize) {
            band->bucket = maxBucketSize;
        }

        if (band->bucket >= cost) {
            band->bucket -= cost;
            band->stats.n_packets += 1;
            band->stats.n_bytes += OvsPacketLenNBL(fwdCtx->curNbl);
        } else if (band->rate > bandExceededRate) {
            bandExceededRate = band->rate;
            bandExceedIndex = index;
        }
    }

    if (bandExceedIndex >= 0) {
        band = &(dpMeter->bands[bandExceedIndex]);
        band->stats.n_packets += 1;
        band->stats.n_bytes += OvsPacketLenNBL(fwdCtx->curNbl);
        if (band->type == OVS_METER_BAND_TYPE_DROP) {
            NdisReleaseRWLock(meterGlobalTableLock, &lockState);
            return TRUE;
        }
    }

    NdisReleaseRWLock(meterGlobalTableLock, &lockState);
    return FALSE;
}
