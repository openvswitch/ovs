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
#include "NetProto.h"
#include "Util.h"
#include "Jhash.h"
#include "Flow.h"
#include "PacketParser.h"
#include "Datapath.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_FLOW
#include "Debug.h"

#pragma warning( push )
#pragma warning( disable:4127 )

extern POVS_SWITCH_CONTEXT gOvsSwitchContext;
extern UINT64 ovsTimeIncrementPerTick;

static NTSTATUS ReportFlowInfo(OvsFlow *flow, UINT32 getFlags,
                               OvsFlowInfo *info);
static NTSTATUS HandleFlowPut(OvsFlowPut *put,
                                  OVS_DATAPATH *datapath,
                                  struct OvsFlowStats *stats);
static NTSTATUS OvsPrepareFlow(OvsFlow **flow, const OvsFlowPut *put,
                               UINT64 hash);
static VOID RemoveFlow(OVS_DATAPATH *datapath, OvsFlow **flow);
static VOID DeleteAllFlows(OVS_DATAPATH *datapath);
static NTSTATUS AddFlow(OVS_DATAPATH *datapath, OvsFlow *flow);
static VOID FreeFlow(OvsFlow *flow);
static VOID __inline *GetStartAddrNBL(const NET_BUFFER_LIST *_pNB);
static NTSTATUS _MapNlToFlowPut(POVS_MESSAGE msgIn, PNL_ATTR keyAttr,
                                PNL_ATTR actionAttr,
                                PNL_ATTR flowAttrClear,
                                OvsFlowPut *mappedFlow);
static VOID _MapKeyAttrToFlowPut(PNL_ATTR *keyAttrs,
                                 PNL_ATTR *tunnelAttrs,
                                 OvsFlowKey *destKey);

static VOID _MapTunAttrToFlowPut(PNL_ATTR *keyAttrs,
                                 PNL_ATTR *tunnelAttrs,
                                 OvsFlowKey *destKey);
static VOID _MapNlToFlowPutFlags(PGENL_MSG_HDR genlMsgHdr,
                                 PNL_ATTR flowAttrClear,
                                 OvsFlowPut *mappedFlow);

static NTSTATUS _FlowNlGetCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                     UINT32 *replyLen);
static NTSTATUS _FlowNlDumpCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                                      UINT32 *replyLen);
static NTSTATUS _MapFlowInfoToNl(PNL_BUFFER nlBuf,
                                 OvsFlowInfo *flowInfo);
static NTSTATUS _MapFlowStatsToNlStats(PNL_BUFFER nlBuf,
                                       OvsFlowStats *flowStats);
static NTSTATUS _MapFlowActionToNlAction(PNL_BUFFER nlBuf,
                                         uint32_t actionsLen,
                                         PNL_ATTR actions);

static NTSTATUS _MapFlowIpv4KeyToNlKey(PNL_BUFFER nlBuf,
                                       IpKey *ipv4FlowPutKey);
static NTSTATUS _MapFlowIpv6KeyToNlKey(PNL_BUFFER nlBuf,
                                       Ipv6Key *ipv6FlowPutKey,
                                       Icmp6Key *ipv6FlowPutIcmpKey);
static NTSTATUS _MapFlowArpKeyToNlKey(PNL_BUFFER nlBuf,
                                      ArpKey *arpFlowPutKey);

static NTSTATUS OvsDoDumpFlows(OvsFlowDumpInput *dumpInput,
                               OvsFlowDumpOutput *dumpOutput,
                               UINT32 *replyLen);


#define OVS_FLOW_TABLE_SIZE 2048
#define OVS_FLOW_TABLE_MASK (OVS_FLOW_TABLE_SIZE -1)
#define HASH_BUCKET(hash) ((hash) & OVS_FLOW_TABLE_MASK)

/* Flow family related netlink policies */

/* For Parsing attributes in FLOW_* commands */
const NL_POLICY nlFlowPolicy[] = {
    [OVS_FLOW_ATTR_KEY] = {.type = NL_A_NESTED, .optional = FALSE},
    [OVS_FLOW_ATTR_MASK] = {.type = NL_A_NESTED, .optional = TRUE},
    [OVS_FLOW_ATTR_ACTIONS] = {.type = NL_A_NESTED, .optional = TRUE},
    [OVS_FLOW_ATTR_STATS] = {.type = NL_A_UNSPEC,
                             .minLen = sizeof(struct ovs_flow_stats),
                             .maxLen = sizeof(struct ovs_flow_stats),
                             .optional = TRUE},
    [OVS_FLOW_ATTR_TCP_FLAGS] = {NL_A_U8, .optional = TRUE},
    [OVS_FLOW_ATTR_USED] = {NL_A_U64, .optional = TRUE}
};

/* For Parsing nested OVS_FLOW_ATTR_KEY attributes.
 * Some of the attributes like OVS_KEY_ATTR_RECIRC_ID
 * & OVS_KEY_ATTR_MPLS are not supported yet. */

const NL_POLICY nlFlowKeyPolicy[] = {
    [OVS_KEY_ATTR_ENCAP] = {.type = NL_A_VAR_LEN, .optional = TRUE},
    [OVS_KEY_ATTR_PRIORITY] = {.type = NL_A_UNSPEC, .minLen = 4,
                               .maxLen = 4, .optional = TRUE},
    [OVS_KEY_ATTR_IN_PORT] = {.type = NL_A_UNSPEC, .minLen = 4,
                              .maxLen = 4, .optional = FALSE},
    [OVS_KEY_ATTR_ETHERNET] = {.type = NL_A_UNSPEC,
                               .minLen = sizeof(struct ovs_key_ethernet),
                               .maxLen = sizeof(struct ovs_key_ethernet),
                               .optional = TRUE},
    [OVS_KEY_ATTR_VLAN] = {.type = NL_A_UNSPEC, .minLen = 2,
                           .maxLen = 2, .optional = TRUE},
    [OVS_KEY_ATTR_ETHERTYPE] = {.type = NL_A_UNSPEC, .minLen = 2,
                                .maxLen = 2, .optional = TRUE},
    [OVS_KEY_ATTR_IPV4] = {.type = NL_A_UNSPEC,
                           .minLen = sizeof(struct ovs_key_ipv4),
                           .maxLen = sizeof(struct ovs_key_ipv4),
                           .optional = TRUE},
    [OVS_KEY_ATTR_IPV6] = {.type = NL_A_UNSPEC,
                           .minLen = sizeof(struct ovs_key_ipv6),
                           .maxLen = sizeof(struct ovs_key_ipv6),
                           .optional = TRUE},
    [OVS_KEY_ATTR_TCP] = {.type = NL_A_UNSPEC,
                          .minLen = sizeof(struct ovs_key_tcp),
                          .maxLen = sizeof(struct ovs_key_tcp),
                          .optional = TRUE},
    [OVS_KEY_ATTR_UDP] = {.type = NL_A_UNSPEC,
                          .minLen = sizeof(struct ovs_key_udp),
                          .maxLen = sizeof(struct ovs_key_udp),
                          .optional = TRUE},
    [OVS_KEY_ATTR_ICMP] = {.type = NL_A_UNSPEC,
                           .minLen = sizeof(struct ovs_key_icmp),
                           .maxLen = sizeof(struct ovs_key_icmp),
                           .optional = TRUE},
    [OVS_KEY_ATTR_ICMPV6] = {.type = NL_A_UNSPEC,
                             .minLen = sizeof(struct ovs_key_icmpv6),
                             .maxLen = sizeof(struct ovs_key_icmpv6),
                             .optional = TRUE},
    [OVS_KEY_ATTR_ARP] = {.type = NL_A_UNSPEC,
                          .minLen = sizeof(struct ovs_key_arp),
                          .maxLen = sizeof(struct ovs_key_arp),
                          .optional = TRUE},
    [OVS_KEY_ATTR_ND] = {.type = NL_A_UNSPEC,
                         .minLen = sizeof(struct ovs_key_nd),
                         .maxLen = sizeof(struct ovs_key_nd),
                         .optional = TRUE},
    [OVS_KEY_ATTR_SKB_MARK] = {.type = NL_A_UNSPEC, .minLen = 4,
                               .maxLen = 4, .optional = TRUE},
    [OVS_KEY_ATTR_TUNNEL] = {.type = NL_A_VAR_LEN, .optional = TRUE},
    [OVS_KEY_ATTR_SCTP] = {.type = NL_A_UNSPEC,
                           .minLen = sizeof(struct ovs_key_sctp),
                           .maxLen = sizeof(struct ovs_key_sctp),
                           .optional = TRUE},
    [OVS_KEY_ATTR_TCP_FLAGS] = {.type = NL_A_UNSPEC,
                                .minLen = 2, .maxLen = 2,
                                .optional = TRUE},
    [OVS_KEY_ATTR_DP_HASH] = {.type = NL_A_UNSPEC, .minLen = 4,
                              .maxLen = 4, .optional = TRUE},
    [OVS_KEY_ATTR_RECIRC_ID] = {.type = NL_A_UNSPEC, .minLen = 4,
                                .maxLen = 4, .optional = TRUE},
    [OVS_KEY_ATTR_MPLS] = {.type = NL_A_VAR_LEN, .optional = TRUE}
};

/* For Parsing nested OVS_KEY_ATTR_TUNNEL attributes */
const NL_POLICY nlFlowTunnelKeyPolicy[] = {
    [OVS_TUNNEL_KEY_ATTR_ID] = {.type = NL_A_UNSPEC, .minLen = 8,
                                .maxLen = 8, .optional = TRUE},
    [OVS_TUNNEL_KEY_ATTR_IPV4_SRC] = {.type = NL_A_UNSPEC, .minLen = 4,
                                      .maxLen = 4, .optional = TRUE},
    [OVS_TUNNEL_KEY_ATTR_IPV4_DST] = {.type = NL_A_UNSPEC, .minLen = 4 ,
                                      .maxLen = 4, .optional = FALSE},
    [OVS_TUNNEL_KEY_ATTR_TOS] = {.type = NL_A_UNSPEC, .minLen = 1,
                                 .maxLen = 1, .optional = TRUE},
    [OVS_TUNNEL_KEY_ATTR_TTL] = {.type = NL_A_UNSPEC, .minLen = 1,
                                 .maxLen = 1, .optional = TRUE},
    [OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT] = {.type = NL_A_UNSPEC, .minLen = 0,
                                           .maxLen = 0, .optional = TRUE},
    [OVS_TUNNEL_KEY_ATTR_CSUM] = {.type = NL_A_UNSPEC, .minLen = 0,
                                  .maxLen = 0, .optional = TRUE},
    [OVS_TUNNEL_KEY_ATTR_OAM] = {.type = NL_A_UNSPEC, .minLen = 0,
                                 .maxLen = 0, .optional = TRUE},
    [OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS] = {.type = NL_A_VAR_LEN,
                                         .optional = TRUE}
};

/* For Parsing nested OVS_FLOW_ATTR_ACTIONS attributes */
const NL_POLICY nlFlowActionPolicy[] = {
    [OVS_ACTION_ATTR_OUTPUT] = {.type = NL_A_UNSPEC, .minLen = sizeof(UINT32),
                                .maxLen = sizeof(UINT32), .optional = TRUE},
    [OVS_ACTION_ATTR_USERSPACE] = {.type = NL_A_VAR_LEN, .optional = TRUE},
    [OVS_ACTION_ATTR_PUSH_VLAN] = {.type = NL_A_UNSPEC,
                                   .minLen =
                                   sizeof(struct ovs_action_push_vlan),
                                   .maxLen =
                                   sizeof(struct ovs_action_push_vlan),
                                   .optional = TRUE},
    [OVS_ACTION_ATTR_POP_VLAN] = {.type = NL_A_UNSPEC, .optional = TRUE},
    [OVS_ACTION_ATTR_PUSH_MPLS] = {.type = NL_A_UNSPEC,
                                   .minLen =
                                   sizeof(struct ovs_action_push_mpls),
                                   .maxLen =
                                   sizeof(struct ovs_action_push_mpls),
                                   .optional = TRUE},
    [OVS_ACTION_ATTR_POP_MPLS] = {.type = NL_A_UNSPEC,
                                  .minLen = sizeof(UINT16),
                                  .maxLen = sizeof(UINT16),
                                  .optional = TRUE},
    [OVS_ACTION_ATTR_RECIRC] = {.type = NL_A_UNSPEC,
                                .minLen = sizeof(UINT32),
                                .maxLen = sizeof(UINT32),
                                .optional = TRUE},
    [OVS_ACTION_ATTR_HASH] = {.type = NL_A_UNSPEC,
                              .minLen = sizeof(struct ovs_action_hash),
                              .maxLen = sizeof(struct ovs_action_hash),
                              .optional = TRUE},
    [OVS_ACTION_ATTR_SET] = {.type = NL_A_VAR_LEN, .optional = TRUE},
    [OVS_ACTION_ATTR_SAMPLE] = {.type = NL_A_VAR_LEN, .optional = TRUE}
};

/*
 *----------------------------------------------------------------------------
 * Netlink interface for flow commands.
 *----------------------------------------------------------------------------
 */

/*
 *----------------------------------------------------------------------------
 *  OvsFlowNewCmdHandler --
 *    Handler for OVS_FLOW_CMD_NEW/SET/DEL command.
 *    It also handles FLUSH case (DEL w/o any key in input)
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsFlowNlCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                    UINT32 *replyLen)
{
    NTSTATUS rc = STATUS_SUCCESS;
    BOOLEAN ok;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    POVS_MESSAGE msgOut = (POVS_MESSAGE)usrParamsCtx->outputBuffer;
    PNL_MSG_HDR nlMsgHdr = &(msgIn->nlMsg);
    PGENL_MSG_HDR genlMsgHdr = &(msgIn->genlMsg);
    POVS_HDR ovsHdr = &(msgIn->ovsHdr);
    PNL_ATTR nlAttrs[__OVS_FLOW_ATTR_MAX];
    UINT32 attrOffset = NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN;
    OvsFlowPut mappedFlow;
    OvsFlowStats stats;
    struct ovs_flow_stats replyStats;
    NL_ERROR nlError = NL_ERROR_SUCCESS;
    NL_BUFFER nlBuf;

    RtlZeroMemory(&mappedFlow, sizeof(OvsFlowPut));
    RtlZeroMemory(&stats, sizeof(stats));
    RtlZeroMemory(&replyStats, sizeof(replyStats));

    if (!(usrParamsCtx->outputBuffer)) {
        /* No output buffer */
        rc = STATUS_INVALID_BUFFER_SIZE;
        goto done;
    }

    /* Get all the top level Flow attributes */
    if ((NlAttrParse(nlMsgHdr, attrOffset, NlMsgAttrsLen(nlMsgHdr),
                     nlFlowPolicy, nlAttrs, ARRAY_SIZE(nlAttrs)))
                     != TRUE) {
        OVS_LOG_ERROR("Attr Parsing failed for msg: %p",
                       nlMsgHdr);
        rc = STATUS_INVALID_PARAMETER;
        goto done;
    }

    /* FLOW_DEL command w/o any key input is a flush case. */
    if ((genlMsgHdr->cmd == OVS_FLOW_CMD_DEL) &&
        (!(nlAttrs[OVS_FLOW_ATTR_KEY]))) {

        rc = OvsFlushFlowIoctl(ovsHdr->dp_ifindex);

       if (rc == STATUS_SUCCESS) {
            /* XXX: refactor this code. */
            /* So far so good. Prepare the reply for userspace */
            NlBufInit(&nlBuf, usrParamsCtx->outputBuffer,
                      usrParamsCtx->outputLength);

            /* Prepare nl Msg headers */
            ok = NlFillOvsMsg(&nlBuf, nlMsgHdr->nlmsgType, 0,
                              nlMsgHdr->nlmsgSeq, nlMsgHdr->nlmsgPid,
                              genlMsgHdr->cmd, OVS_FLOW_VERSION,
                              ovsHdr->dp_ifindex);
            if (ok) {
                *replyLen = msgOut->nlMsg.nlmsgLen;
            } else {
                rc = STATUS_INVALID_BUFFER_SIZE;
            }
       }

       goto done;
    }

    if ((rc = _MapNlToFlowPut(msgIn, nlAttrs[OVS_FLOW_ATTR_KEY],
         nlAttrs[OVS_FLOW_ATTR_ACTIONS], nlAttrs[OVS_FLOW_ATTR_CLEAR],
         &mappedFlow))
        != STATUS_SUCCESS) {
        OVS_LOG_ERROR("Conversion to OvsFlowPut failed");
        goto done;
    }

    rc = OvsPutFlowIoctl(&mappedFlow, sizeof (struct OvsFlowPut),
                         &stats);
    if (rc != STATUS_SUCCESS) {
        OVS_LOG_ERROR("OvsPutFlowIoctl failed.");
        goto done;
    }

    replyStats.n_packets = stats.packetCount;
    replyStats.n_bytes = stats.byteCount;

    /* So far so good. Prepare the reply for userspace */
    NlBufInit(&nlBuf, usrParamsCtx->outputBuffer,
              usrParamsCtx->outputLength);

    /* Prepare nl Msg headers */
    ok = NlFillOvsMsg(&nlBuf, nlMsgHdr->nlmsgType, 0,
                      nlMsgHdr->nlmsgSeq, nlMsgHdr->nlmsgPid,
                      genlMsgHdr->cmd, OVS_FLOW_VERSION,
                      ovsHdr->dp_ifindex);
    if (!ok) {
        rc = STATUS_INVALID_BUFFER_SIZE;
        goto done;
    } else {
        rc = STATUS_SUCCESS;
    }

    /* Append OVS_FLOW_ATTR_STATS attribute */
    if (!NlMsgPutTailUnspec(&nlBuf, OVS_FLOW_ATTR_STATS,
        (PCHAR)(&replyStats), sizeof(replyStats))) {
        OVS_LOG_ERROR("Adding OVS_FLOW_ATTR_STATS attribute failed.");
        rc = STATUS_INVALID_BUFFER_SIZE;
        goto done;
    }

    msgOut->nlMsg.nlmsgLen = NLMSG_ALIGN(NlBufSize(&nlBuf));
    *replyLen = msgOut->nlMsg.nlmsgLen;

done:

    if (nlError != NL_ERROR_SUCCESS) {
        POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
                                       usrParamsCtx->outputBuffer;
        NlBuildErrorMsg(msgIn, msgError, nlError);
        *replyLen = msgError->nlMsg.nlmsgLen;
        rc = STATUS_SUCCESS;
    }

    return rc;
}

/*
 *----------------------------------------------------------------------------
 *  OvsFlowNlGetCmdHandler --
 *    Handler for OVS_FLOW_CMD_GET/DUMP commands.
 *----------------------------------------------------------------------------
 */
NTSTATUS
OvsFlowNlGetCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                       UINT32 *replyLen)
{
    NTSTATUS status = STATUS_SUCCESS;
    NL_ERROR nlError = NL_ERROR_SUCCESS;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;

    if (usrParamsCtx->devOp == OVS_TRANSACTION_DEV_OP) {
        status = _FlowNlGetCmdHandler(usrParamsCtx, replyLen);

        /* No trasanctional errors as of now.
         * If we have something then we need to convert rc to
         * nlError. */
        if ((nlError != NL_ERROR_SUCCESS) &&
            (usrParamsCtx->outputBuffer)) {
            POVS_MESSAGE_ERROR msgError = (POVS_MESSAGE_ERROR)
                                           usrParamsCtx->outputBuffer;
            NlBuildErrorMsg(msgIn, msgError, nlError);
            *replyLen = msgError->nlMsg.nlmsgLen;
            status = STATUS_SUCCESS;
            goto done;
        }
    } else {
        status = _FlowNlDumpCmdHandler(usrParamsCtx, replyLen);
    }

done:
    return status;
}

/*
 *----------------------------------------------------------------------------
 *  _FlowNlGetCmdHandler --
 *    Handler for OVS_FLOW_CMD_GET command.
 *----------------------------------------------------------------------------
 */
NTSTATUS
_FlowNlGetCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                     UINT32 *replyLen)
{
    NTSTATUS rc = STATUS_SUCCESS;
    POVS_MESSAGE msgIn = (POVS_MESSAGE)usrParamsCtx->inputBuffer;
    PNL_MSG_HDR nlMsgHdr = &(msgIn->nlMsg);
    POVS_HDR ovsHdr = &(msgIn->ovsHdr);
    PNL_MSG_HDR nlMsgOutHdr = NULL;
    UINT32 attrOffset = NLMSG_HDRLEN + GENL_HDRLEN + OVS_HDRLEN;
    PNL_ATTR nlAttrs[__OVS_FLOW_ATTR_MAX];

    OvsFlowGetInput getInput;
    OvsFlowGetOutput getOutput;
    NL_BUFFER nlBuf;
    PNL_ATTR keyAttrs[__OVS_KEY_ATTR_MAX];
    PNL_ATTR tunnelAttrs[__OVS_TUNNEL_KEY_ATTR_MAX];

    NlBufInit(&nlBuf, usrParamsCtx->outputBuffer,
              usrParamsCtx->outputLength);
    RtlZeroMemory(&getInput, sizeof(OvsFlowGetInput));
    RtlZeroMemory(&getOutput, sizeof(OvsFlowGetOutput));
    UINT32 keyAttrOffset = 0;
    UINT32 tunnelKeyAttrOffset = 0;
    BOOLEAN ok;

    if (usrParamsCtx->inputLength > usrParamsCtx->outputLength) {
        /* Should not be the case.
         * We'll be copying the flow keys back from
         * input buffer to output buffer. */
        rc = STATUS_INVALID_PARAMETER;
        OVS_LOG_ERROR("inputLength: %d GREATER THEN outputLength: %d",
                      usrParamsCtx->inputLength, usrParamsCtx->outputLength);
        goto done;
    }

    /* Get all the top level Flow attributes */
    if ((NlAttrParse(nlMsgHdr, attrOffset, NlMsgAttrsLen(nlMsgHdr),
                     nlFlowPolicy, nlAttrs, ARRAY_SIZE(nlAttrs)))
                     != TRUE) {
        OVS_LOG_ERROR("Attr Parsing failed for msg: %p",
                       nlMsgHdr);
        rc = STATUS_INVALID_PARAMETER;
        goto done;
    }

    keyAttrOffset = (UINT32)((PCHAR) nlAttrs[OVS_FLOW_ATTR_KEY] -
                    (PCHAR)nlMsgHdr);

    /* Get flow keys attributes */
    if ((NlAttrParseNested(nlMsgHdr, keyAttrOffset,
                           NlAttrLen(nlAttrs[OVS_FLOW_ATTR_KEY]),
                           nlFlowKeyPolicy, keyAttrs, ARRAY_SIZE(keyAttrs)))
                           != TRUE) {
        OVS_LOG_ERROR("Key Attr Parsing failed for msg: %p",
                       nlMsgHdr);
        rc = STATUS_INVALID_PARAMETER;
        goto done;
    }

    if (keyAttrs[OVS_KEY_ATTR_TUNNEL]) {
        tunnelKeyAttrOffset = (UINT32)((PCHAR)
                              (keyAttrs[OVS_KEY_ATTR_TUNNEL])
                              - (PCHAR)nlMsgHdr);

        /* Get tunnel keys attributes */
        if ((NlAttrParseNested(nlMsgHdr, tunnelKeyAttrOffset,
                               NlAttrLen(keyAttrs[OVS_KEY_ATTR_TUNNEL]),
                               nlFlowTunnelKeyPolicy,
                               tunnelAttrs, ARRAY_SIZE(tunnelAttrs)))
                               != TRUE) {
            OVS_LOG_ERROR("Tunnel key Attr Parsing failed for msg: %p",
                           nlMsgHdr);
            rc = STATUS_INVALID_PARAMETER;
            goto done;
        }
    }

    _MapKeyAttrToFlowPut(keyAttrs, tunnelAttrs,
                         &(getInput.key));

    getInput.dpNo = ovsHdr->dp_ifindex;
    getInput.getFlags = FLOW_GET_STATS | FLOW_GET_ACTIONS;

    /* 4th argument is a no op.
     * We are keeping this argument to be compatible
     * with our dpif-windows based interface. */
    rc = OvsGetFlowIoctl(&getInput, &getOutput);
    if (rc != STATUS_SUCCESS) {
        OVS_LOG_ERROR("OvsGetFlowIoctl failed.");
        goto done;
    }

    /* Lets prepare the reply. */
    nlMsgOutHdr = (PNL_MSG_HDR)(NlBufAt(&nlBuf, 0, 0));

    /* Input already has all the attributes for the flow key.
     * Lets copy the values back. */
    ok = NlMsgPutTail(&nlBuf, (PCHAR)(usrParamsCtx->inputBuffer),
                      usrParamsCtx->inputLength);
    if (!ok) {
        OVS_LOG_ERROR("Could not copy the data to the buffer tail");
        goto done;
    }

    rc = _MapFlowStatsToNlStats(&nlBuf, &((getOutput.info).stats));
    if (rc != STATUS_SUCCESS) {
        OVS_LOG_ERROR("_OvsFlowMapFlowKeyToNlStats failed.");
        goto done;
    }

    rc = _MapFlowActionToNlAction(&nlBuf, ((getOutput.info).actionsLen),
                                  getOutput.info.actions);
    if (rc != STATUS_SUCCESS) {
        OVS_LOG_ERROR("_MapFlowActionToNlAction failed.");
        goto done;
    }

    NlMsgSetSize(nlMsgOutHdr, NlBufSize(&nlBuf));
    NlMsgAlignSize(nlMsgOutHdr);
    *replyLen += NlMsgSize(nlMsgOutHdr);

done:
    return rc;
}

/*
 *----------------------------------------------------------------------------
 *  _FlowNlDumpCmdHandler --
 *    Handler for OVS_FLOW_CMD_DUMP command.
 *----------------------------------------------------------------------------
 */
NTSTATUS
_FlowNlDumpCmdHandler(POVS_USER_PARAMS_CONTEXT usrParamsCtx,
                      UINT32 *replyLen)
{
    NTSTATUS rc = STATUS_SUCCESS;
    UINT32  temp = 0;   /* To keep compiler happy for calling OvsDoDumpFlows */

    POVS_OPEN_INSTANCE instance = (POVS_OPEN_INSTANCE)
                                  (usrParamsCtx->ovsInstance);

    if (usrParamsCtx->devOp == OVS_WRITE_DEV_OP) {
        /* Dump Start */
        OvsSetupDumpStart(usrParamsCtx);
        goto done;
    }

    POVS_MESSAGE msgIn = instance->dumpState.ovsMsg;
    PNL_MSG_HDR nlMsgHdr = &(msgIn->nlMsg);
    PGENL_MSG_HDR genlMsgHdr = &(msgIn->genlMsg);
    POVS_HDR ovsHdr = &(msgIn->ovsHdr);
    PNL_MSG_HDR nlMsgOutHdr = NULL;
    UINT32 hdrOffset = 0;

    /* Get Next */
    OvsFlowDumpOutput dumpOutput;
    OvsFlowDumpInput dumpInput;
    NL_BUFFER nlBuf;

    NlBufInit(&nlBuf, usrParamsCtx->outputBuffer,
              usrParamsCtx->outputLength);

    ASSERT(usrParamsCtx->devOp == OVS_READ_DEV_OP);
    ASSERT(usrParamsCtx->outputLength);

    RtlZeroMemory(&dumpInput, sizeof(OvsFlowDumpInput));
    RtlZeroMemory(&dumpOutput, sizeof(OvsFlowDumpOutput));

    dumpInput.dpNo = ovsHdr->dp_ifindex;
    dumpInput.getFlags = FLOW_GET_KEY | FLOW_GET_STATS | FLOW_GET_ACTIONS;

    /* Lets provide as many flows to userspace as possible. */
    do {
        dumpInput.position[0] = instance->dumpState.index[0];
        dumpInput.position[1] = instance->dumpState.index[1];

        rc = OvsDoDumpFlows(&dumpInput, &dumpOutput, &temp);
        if (rc != STATUS_SUCCESS) {
            OVS_LOG_ERROR("OvsDoDumpFlows failed with rc: %d", rc);
            break;
        }

        /* Done with Dump, send NLMSG_DONE */
        if (!(dumpOutput.n)) {
            BOOLEAN ok;

            OVS_LOG_INFO("Dump Done");

            nlMsgOutHdr = (PNL_MSG_HDR)(NlBufAt(&nlBuf, NlBufSize(&nlBuf), 0));
            ok = NlFillNlHdr(&nlBuf, NLMSG_DONE, NLM_F_MULTI,
                             nlMsgHdr->nlmsgSeq, nlMsgHdr->nlmsgPid);

            if (!ok) {
                rc = STATUS_INVALID_BUFFER_SIZE;
                OVS_LOG_ERROR("Unable to prepare DUMP_DONE reply.");
                break;
            } else {
                rc = STATUS_SUCCESS;
            }

            NlMsgAlignSize(nlMsgOutHdr);
            *replyLen += NlMsgSize(nlMsgOutHdr);

            FreeUserDumpState(instance);
            break;
        } else {
            BOOLEAN ok;

            hdrOffset = NlBufSize(&nlBuf);
            nlMsgOutHdr = (PNL_MSG_HDR)(NlBufAt(&nlBuf, hdrOffset, 0));

            /* Netlink header */
            ok = NlFillOvsMsg(&nlBuf, nlMsgHdr->nlmsgType, NLM_F_MULTI,
                              nlMsgHdr->nlmsgSeq, nlMsgHdr->nlmsgPid,
                              genlMsgHdr->cmd, genlMsgHdr->version,
                              ovsHdr->dp_ifindex);

            if (!ok) {
                /* Reset rc to success so that we can
                 * send already added messages to user space. */
                rc = STATUS_SUCCESS;
                break;
            }

            /* Time to add attributes */
            rc = _MapFlowInfoToNl(&nlBuf, &(dumpOutput.flow));
            if (rc != STATUS_SUCCESS) {
                /* Adding the attribute failed, we are out of
                   space in the buffer, remove the appended OVS header */
                NlMsgSetSize(nlMsgOutHdr,
                             NlMsgSize(nlMsgOutHdr) -
                             sizeof(struct _OVS_MESSAGE));

                /* Reset rc to success so that we can
                 * send already added messages to user space. */
                rc = STATUS_SUCCESS;
                break;
            }

            NlMsgSetSize(nlMsgOutHdr, NlBufSize(&nlBuf) - hdrOffset);
            NlMsgAlignSize(nlMsgOutHdr);
            *replyLen += NlMsgSize(nlMsgOutHdr);
            instance->dumpState.index[0] = dumpOutput.position[0];
            instance->dumpState.index[1] = dumpOutput.position[1];
        }
    } while(TRUE);

done:
    return rc;
}

/*
 *----------------------------------------------------------------------------
 *  _MapFlowInfoToNl --
 *    Maps OvsFlowInfo to Netlink attributes.
 *----------------------------------------------------------------------------
 */
static NTSTATUS
_MapFlowInfoToNl(PNL_BUFFER nlBuf, OvsFlowInfo *flowInfo)
{
    NTSTATUS rc = STATUS_SUCCESS;

    rc = MapFlowKeyToNlKey(nlBuf, &(flowInfo->key), OVS_FLOW_ATTR_KEY,
                           OVS_KEY_ATTR_TUNNEL);
    if (rc != STATUS_SUCCESS) {
        goto done;
    }

    rc = _MapFlowStatsToNlStats(nlBuf, &(flowInfo->stats));
    if (rc != STATUS_SUCCESS) {
        goto done;
    }

    rc = _MapFlowActionToNlAction(nlBuf, flowInfo->actionsLen,
                                  flowInfo->actions);
    if (rc != STATUS_SUCCESS) {
        goto done;
    }

done:
    return rc;
}

/*
 *----------------------------------------------------------------------------
 *  _MapFlowStatsToNlStats --
 *    Maps OvsFlowStats to OVS_FLOW_ATTR_STATS attribute.
 *----------------------------------------------------------------------------
 */
static NTSTATUS
_MapFlowStatsToNlStats(PNL_BUFFER nlBuf, OvsFlowStats *flowStats)
{
    NTSTATUS rc = STATUS_SUCCESS;
    struct ovs_flow_stats replyStats;

    replyStats.n_packets = flowStats->packetCount;
    replyStats.n_bytes = flowStats->byteCount;

    if (!NlMsgPutTailU64(nlBuf, OVS_FLOW_ATTR_USED, flowStats->used)) {
        rc = STATUS_INVALID_BUFFER_SIZE;
        goto done;
    }

    if (!NlMsgPutTailUnspec(nlBuf, OVS_FLOW_ATTR_STATS,
                           (PCHAR)(&replyStats),
                           sizeof(struct ovs_flow_stats))) {
        rc = STATUS_INVALID_BUFFER_SIZE;
        goto done;
    }

    if (!NlMsgPutTailU8(nlBuf, OVS_FLOW_ATTR_TCP_FLAGS, flowStats->tcpFlags)) {
        rc = STATUS_INVALID_BUFFER_SIZE;
        goto done;
    }

done:
    return rc;
}

/*
 *----------------------------------------------------------------------------
 *  _MapFlowActionToNlAction --
 *    Maps flow actions to OVS_FLOW_ATTR_ACTION attribute.
 *----------------------------------------------------------------------------
 */
static NTSTATUS
_MapFlowActionToNlAction(PNL_BUFFER nlBuf, uint32_t actionsLen,
                         PNL_ATTR actions)
{
    NTSTATUS rc = STATUS_SUCCESS;
    UINT32 offset = 0;

    offset = NlMsgStartNested(nlBuf, OVS_FLOW_ATTR_ACTIONS);
    if (!offset) {
        /* Starting the nested attribute failed. */
        rc = STATUS_INVALID_BUFFER_SIZE;
        goto error_nested_start;
    }

    if (!NlBufCopyAtTail(nlBuf, (PCHAR)actions, actionsLen)) {
        /* Adding a nested attribute failed. */
        rc = STATUS_INVALID_BUFFER_SIZE;
        goto done;
    }

done:
    NlMsgEndNested(nlBuf, offset);
error_nested_start:
    return rc;

}

/*
 *----------------------------------------------------------------------------
 *  MapFlowKeyToNlKey --
 *   Maps OvsFlowKey to OVS_FLOW_ATTR_KEY attribute.
 *----------------------------------------------------------------------------
 */
NTSTATUS
MapFlowKeyToNlKey(PNL_BUFFER nlBuf,
                  OvsFlowKey *flowKey,
                  UINT16 keyType,
                  UINT16 tunKeyType)
{
    NTSTATUS rc = STATUS_SUCCESS;
    struct ovs_key_ethernet ethKey;
    UINT32 offset = 0;

    offset = NlMsgStartNested(nlBuf, keyType);
    if (!offset) {
        /* Starting the nested attribute failed. */
        rc = STATUS_UNSUCCESSFUL;
        goto error_nested_start;
    }

    /* Ethernet header */
    RtlCopyMemory(&(ethKey.eth_src), flowKey->l2.dlSrc, ETH_ADDR_LEN);
    RtlCopyMemory(&(ethKey.eth_dst), flowKey->l2.dlDst, ETH_ADDR_LEN);

    if (!NlMsgPutTailUnspec(nlBuf, OVS_KEY_ATTR_ETHERNET,
                           (PCHAR)(&ethKey),
                           sizeof(struct ovs_key_ethernet))) {
        rc = STATUS_UNSUCCESSFUL;
        goto done;
    }

    if (!NlMsgPutTailU32(nlBuf, OVS_KEY_ATTR_IN_PORT,
                         flowKey->l2.inPort)) {
        rc = STATUS_UNSUCCESSFUL;
        goto done;
    }

    if (!NlMsgPutTailU16(nlBuf, OVS_KEY_ATTR_ETHERTYPE,
                         flowKey->l2.dlType)) {
        rc = STATUS_UNSUCCESSFUL;
        goto done;
    }

    if (flowKey->l2.vlanTci) {
        if (!NlMsgPutTailU16(nlBuf, OVS_KEY_ATTR_VLAN,
                             flowKey->l2.vlanTci)) {
            rc = STATUS_UNSUCCESSFUL;
            goto done;
        }
    }

    /* ==== L3 + L4 ==== */
    switch (ntohs(flowKey->l2.dlType)) {
        case ETH_TYPE_IPV4: {
        IpKey *ipv4FlowPutKey = &(flowKey->ipKey);
        rc = _MapFlowIpv4KeyToNlKey(nlBuf, ipv4FlowPutKey);
        break;
        }

        case ETH_TYPE_IPV6: {
        Ipv6Key *ipv6FlowPutKey = &(flowKey->ipv6Key);
        Icmp6Key *icmpv6FlowPutKey = &(flowKey->icmp6Key);
        rc = _MapFlowIpv6KeyToNlKey(nlBuf, ipv6FlowPutKey,
                                    icmpv6FlowPutKey);
        break;
        }

        case ETH_TYPE_ARP:
        case ETH_TYPE_RARP: {
        ArpKey *arpFlowPutKey = &(flowKey->arpKey);
        rc = _MapFlowArpKeyToNlKey(nlBuf, arpFlowPutKey);
        break;
        }

        default:
        break;
    }

    if (rc != STATUS_SUCCESS) {
        goto done;
    }

    if (flowKey->tunKey.dst) {
        rc = MapFlowTunKeyToNlKey(nlBuf, &(flowKey->tunKey),
                                  tunKeyType);
        if (rc != STATUS_SUCCESS) {
            goto done;
        }
    }

done:
    NlMsgEndNested(nlBuf, offset);
error_nested_start:
    return rc;
}

/*
 *----------------------------------------------------------------------------
 *  MapFlowTunKeyToNlKey --
 *   Maps OvsIPv4TunnelKey to OVS_TUNNEL_KEY_ATTR_ID attribute.
 *----------------------------------------------------------------------------
 */
NTSTATUS
MapFlowTunKeyToNlKey(PNL_BUFFER nlBuf,
                     OvsIPv4TunnelKey *tunKey,
                     UINT16 tunKeyType)
{
    NTSTATUS rc = STATUS_SUCCESS;
    UINT32 offset = 0;

    offset = NlMsgStartNested(nlBuf, tunKeyType);
    if (!offset) {
        /* Starting the nested attribute failed. */
        rc = STATUS_UNSUCCESSFUL;
        goto error_nested_start;
    }

    if (!NlMsgPutTailU64(nlBuf, OVS_TUNNEL_KEY_ATTR_ID,
                         tunKey->tunnelId)) {
        rc = STATUS_UNSUCCESSFUL;
        goto done;
    }

    if (!NlMsgPutTailU32(nlBuf, OVS_TUNNEL_KEY_ATTR_IPV4_DST,
                         tunKey->dst)) {
        rc = STATUS_UNSUCCESSFUL;
        goto done;
    }

    if (!NlMsgPutTailU32(nlBuf, OVS_TUNNEL_KEY_ATTR_IPV4_SRC,
                         tunKey->src)) {
        rc = STATUS_UNSUCCESSFUL;
        goto done;
    }

    if (!NlMsgPutTailU8(nlBuf, OVS_TUNNEL_KEY_ATTR_TOS,
                        tunKey->tos)) {
        rc = STATUS_UNSUCCESSFUL;
        goto done;
    }

    if (!NlMsgPutTailU8(nlBuf, OVS_TUNNEL_KEY_ATTR_TTL,
                         tunKey->ttl)) {
        rc = STATUS_UNSUCCESSFUL;
        goto done;
    }

done:
    NlMsgEndNested(nlBuf, offset);
error_nested_start:
    return rc;
}

/*
 *----------------------------------------------------------------------------
 *  _MapFlowTunKeyToNlKey --
 *    Maps OvsIPv4FlowPutKey to OVS_KEY_ATTR_IPV4 attribute.
 *----------------------------------------------------------------------------
 */
static NTSTATUS
_MapFlowIpv4KeyToNlKey(PNL_BUFFER nlBuf, IpKey *ipv4FlowPutKey)
{
    NTSTATUS rc = STATUS_SUCCESS;
    struct ovs_key_ipv4 ipv4Key;

    ipv4Key.ipv4_src = ipv4FlowPutKey->nwSrc;
    ipv4Key.ipv4_dst = ipv4FlowPutKey->nwDst;
    ipv4Key.ipv4_proto = ipv4FlowPutKey->nwProto;
    ipv4Key.ipv4_tos = ipv4FlowPutKey->nwTos;
    ipv4Key.ipv4_ttl = ipv4FlowPutKey->nwTtl;
    ipv4Key.ipv4_frag = ipv4FlowPutKey->nwFrag;

    if (!NlMsgPutTailUnspec(nlBuf, OVS_KEY_ATTR_IPV4,
                           (PCHAR)(&ipv4Key),
                           sizeof(struct ovs_key_ipv4))) {
        rc = STATUS_UNSUCCESSFUL;
        goto done;
    }

    switch (ipv4Key.ipv4_proto) {
        case IPPROTO_TCP: {
            struct ovs_key_tcp tcpKey;
            tcpKey.tcp_src = ipv4FlowPutKey->l4.tpSrc;
            tcpKey.tcp_dst = ipv4FlowPutKey->l4.tpDst;
            if (!NlMsgPutTailUnspec(nlBuf, OVS_KEY_ATTR_TCP,
                                   (PCHAR)(&tcpKey),
                                   sizeof(tcpKey))) {
                rc = STATUS_UNSUCCESSFUL;
                goto done;
            }
            break;
        }

        case IPPROTO_UDP: {
            struct ovs_key_udp udpKey;
            udpKey.udp_src = ipv4FlowPutKey->l4.tpSrc;
            udpKey.udp_dst = ipv4FlowPutKey->l4.tpDst;
            if (!NlMsgPutTailUnspec(nlBuf, OVS_KEY_ATTR_UDP,
                                   (PCHAR)(&udpKey),
                                   sizeof(udpKey))) {
                rc = STATUS_UNSUCCESSFUL;
                goto done;
            }
            break;
        }

        case IPPROTO_SCTP: {
            struct ovs_key_sctp sctpKey;
            sctpKey.sctp_src = ipv4FlowPutKey->l4.tpSrc;
            sctpKey.sctp_dst = ipv4FlowPutKey->l4.tpDst;
            if (!NlMsgPutTailUnspec(nlBuf, OVS_KEY_ATTR_SCTP,
                                   (PCHAR)(&sctpKey),
                                   sizeof(sctpKey))) {
                rc = STATUS_UNSUCCESSFUL;
                goto done;
            }
            break;
        }

        case IPPROTO_ICMP: {
            struct ovs_key_icmp icmpKey;
            /* XXX: revisit to see if htons is needed */
            icmpKey.icmp_type = (__u8)(ipv4FlowPutKey->l4.tpSrc);
            icmpKey.icmp_code = (__u8)(ipv4FlowPutKey->l4.tpDst);

            if (!NlMsgPutTailUnspec(nlBuf, OVS_KEY_ATTR_ICMP,
                                   (PCHAR)(&icmpKey),
                                   sizeof(icmpKey))) {
                rc = STATUS_UNSUCCESSFUL;
                goto done;
            }
            break;
        }

        default:
            break;
    }

done:
    return rc;
}

/*
 *----------------------------------------------------------------------------
 *  _MapFlowIpv6KeyToNlKey --
 *    Maps _MapFlowIpv6KeyToNlKey to OVS_KEY_ATTR_IPV6 attribute.
 *----------------------------------------------------------------------------
 */
static NTSTATUS
_MapFlowIpv6KeyToNlKey(PNL_BUFFER nlBuf, Ipv6Key *ipv6FlowPutKey,
                       Icmp6Key *icmpv6FlowPutKey)
{
    NTSTATUS rc = STATUS_SUCCESS;
    struct ovs_key_ipv6 ipv6Key;

    RtlCopyMemory(&(ipv6Key.ipv6_src), &ipv6FlowPutKey->ipv6Src,
                  sizeof ipv6Key.ipv6_src);
    RtlCopyMemory(&(ipv6Key.ipv6_dst), &ipv6FlowPutKey->ipv6Dst,
                  sizeof ipv6Key.ipv6_dst);

    ipv6Key.ipv6_label = ipv6FlowPutKey->ipv6Label;
    ipv6Key.ipv6_proto = ipv6FlowPutKey->nwProto;
    ipv6Key.ipv6_tclass = ipv6FlowPutKey->nwTos;
    ipv6Key.ipv6_hlimit = ipv6FlowPutKey->nwTtl;
    ipv6Key.ipv6_frag = ipv6FlowPutKey->nwFrag;

    if (!NlMsgPutTailUnspec(nlBuf, OVS_KEY_ATTR_IPV6,
                           (PCHAR)(&ipv6Key),
                           sizeof(ipv6Key))) {
        rc = STATUS_UNSUCCESSFUL;
        goto done;
    }

    switch (ipv6Key.ipv6_proto) {
        case IPPROTO_TCP: {
            struct ovs_key_tcp tcpKey;
            tcpKey.tcp_src = ipv6FlowPutKey->l4.tpSrc;
            tcpKey.tcp_dst = ipv6FlowPutKey->l4.tpDst;
            if (!NlMsgPutTailUnspec(nlBuf, OVS_KEY_ATTR_TCP,
                                   (PCHAR)(&tcpKey),
                                   sizeof(tcpKey))) {
                rc = STATUS_UNSUCCESSFUL;
                goto done;
            }
            break;
        }

        case IPPROTO_UDP: {
            struct ovs_key_udp udpKey;
            udpKey.udp_src = ipv6FlowPutKey->l4.tpSrc;
            udpKey.udp_dst = ipv6FlowPutKey->l4.tpDst;
            if (!NlMsgPutTailUnspec(nlBuf, OVS_KEY_ATTR_UDP,
                                   (PCHAR)(&udpKey),
                                   sizeof(udpKey))) {
                rc = STATUS_UNSUCCESSFUL;
                goto done;
            }
            break;
        }

        case IPPROTO_SCTP: {
            struct ovs_key_sctp sctpKey;
            sctpKey.sctp_src = ipv6FlowPutKey->l4.tpSrc;
            sctpKey.sctp_dst = ipv6FlowPutKey->l4.tpDst;
            if (!NlMsgPutTailUnspec(nlBuf, OVS_KEY_ATTR_SCTP,
                                   (PCHAR)(&sctpKey),
                                   sizeof(sctpKey))) {
                rc = STATUS_UNSUCCESSFUL;
                goto done;
            }
            break;
        }

        case IPPROTO_ICMPV6: {
            struct ovs_key_icmpv6 icmpV6Key;
            struct ovs_key_nd ndKey;

            /* XXX: revisit to see if htons is needed */
            icmpV6Key.icmpv6_type = (__u8)(icmpv6FlowPutKey->l4.tpSrc);
            icmpV6Key.icmpv6_code = (__u8)(icmpv6FlowPutKey->l4.tpDst);

            if (!NlMsgPutTailUnspec(nlBuf, OVS_KEY_ATTR_ICMPV6,
                                   (PCHAR)(&icmpV6Key),
                                   sizeof(icmpV6Key))) {
                rc = STATUS_UNSUCCESSFUL;
                goto done;
            }

            RtlCopyMemory(&(ndKey.nd_target), &icmpv6FlowPutKey->ndTarget,
                          sizeof(icmpv6FlowPutKey->ndTarget));
            RtlCopyMemory(&(ndKey.nd_sll), &icmpv6FlowPutKey->arpSha,
                          ETH_ADDR_LEN);
            RtlCopyMemory(&(ndKey.nd_tll), &icmpv6FlowPutKey->arpTha,
                          ETH_ADDR_LEN);
            if (!NlMsgPutTailUnspec(nlBuf, OVS_KEY_ATTR_ND,
                                   (PCHAR)(&ndKey),
                                   sizeof(ndKey))) {
                rc = STATUS_UNSUCCESSFUL;
                goto done;
            }

            break;
        }

        default:
            break;
    }

done:
    return rc;
}

/*
 *----------------------------------------------------------------------------
 *  _MapFlowArpKeyToNlKey --
 *    Maps _MapFlowArpKeyToNlKey to OVS_KEY_ATTR_ARP attribute.
 *----------------------------------------------------------------------------
 */
static NTSTATUS
_MapFlowArpKeyToNlKey(PNL_BUFFER nlBuf, ArpKey *arpFlowPutKey)
{
    NTSTATUS rc = STATUS_SUCCESS;
    struct ovs_key_arp arpKey;

    arpKey.arp_sip = arpFlowPutKey->nwSrc;
    arpKey.arp_tip = arpFlowPutKey->nwDst;

    RtlCopyMemory(&(arpKey.arp_sha), arpFlowPutKey->arpSha, ETH_ADDR_LEN);
    RtlCopyMemory(&(arpKey.arp_tha), arpFlowPutKey->arpTha, ETH_ADDR_LEN);

    /*
     * Flow_Extract() stores 'nwProto' in host order for ARP since 'nwProto' is
     * 1 byte field and the ARP opcode is 2 bytes, and all of the kernel code
     * understand this while looking at an ARP key.
     * While we pass up the ARP key to userspace, convert from host order to
     * network order. Likewise, when processing an ARP key from userspace,
     * convert from network order to host order.
     *
     * It is important to note that the flow table stores the ARP opcode field
     * in host order.
     */
    arpKey.arp_op = htons(arpFlowPutKey->nwProto);

    if (!NlMsgPutTailUnspec(nlBuf, OVS_KEY_ATTR_ARP,
                           (PCHAR)(&arpKey),
                           sizeof(arpKey))) {
        rc = STATUS_UNSUCCESSFUL;
        goto done;
    }

done:
    return rc;
}

/*
 *----------------------------------------------------------------------------
 *  _MapNlToFlowPut --
 *    Maps input netlink message to OvsFlowPut.
 *----------------------------------------------------------------------------
 */
static NTSTATUS
_MapNlToFlowPut(POVS_MESSAGE msgIn, PNL_ATTR keyAttr,
                PNL_ATTR actionAttr, PNL_ATTR flowAttrClear,
                OvsFlowPut *mappedFlow)
{
    NTSTATUS rc = STATUS_SUCCESS;
    PNL_MSG_HDR nlMsgHdr = &(msgIn->nlMsg);
    PGENL_MSG_HDR genlMsgHdr = &(msgIn->genlMsg);
    POVS_HDR ovsHdr = &(msgIn->ovsHdr);

    UINT32 keyAttrOffset = (UINT32)((PCHAR)keyAttr - (PCHAR)nlMsgHdr);
    UINT32 tunnelKeyAttrOffset;

    PNL_ATTR keyAttrs[__OVS_KEY_ATTR_MAX] = {NULL};
    PNL_ATTR tunnelAttrs[__OVS_TUNNEL_KEY_ATTR_MAX] = {NULL};

    /* Get flow keys attributes */
    if ((NlAttrParseNested(nlMsgHdr, keyAttrOffset, NlAttrLen(keyAttr),
                           nlFlowKeyPolicy, keyAttrs, ARRAY_SIZE(keyAttrs)))
                           != TRUE) {
        OVS_LOG_ERROR("Key Attr Parsing failed for msg: %p",
                       nlMsgHdr);
        rc = STATUS_INVALID_PARAMETER;
        goto done;
    }

    if (keyAttrs[OVS_KEY_ATTR_TUNNEL]) {
        tunnelKeyAttrOffset = (UINT32)((PCHAR)
                              (keyAttrs[OVS_KEY_ATTR_TUNNEL])
                              - (PCHAR)nlMsgHdr);

        /* Get tunnel keys attributes */
        if ((NlAttrParseNested(nlMsgHdr, tunnelKeyAttrOffset,
                               NlAttrLen(keyAttrs[OVS_KEY_ATTR_TUNNEL]),
                               nlFlowTunnelKeyPolicy,
                               tunnelAttrs, ARRAY_SIZE(tunnelAttrs)))
                               != TRUE) {
            OVS_LOG_ERROR("Tunnel key Attr Parsing failed for msg: %p",
                           nlMsgHdr);
            rc = STATUS_INVALID_PARAMETER;
            goto done;
        }
    }

    _MapKeyAttrToFlowPut(keyAttrs, tunnelAttrs,
                         &(mappedFlow->key));

    /* Map the action */
    if (actionAttr) {
        mappedFlow->actionsLen = NlAttrGetSize(actionAttr);
        mappedFlow->actions = NlAttrGet(actionAttr);
    }

    mappedFlow->dpNo = ovsHdr->dp_ifindex;

    _MapNlToFlowPutFlags(genlMsgHdr, flowAttrClear,
                                mappedFlow);

done:
    return rc;
}

/*
 *----------------------------------------------------------------------------
 *  _MapNlToFlowPutFlags --
 *    Maps netlink message to OvsFlowPut->flags.
 *----------------------------------------------------------------------------
 */
static VOID
_MapNlToFlowPutFlags(PGENL_MSG_HDR genlMsgHdr,
                     PNL_ATTR flowAttrClear, OvsFlowPut *mappedFlow)
{
    uint32_t flags = 0;

    switch (genlMsgHdr->cmd) {
    case OVS_FLOW_CMD_NEW:
         flags |= OVSWIN_FLOW_PUT_CREATE;
         break;
    case OVS_FLOW_CMD_DEL:
         flags |= OVSWIN_FLOW_PUT_DELETE;
         break;
    case OVS_FLOW_CMD_SET:
         flags |= OVSWIN_FLOW_PUT_MODIFY;
         break;
    default:
         ASSERT(0);
    }

    if (flowAttrClear) {
        flags |= OVSWIN_FLOW_PUT_CLEAR;
    }

    mappedFlow->flags = flags;
}

/*
 *----------------------------------------------------------------------------
 *  _MapKeyAttrToFlowPut --
 *    Converts FLOW_KEY attribute to OvsFlowPut->key.
 *----------------------------------------------------------------------------
 */
static VOID
_MapKeyAttrToFlowPut(PNL_ATTR *keyAttrs,
                     PNL_ATTR *tunnelAttrs,
                     OvsFlowKey *destKey)
{
    _MapTunAttrToFlowPut(keyAttrs, tunnelAttrs, destKey);

    /* ===== L2 headers ===== */
    destKey->l2.inPort = NlAttrGetU32(keyAttrs[OVS_KEY_ATTR_IN_PORT]);

    if (keyAttrs[OVS_KEY_ATTR_ETHERNET]) {
        const struct ovs_key_ethernet *eth_key;
        eth_key = NlAttrGet(keyAttrs[OVS_KEY_ATTR_ETHERNET]);
        RtlCopyMemory(destKey->l2.dlSrc, eth_key->eth_src, ETH_ADDR_LEN);
        RtlCopyMemory(destKey->l2.dlDst, eth_key->eth_dst, ETH_ADDR_LEN);
    }

    /* TODO: Ideally ETHERTYPE should not be optional.
     * But during vswitchd bootup we are seeing FLOW_ADD
     * requests with no ETHERTYPE attributes.
     * Need to verify this. */
    if (keyAttrs[OVS_KEY_ATTR_ETHERTYPE]) {
        destKey->l2.dlType = (NlAttrGetU16(keyAttrs
                                        [OVS_KEY_ATTR_ETHERTYPE]));
    }

    if (keyAttrs[OVS_KEY_ATTR_VLAN]) {
        destKey->l2.vlanTci = NlAttrGetU16(keyAttrs[OVS_KEY_ATTR_VLAN]);
    }

    /* ==== L3 + L4. ==== */
    destKey->l2.keyLen = OVS_WIN_TUNNEL_KEY_SIZE + OVS_L2_KEY_SIZE
                         - destKey->l2.offset;

    switch (ntohs(destKey->l2.dlType)) {
    case ETH_TYPE_IPV4: {

        if (keyAttrs[OVS_KEY_ATTR_IPV4]) {
            const struct ovs_key_ipv4 *ipv4Key;

            ipv4Key = NlAttrGet(keyAttrs[OVS_KEY_ATTR_IPV4]);
            IpKey *ipv4FlowPutKey = &(destKey->ipKey);
            ipv4FlowPutKey->nwSrc = ipv4Key->ipv4_src;
            ipv4FlowPutKey->nwDst = ipv4Key->ipv4_dst;
            ipv4FlowPutKey->nwProto = ipv4Key->ipv4_proto;
            ipv4FlowPutKey->nwTos = ipv4Key->ipv4_tos;
            ipv4FlowPutKey->nwTtl = ipv4Key->ipv4_ttl;
            ipv4FlowPutKey->nwFrag = ipv4Key->ipv4_frag;

            if (keyAttrs[OVS_KEY_ATTR_TCP]) {
                const struct ovs_key_tcp *tcpKey;
                tcpKey = NlAttrGet(keyAttrs[OVS_KEY_ATTR_TCP]);
                ipv4FlowPutKey->l4.tpSrc = tcpKey->tcp_src;
                ipv4FlowPutKey->l4.tpDst = tcpKey->tcp_dst;
            }

            if (keyAttrs[OVS_KEY_ATTR_UDP]) {
                const struct ovs_key_udp *udpKey;
                udpKey = NlAttrGet(keyAttrs[OVS_KEY_ATTR_UDP]);
                ipv4FlowPutKey->l4.tpSrc = udpKey->udp_src;
                ipv4FlowPutKey->l4.tpDst = udpKey->udp_dst;
            }

            if (keyAttrs[OVS_KEY_ATTR_SCTP]) {
                const struct ovs_key_sctp *sctpKey;
                sctpKey = NlAttrGet(keyAttrs[OVS_KEY_ATTR_SCTP]);
                ipv4FlowPutKey->l4.tpSrc = sctpKey->sctp_src;
                ipv4FlowPutKey->l4.tpDst = sctpKey->sctp_dst;
            }

            destKey->l2.keyLen += OVS_IP_KEY_SIZE;
        }
        break;
    }
    case ETH_TYPE_IPV6: {

        if (keyAttrs[OVS_KEY_ATTR_IPV6]) {
            const struct ovs_key_ipv6 *ipv6Key;

            ipv6Key = NlAttrGet(keyAttrs[OVS_KEY_ATTR_IPV6]);
            Ipv6Key *ipv6FlowPutKey = &(destKey->ipv6Key);

            RtlCopyMemory(&ipv6FlowPutKey->ipv6Src, ipv6Key->ipv6_src,
                          sizeof ipv6Key->ipv6_src);
            RtlCopyMemory(&ipv6FlowPutKey->ipv6Dst, ipv6Key->ipv6_dst,
                          sizeof ipv6Key->ipv6_dst);

            ipv6FlowPutKey->ipv6Label = ipv6Key->ipv6_label;
            ipv6FlowPutKey->nwProto  = ipv6Key->ipv6_proto;
            ipv6FlowPutKey->nwTos = ipv6Key->ipv6_tclass;
            ipv6FlowPutKey->nwTtl = ipv6Key->ipv6_hlimit;
            ipv6FlowPutKey->nwFrag = ipv6Key->ipv6_frag;

            if (keyAttrs[OVS_KEY_ATTR_TCP]) {
                const struct ovs_key_tcp *tcpKey;
                tcpKey = NlAttrGet(keyAttrs[OVS_KEY_ATTR_TCP]);
                ipv6FlowPutKey->l4.tpSrc = tcpKey->tcp_src;
                ipv6FlowPutKey->l4.tpDst = tcpKey->tcp_dst;
            }

            if (keyAttrs[OVS_KEY_ATTR_UDP]) {
                const struct ovs_key_udp *udpKey;
                udpKey = NlAttrGet(keyAttrs[OVS_KEY_ATTR_UDP]);
                ipv6FlowPutKey->l4.tpSrc = udpKey->udp_src;
                ipv6FlowPutKey->l4.tpDst = udpKey->udp_dst;
            }

            if (keyAttrs[OVS_KEY_ATTR_SCTP]) {
                const struct ovs_key_sctp *sctpKey;
                sctpKey = NlAttrGet(keyAttrs[OVS_KEY_ATTR_SCTP]);
                ipv6FlowPutKey->l4.tpSrc = sctpKey->sctp_src;
                ipv6FlowPutKey->l4.tpDst = sctpKey->sctp_dst;
            }

            if (keyAttrs[OVS_KEY_ATTR_ICMPV6]) {
                const struct ovs_key_icmpv6 *icmpv6Key;

                Icmp6Key *icmp6FlowPutKey= &(destKey->icmp6Key);

                icmpv6Key = NlAttrGet(keyAttrs[OVS_KEY_ATTR_ICMPV6]);

                icmp6FlowPutKey->l4.tpSrc = icmpv6Key->icmpv6_type;
                icmp6FlowPutKey->l4.tpDst = icmpv6Key->icmpv6_code;

                if (keyAttrs[OVS_KEY_ATTR_ND]) {
                    const struct ovs_key_nd *ndKey;

                    ndKey = NlAttrGet(keyAttrs[OVS_KEY_ATTR_ND]);
                    RtlCopyMemory(&icmp6FlowPutKey->ndTarget,
                                  ndKey->nd_target, sizeof (icmp6FlowPutKey->ndTarget));
                    RtlCopyMemory(icmp6FlowPutKey->arpSha,
                                  ndKey->nd_sll, ETH_ADDR_LEN);
                    RtlCopyMemory(icmp6FlowPutKey->arpTha,
                                  ndKey->nd_tll, ETH_ADDR_LEN);
                }

                destKey->l2.keyLen += OVS_ICMPV6_KEY_SIZE;

            } else {

                destKey->l2.keyLen += OVS_IPV6_KEY_SIZE;
            }

            ipv6FlowPutKey->pad = 0;
        }
        break;
    }
    case ETH_TYPE_ARP:
    case ETH_TYPE_RARP: {

        if (keyAttrs[OVS_KEY_ATTR_ARP]) {
            ArpKey *arpFlowPutKey = &destKey->arpKey;
            const struct ovs_key_arp *arpKey;

            arpKey = NlAttrGet(keyAttrs[OVS_KEY_ATTR_ARP]);

            arpFlowPutKey->nwSrc = arpKey->arp_sip;
            arpFlowPutKey->nwDst = arpKey->arp_tip;

            RtlCopyMemory(arpFlowPutKey->arpSha, arpKey->arp_sha, ETH_ADDR_LEN);
            RtlCopyMemory(arpFlowPutKey->arpTha, arpKey->arp_tha, ETH_ADDR_LEN);
            /* Kernel datapath assumes 'arpFlowPutKey->nwProto' to be in host
             * order. */
            arpFlowPutKey->nwProto = (UINT8)ntohs((arpKey->arp_op));
            arpFlowPutKey->pad[0] = 0;
            arpFlowPutKey->pad[1] = 0;
            arpFlowPutKey->pad[2] = 0;
            destKey->l2.keyLen += OVS_ARP_KEY_SIZE;
            break;
        }
    }
    }
}

/*
 *----------------------------------------------------------------------------
 *  _MapTunAttrToFlowPut --
 *    Converts FLOW_TUNNEL_KEY attribute to OvsFlowKey->tunKey.
 *----------------------------------------------------------------------------
 */
static VOID
_MapTunAttrToFlowPut(PNL_ATTR *keyAttrs,
                     PNL_ATTR *tunAttrs,
                     OvsFlowKey *destKey)
{
    if (keyAttrs[OVS_KEY_ATTR_TUNNEL]) {

        if (tunAttrs[OVS_TUNNEL_KEY_ATTR_ID]) {
            destKey->tunKey.tunnelId = NlAttrGetU64
                                       (tunAttrs[OVS_TUNNEL_KEY_ATTR_ID]);
            destKey->tunKey.flags |= OVS_TNL_F_KEY;
        }

        if (tunAttrs[OVS_TUNNEL_KEY_ATTR_IPV4_DST]) {
        destKey->tunKey.dst = NlAttrGetU32
                              (tunAttrs[OVS_TUNNEL_KEY_ATTR_IPV4_DST]);
        }

        if (tunAttrs[OVS_TUNNEL_KEY_ATTR_IPV4_SRC]) {
        destKey->tunKey.src = NlAttrGetU32
                              (tunAttrs[OVS_TUNNEL_KEY_ATTR_IPV4_SRC]);
        }

        if (tunAttrs[OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT]) {
            destKey->tunKey.flags |= OVS_TNL_F_DONT_FRAGMENT;
        }

        if (tunAttrs[OVS_TUNNEL_KEY_ATTR_CSUM]) {
            destKey->tunKey.flags |= OVS_TNL_F_CSUM;
        }

        if (tunAttrs[OVS_TUNNEL_KEY_ATTR_TOS]) {
        destKey->tunKey.tos = NlAttrGetU8
                              (tunAttrs[OVS_TUNNEL_KEY_ATTR_TOS]);
        }

        if (tunAttrs[OVS_TUNNEL_KEY_ATTR_TTL]) {
        destKey->tunKey.ttl = NlAttrGetU8
                              (tunAttrs[OVS_TUNNEL_KEY_ATTR_TTL]);
        }

        destKey->tunKey.pad = 0;
        destKey->l2.offset = 0;
    } else {
        destKey->tunKey.attr[0] = 0;
        destKey->tunKey.attr[1] = 0;
        destKey->tunKey.attr[2] = 0;
        destKey->l2.offset = sizeof destKey->tunKey;
    }
}

/*
 *----------------------------------------------------------------------------
 * OvsDeleteFlowTable --
 * Results:
 *    NDIS_STATUS_SUCCESS always.
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsDeleteFlowTable(OVS_DATAPATH *datapath)
{
    if (datapath == NULL || datapath->flowTable == NULL) {
        return NDIS_STATUS_SUCCESS;
    }

    DeleteAllFlows(datapath);
    OvsFreeMemoryWithTag(datapath->flowTable, OVS_FLOW_POOL_TAG);
    datapath->flowTable = NULL;
    NdisFreeRWLock(datapath->lock);

    return NDIS_STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsAllocateFlowTable --
 * Results:
 *    NDIS_STATUS_SUCCESS on success.
 *    NDIS_STATUS_RESOURCES if memory couldn't be allocated
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsAllocateFlowTable(OVS_DATAPATH *datapath,
                     POVS_SWITCH_CONTEXT switchContext)
{
    PLIST_ENTRY bucket;
    int i;

    datapath->flowTable = OvsAllocateMemoryWithTag(
        OVS_FLOW_TABLE_SIZE * sizeof(LIST_ENTRY), OVS_FLOW_POOL_TAG);
    if (!datapath->flowTable) {
        return NDIS_STATUS_RESOURCES;
    }
    for (i = 0; i < OVS_FLOW_TABLE_SIZE; i++) {
        bucket = &(datapath->flowTable[i]);
        InitializeListHead(bucket);
    }
    datapath->lock = NdisAllocateRWLock(switchContext->NdisFilterHandle);

    return NDIS_STATUS_SUCCESS;
}


/*
 *----------------------------------------------------------------------------
 *  GetStartAddrNBL --
 *    Get the virtual address of the frame.
 *
 *  Results:
 *    Virtual address of the frame.
 *----------------------------------------------------------------------------
 */
static __inline VOID *
GetStartAddrNBL(const NET_BUFFER_LIST *_pNB)
{
    PMDL curMdl;
    PUINT8 curBuffer;
    PEthHdr curHeader;

    ASSERT(_pNB);

    // Ethernet Header is a guaranteed safe access.
    curMdl = (NET_BUFFER_LIST_FIRST_NB(_pNB))->CurrentMdl;
    curBuffer =  MmGetSystemAddressForMdlSafe(curMdl, LowPagePriority);
    if (!curBuffer) {
        return NULL;
    }

    curHeader = (PEthHdr)
    (curBuffer + (NET_BUFFER_LIST_FIRST_NB(_pNB))->CurrentMdlOffset);

    return (VOID *) curHeader;
}

VOID
OvsFlowUsed(OvsFlow *flow,
            const NET_BUFFER_LIST *packet,
            const POVS_PACKET_HDR_INFO layers)
{
    LARGE_INTEGER tickCount;

    KeQueryTickCount(&tickCount);
    flow->used = tickCount.QuadPart * ovsTimeIncrementPerTick;
    flow->packetCount++;
    flow->byteCount += OvsPacketLenNBL(packet);
    flow->tcpFlags |= OvsGetTcpFlags(packet, &flow->key, layers);
}


VOID
DeleteAllFlows(OVS_DATAPATH *datapath)
{
    INT i;
    PLIST_ENTRY bucket;

    for (i = 0; i < OVS_FLOW_TABLE_SIZE; i++) {
        PLIST_ENTRY next;
        bucket = &(datapath->flowTable[i]);
        while (!IsListEmpty(bucket)) {
            OvsFlow *flow;
            next = bucket->Flink;
            flow = CONTAINING_RECORD(next, OvsFlow, ListEntry);
            RemoveFlow(datapath, &flow);
        }
    }
}

/*
 *----------------------------------------------------------------------------
 * Initializes 'flow' members from 'packet', 'skb_priority', 'tun_id', and
 * 'ofp_in_port'.
 *
 * Initializes 'packet' header pointers as follows:
 *
 *    - packet->l2 to the start of the Ethernet header.
 *
 *    - packet->l3 to just past the Ethernet header, or just past the
 *      vlan_header if one is present, to the first byte of the payload of the
 *      Ethernet frame.
 *
 *    - packet->l4 to just past the IPv4 header, if one is present and has a
 *      correct length, and otherwise NULL.
 *
 *    - packet->l7 to just past the TCP or UDP or ICMP header, if one is
 *      present and has a correct length, and otherwise NULL.
 *
 * Returns NDIS_STATUS_SUCCESS normally.  Fails only if packet data cannot be accessed
 * (e.g. if Pkt_CopyBytesOut() returns an error).
 *----------------------------------------------------------------------------
 */
NDIS_STATUS
OvsExtractFlow(const NET_BUFFER_LIST *packet,
               UINT32 inPort,
               OvsFlowKey *flow,
               POVS_PACKET_HDR_INFO layers,
               OvsIPv4TunnelKey *tunKey)
{
    struct Eth_Header *eth;
    UINT8 offset = 0;
    PVOID vlanTagValue;

    layers->value = 0;

    if (tunKey) {
        ASSERT(tunKey->dst != 0);
        RtlMoveMemory(&flow->tunKey, tunKey, sizeof flow->tunKey);
        flow->l2.offset = 0;
    } else {
        flow->tunKey.dst = 0;
        flow->l2.offset = OVS_WIN_TUNNEL_KEY_SIZE;
    }

    flow->l2.inPort = inPort;

    if ( OvsPacketLenNBL(packet) < ETH_HEADER_LEN_DIX) {
        flow->l2.keyLen = OVS_WIN_TUNNEL_KEY_SIZE + 8 - flow->l2.offset;
        return NDIS_STATUS_SUCCESS;
    }

    /* Link layer. */
    eth = (Eth_Header *)GetStartAddrNBL((NET_BUFFER_LIST *)packet);
    memcpy(flow->l2.dlSrc, eth->src, ETH_ADDR_LENGTH);
    memcpy(flow->l2.dlDst, eth->dst, ETH_ADDR_LENGTH);

    /*
     * vlan_tci.
     */
    vlanTagValue = NET_BUFFER_LIST_INFO(packet, Ieee8021QNetBufferListInfo);
    if (vlanTagValue) {
        PNDIS_NET_BUFFER_LIST_8021Q_INFO vlanTag =
            (PNDIS_NET_BUFFER_LIST_8021Q_INFO)(PVOID *)&vlanTagValue;
        flow->l2.vlanTci = htons(vlanTag->TagHeader.VlanId | OVSWIN_VLAN_CFI |
                                 (vlanTag->TagHeader.UserPriority << 13));
    } else {
        if (eth->dix.typeNBO == ETH_TYPE_802_1PQ_NBO) {
            Eth_802_1pq_Tag *tag= (Eth_802_1pq_Tag *)&eth->dix.typeNBO;
            flow->l2.vlanTci = ((UINT16)tag->priority << 13) |
                               OVSWIN_VLAN_CFI |
                               ((UINT16)tag->vidHi << 8)  | tag->vidLo;
            offset = sizeof (Eth_802_1pq_Tag);
        } else {
            flow->l2.vlanTci = 0;
        }
        /*
        * XXX
        * Please note after this point, src mac and dst mac should
        * not be accessed through eth
        */
        eth = (Eth_Header *)((UINT8 *)eth + offset);
    }

    /*
     * dl_type.
     *
     * XXX assume that at least the first
     * 12 bytes of received packets are mapped.  This code has the stronger
     * assumption that at least the first 22 bytes of 'packet' is mapped (if my
     * arithmetic is right).
     */
    if (ETH_TYPENOT8023(eth->dix.typeNBO)) {
        flow->l2.dlType = eth->dix.typeNBO;
        layers->l3Offset = ETH_HEADER_LEN_DIX + offset;
    } else if (OvsPacketLenNBL(packet)  >= ETH_HEADER_LEN_802_3 &&
              eth->e802_3.llc.dsap == 0xaa &&
              eth->e802_3.llc.ssap == 0xaa &&
              eth->e802_3.llc.control == ETH_LLC_CONTROL_UFRAME &&
              eth->e802_3.snap.snapOrg[0] == 0x00 &&
              eth->e802_3.snap.snapOrg[1] == 0x00 &&
              eth->e802_3.snap.snapOrg[2] == 0x00) {
        flow->l2.dlType = eth->e802_3.snap.snapType.typeNBO;
        layers->l3Offset = ETH_HEADER_LEN_802_3 + offset;
    } else {
        flow->l2.dlType = htons(OVSWIN_DL_TYPE_NONE);
        layers->l3Offset = ETH_HEADER_LEN_DIX + offset;
    }

    flow->l2.keyLen = OVS_WIN_TUNNEL_KEY_SIZE + OVS_L2_KEY_SIZE - flow->l2.offset;
    /* Network layer. */
    if (flow->l2.dlType == htons(ETH_TYPE_IPV4)) {
        struct IPHdr ip_storage;
        const struct IPHdr *nh;
        IpKey *ipKey = &flow->ipKey;

        flow->l2.keyLen += OVS_IP_KEY_SIZE;
        layers->isIPv4 = 1;
        nh = OvsGetIp(packet, layers->l3Offset, &ip_storage);
        if (nh) {
            layers->l4Offset = layers->l3Offset + nh->ihl * 4;

            ipKey->nwSrc = nh->saddr;
            ipKey->nwDst = nh->daddr;
            ipKey->nwProto = nh->protocol;

            ipKey->nwTos = nh->tos;
            if (nh->frag_off & htons(IP_MF | IP_OFFSET)) {
                ipKey->nwFrag = OVSWIN_NW_FRAG_ANY;
                if (nh->frag_off & htons(IP_OFFSET)) {
                    ipKey->nwFrag |= OVSWIN_NW_FRAG_LATER;
                }
            } else {
                ipKey->nwFrag = 0;
            }

            ipKey->nwTtl = nh->ttl;
            ipKey->l4.tpSrc = 0;
            ipKey->l4.tpDst = 0;

            if (!(nh->frag_off & htons(IP_OFFSET))) {
                if (ipKey->nwProto == SOCKET_IPPROTO_TCP) {
                    OvsParseTcp(packet, &ipKey->l4, layers);
                } else if (ipKey->nwProto == SOCKET_IPPROTO_UDP) {
                    OvsParseUdp(packet, &ipKey->l4, layers);
                } else if (ipKey->nwProto == SOCKET_IPPROTO_ICMP) {
                    ICMPHdr icmpStorage;
                    const ICMPHdr *icmp;

                    icmp = OvsGetIcmp(packet, layers->l4Offset, &icmpStorage);
                    if (icmp) {
                        ipKey->l4.tpSrc = htons(icmp->type);
                        ipKey->l4.tpDst = htons(icmp->code);
                        layers->l7Offset = layers->l4Offset + sizeof *icmp;
                    }
                }
            }
        } else {
            ((UINT64 *)ipKey)[0] = 0;
            ((UINT64 *)ipKey)[1] = 0;
        }
    } else if (flow->l2.dlType == htons(ETH_TYPE_IPV6)) {
        NDIS_STATUS status;
        flow->l2.keyLen += OVS_IPV6_KEY_SIZE;
        status = OvsParseIPv6(packet, flow, layers);
        if (status != NDIS_STATUS_SUCCESS) {
            memset(&flow->ipv6Key, 0, sizeof (Ipv6Key));
            return status;
        }
        layers->isIPv6 = 1;
        flow->ipv6Key.l4.tpSrc = 0;
        flow->ipv6Key.l4.tpDst = 0;
        flow->ipv6Key.pad = 0;

        if (flow->ipv6Key.nwProto == SOCKET_IPPROTO_TCP) {
            OvsParseTcp(packet, &(flow->ipv6Key.l4), layers);
        } else if (flow->ipv6Key.nwProto == SOCKET_IPPROTO_UDP) {
            OvsParseUdp(packet, &(flow->ipv6Key.l4), layers);
        } else if (flow->ipv6Key.nwProto == SOCKET_IPPROTO_ICMPV6) {
            OvsParseIcmpV6(packet, flow, layers);
            flow->l2.keyLen += (OVS_ICMPV6_KEY_SIZE - OVS_IPV6_KEY_SIZE);
        }
    } else if (flow->l2.dlType == htons(ETH_TYPE_ARP)) {
        EtherArp arpStorage;
        const EtherArp *arp;
        ArpKey *arpKey = &flow->arpKey;
        ((UINT64 *)arpKey)[0] = 0;
        ((UINT64 *)arpKey)[1] = 0;
        ((UINT64 *)arpKey)[2] = 0;
        flow->l2.keyLen += OVS_ARP_KEY_SIZE;
        arp = OvsGetArp(packet, layers->l3Offset, &arpStorage);
        if (arp && arp->ea_hdr.ar_hrd == htons(1) &&
            arp->ea_hdr.ar_pro == htons(ETH_TYPE_IPV4) &&
            arp->ea_hdr.ar_hln == ETH_ADDR_LENGTH &&
            arp->ea_hdr.ar_pln == 4) {
            /* We only match on the lower 8 bits of the opcode. */
            if (ntohs(arp->ea_hdr.ar_op) <= 0xff) {
                arpKey->nwProto = (UINT8)ntohs(arp->ea_hdr.ar_op);
            }
            if (arpKey->nwProto == ARPOP_REQUEST
                || arpKey->nwProto == ARPOP_REPLY) {
                memcpy(&arpKey->nwSrc, arp->arp_spa, 4);
                memcpy(&arpKey->nwDst, arp->arp_tpa, 4);
                memcpy(arpKey->arpSha, arp->arp_sha, ETH_ADDR_LENGTH);
                memcpy(arpKey->arpTha, arp->arp_tha, ETH_ADDR_LENGTH);
            }
        }
    }

    return NDIS_STATUS_SUCCESS;
}

__inline BOOLEAN
FlowEqual(UINT64 *src, UINT64 *dst, UINT32 size)
{
    UINT32 i;
    ASSERT((size & 0x7) == 0);
    ASSERT(((UINT64)src & 0x7) == 0);
    ASSERT(((UINT64)dst & 0x7) == 0);
    for (i = 0; i < (size >> 3); i++) {
        if (src[i] != dst[i]) {
            return FALSE;
        }
    }
    return TRUE;
}


/*
 * ----------------------------------------------------------------------------
 * AddFlow --
 *    Add a flow to flow table.
 *
 * Results:
 *   NDIS_STATUS_SUCCESS if no same flow in the flow table.
 * ----------------------------------------------------------------------------
 */
NTSTATUS
AddFlow(OVS_DATAPATH *datapath, OvsFlow *flow)
{
    PLIST_ENTRY head;

    if (OvsLookupFlow(datapath, &flow->key, &flow->hash, TRUE) != NULL) {
        return STATUS_INVALID_HANDLE;
    }

    head = &(datapath->flowTable[HASH_BUCKET(flow->hash)]);
    /*
     * We need fence here to make sure flow's nextPtr is updated before
     * head->nextPtr is updated.
     */
    KeMemoryBarrier();

    //KeAcquireSpinLock(&FilterDeviceExtension->NblQueueLock, &oldIrql);
    InsertTailList(head, &flow->ListEntry);
    //KeReleaseSpinLock(&FilterDeviceExtension->NblQueueLock, oldIrql);

    datapath->nFlows++;

    return STATUS_SUCCESS;
}


/* ----------------------------------------------------------------------------
 * RemoveFlow --
 *   Remove a flow from flow table, and added to wait list
 * ----------------------------------------------------------------------------
 */
VOID
RemoveFlow(OVS_DATAPATH *datapath,
           OvsFlow **flow)
{
    OvsFlow *f = *flow;
    *flow = NULL;

    ASSERT(datapath->nFlows);
    datapath->nFlows--;
    // Remove the flow  from queue
    RemoveEntryList(&f->ListEntry);
    FreeFlow(f);
}


/*
 * ----------------------------------------------------------------------------
 * OvsLookupFlow --
 *
 *    Find flow from flow table based on flow key.
 *    Caller should either hold portset handle or should
 *    have a flowRef in datapath or Acquired datapath.
 *
 * Results:
 *    Flow pointer if lookup successful.
 *    NULL if not exists.
 * ----------------------------------------------------------------------------
 */
OvsFlow *
OvsLookupFlow(OVS_DATAPATH *datapath,
              const OvsFlowKey *key,
              UINT64 *hash,
              BOOLEAN hashValid)
{
    PLIST_ENTRY link, head;
    UINT16 offset = key->l2.offset;
    UINT16 size = key->l2.keyLen;
    UINT8 *start;

    ASSERT(key->tunKey.dst || offset == sizeof (OvsIPv4TunnelKey));
    ASSERT(!key->tunKey.dst || offset == 0);

    start = (UINT8 *)key + offset;

    if (!hashValid) {
        *hash = OvsJhashBytes(start, size, 0);
    }

    head = &datapath->flowTable[HASH_BUCKET(*hash)];
    link  = head->Flink;
    while (link != head) {
        OvsFlow *flow = CONTAINING_RECORD(link, OvsFlow, ListEntry);

        if (flow->hash == *hash &&
            flow->key.l2.val == key->l2.val &&
            FlowEqual((UINT64 *)((uint8 *)&flow->key + offset),
                         (UINT64 *)start, size)) {
            return flow;
        }
        link = link->Flink;
    }
    return NULL;
}


/*
 * ----------------------------------------------------------------------------
 * OvsHashFlow --
 *    Calculate the hash for the given flow key.
 * ----------------------------------------------------------------------------
 */
UINT64
OvsHashFlow(const OvsFlowKey *key)
{
    UINT16 offset = key->l2.offset;
    UINT16 size = key->l2.keyLen;
    UINT8 *start;

    ASSERT(key->tunKey.dst || offset == sizeof (OvsIPv4TunnelKey));
    ASSERT(!key->tunKey.dst || offset == 0);
    start = (UINT8 *)key + offset;
    return OvsJhashBytes(start, size, 0);
}


/*
 * ----------------------------------------------------------------------------
 * FreeFlow --
 *    Free a flow and its actions.
 * ----------------------------------------------------------------------------
 */
VOID
FreeFlow(OvsFlow *flow)
{
    ASSERT(flow);
    OvsFreeMemoryWithTag(flow, OVS_FLOW_POOL_TAG);
}

NTSTATUS
OvsDoDumpFlows(OvsFlowDumpInput *dumpInput,
               OvsFlowDumpOutput *dumpOutput,
               UINT32 *replyLen)
{
    UINT32 dpNo;
    OVS_DATAPATH *datapath = NULL;
    OvsFlow *flow;
    PLIST_ENTRY node, head;
    UINT32 column = 0;
    UINT32 rowIndex, columnIndex;
    LOCK_STATE_EX dpLockState;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN findNextNonEmpty = FALSE;

    dpNo = dumpInput->dpNo;
    if (gOvsSwitchContext->dpNo != dpNo) {
        status = STATUS_INVALID_PARAMETER;
        goto exit;
    }

    rowIndex = dumpInput->position[0];
    if (rowIndex >= OVS_FLOW_TABLE_SIZE) {
        dumpOutput->n = 0;
        *replyLen = sizeof(*dumpOutput);
        goto exit;
    }

    columnIndex = dumpInput->position[1];

    datapath = &gOvsSwitchContext->datapath;
    ASSERT(datapath);
    OvsAcquireDatapathRead(datapath, &dpLockState, FALSE);

    head = &datapath->flowTable[rowIndex];
    node = head->Flink;

    while (column < columnIndex) {
        if (node == head) {
            break;
        }
        node = node->Flink;
        column++;
    }

    if (node == head) {
        findNextNonEmpty = TRUE;
        columnIndex = 0;
    }

    if (findNextNonEmpty) {
        while (head == node) {
            if (++rowIndex >= OVS_FLOW_TABLE_SIZE) {
                dumpOutput->n = 0;
                goto dp_unlock;
            }
            head = &datapath->flowTable[rowIndex];
            node = head->Flink;
        }
    }

    ASSERT(node != head);
    ASSERT(rowIndex < OVS_FLOW_TABLE_SIZE);

    flow = CONTAINING_RECORD(node, OvsFlow, ListEntry);
    status = ReportFlowInfo(flow, dumpInput->getFlags, &dumpOutput->flow);

    if (status == STATUS_BUFFER_TOO_SMALL) {
        dumpOutput->n = sizeof(OvsFlowDumpOutput) + flow->actionsLen;
        *replyLen = sizeof(*dumpOutput);
    } else {
        dumpOutput->n = 1; //one flow reported.
        *replyLen = sizeof(*dumpOutput) + dumpOutput->flow.actionsLen;
    }

    dumpOutput->position[0] = rowIndex;
    dumpOutput->position[1] = ++columnIndex;

dp_unlock:
    OvsReleaseDatapath(datapath, &dpLockState);

exit:
    return status;
}

static NTSTATUS
ReportFlowInfo(OvsFlow *flow,
               UINT32 getFlags,
               OvsFlowInfo *info)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (getFlags & FLOW_GET_KEY) {
        // always copy the tunnel key part
        RtlCopyMemory(&info->key, &flow->key,
                            flow->key.l2.keyLen + flow->key.l2.offset);
    }

    if (getFlags & FLOW_GET_STATS) {
        OvsFlowStats *stats = &info->stats;
        stats->packetCount = flow->packetCount;
        stats->byteCount = flow->byteCount;
        stats->used = (UINT32)flow->used;
        stats->tcpFlags = flow->tcpFlags;
    }

    if (getFlags & FLOW_GET_ACTIONS) {
        if (flow->actionsLen == 0) {
            info->actionsLen = 0;
        } else {
            info->actions = flow->actions;
            info->actionsLen = flow->actionsLen;
        }
    }

    return status;
}

NTSTATUS
OvsPutFlowIoctl(PVOID inputBuffer,
                UINT32 inputLength,
                struct OvsFlowStats *stats)
{
    NTSTATUS status = STATUS_SUCCESS;
    OVS_DATAPATH *datapath = NULL;
    ULONG actionsLen;
    OvsFlowPut *put;
    UINT32 dpNo;
    LOCK_STATE_EX dpLockState;

    if ((inputLength < sizeof(OvsFlowPut)) || (inputBuffer == NULL)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    put = (OvsFlowPut *)inputBuffer;
    if (put->actionsLen > 0) {
        actionsLen = put->actionsLen;
    } else {
        actionsLen = 0;
    }

    dpNo = put->dpNo;
    if (gOvsSwitchContext->dpNo != dpNo) {
        status = STATUS_INVALID_PARAMETER;
        goto exit;
    }

    datapath = &gOvsSwitchContext->datapath;
    ASSERT(datapath);
    OvsAcquireDatapathWrite(datapath, &dpLockState, FALSE);
    status = HandleFlowPut(put, datapath, stats);
    OvsReleaseDatapath(datapath, &dpLockState);

exit:
    return status;
}


/* Handles flow add, modify as well as delete */
static NTSTATUS
HandleFlowPut(OvsFlowPut *put,
              OVS_DATAPATH *datapath,
              struct OvsFlowStats *stats)
{
    BOOLEAN   mayCreate, mayModify, mayDelete;
    OvsFlow   *KernelFlow;
    UINT64    hash;
    NTSTATUS  status = STATUS_SUCCESS;

    mayCreate = (put->flags & OVSWIN_FLOW_PUT_CREATE) != 0;
    mayModify = (put->flags & OVSWIN_FLOW_PUT_MODIFY) != 0;
    mayDelete = (put->flags & OVSWIN_FLOW_PUT_DELETE) != 0;

    if ((mayCreate || mayModify) == mayDelete) {
        return STATUS_INVALID_PARAMETER;
    }

    KernelFlow = OvsLookupFlow(datapath, &put->key, &hash, FALSE);
    if (!KernelFlow) {
        if (!mayCreate) {
            return STATUS_INVALID_PARAMETER;
        }

        status = OvsPrepareFlow(&KernelFlow, put, hash);
        if (status != STATUS_SUCCESS) {
            FreeFlow(KernelFlow);
            return STATUS_UNSUCCESSFUL;
        }

        status = AddFlow(datapath, KernelFlow);
        if (status != STATUS_SUCCESS) {
            FreeFlow(KernelFlow);
            return STATUS_UNSUCCESSFUL;
        }

        /* Validate the flow addition */
        {
            UINT64 newHash;
            OvsFlow *flow = OvsLookupFlow(datapath, &put->key, &newHash,
                                                                    FALSE);
            ASSERT(flow);
            ASSERT(newHash == hash);
            if (!flow || newHash != hash) {
                return STATUS_UNSUCCESSFUL;
            }
        }
    } else {
        stats->packetCount = KernelFlow->packetCount;
        stats->byteCount = KernelFlow->byteCount;
        stats->tcpFlags = KernelFlow->tcpFlags;
        stats->used = (UINT32)KernelFlow->used;

        if (mayModify) {
            OvsFlow *newFlow;
            status = OvsPrepareFlow(&newFlow, put, hash);
            if (status != STATUS_SUCCESS) {
                return STATUS_UNSUCCESSFUL;
            }

            KernelFlow = OvsLookupFlow(datapath, &put->key, &hash, TRUE);
            if (KernelFlow)  {
                if ((put->flags & OVSWIN_FLOW_PUT_CLEAR) == 0) {
                    newFlow->packetCount = KernelFlow->packetCount;
                    newFlow->byteCount = KernelFlow->byteCount;
                    newFlow->tcpFlags = KernelFlow->tcpFlags;
                }
                RemoveFlow(datapath, &KernelFlow);
            }  else  {
                if ((put->flags & OVSWIN_FLOW_PUT_CLEAR) == 0)  {
                    newFlow->packetCount = stats->packetCount;
                    newFlow->byteCount = stats->byteCount;
                    newFlow->tcpFlags = stats->tcpFlags;
                }
            }
            status = AddFlow(datapath, newFlow);
            ASSERT(status == STATUS_SUCCESS);

            /* Validate the flow addition */
            {
                UINT64 newHash;
                OvsFlow *testflow = OvsLookupFlow(datapath, &put->key,
                                                            &newHash, FALSE);
                ASSERT(testflow);
                ASSERT(newHash == hash);
                if (!testflow || newHash != hash) {
                    FreeFlow(newFlow);
                    return STATUS_UNSUCCESSFUL;
                }
            }
        } else {
            if (mayDelete) {
                if (KernelFlow) {
                    RemoveFlow(datapath, &KernelFlow);
                }
            } else {
                /* Return success if an identical flow already exists. */
                /* XXX: should we return EEXIST in a netlink error? */
                return STATUS_SUCCESS;
            }
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
OvsPrepareFlow(OvsFlow **flow,
               const OvsFlowPut *put,
               UINT64 hash)
{
    OvsFlow     *localFlow = *flow;
    NTSTATUS status = STATUS_SUCCESS;

    do {
        *flow = localFlow =
            OvsAllocateMemoryWithTag(sizeof(OvsFlow) + put->actionsLen,
                                     OVS_FLOW_POOL_TAG);
        if (localFlow == NULL) {
            status = STATUS_NO_MEMORY;
            break;
        }

        localFlow->key = put->key;
        localFlow->actionsLen = put->actionsLen;
        if (put->actionsLen) {
            NdisMoveMemory((PUCHAR)localFlow->actions, put->actions,
                                       put->actionsLen);
        }
        localFlow->userActionsLen = 0;  // 0 indicate no conversion is made
        localFlow->used = 0;
        localFlow->packetCount = 0;
        localFlow->byteCount = 0;
        localFlow->tcpFlags = 0;
        localFlow->hash = hash;
    } while(FALSE);

    return status;
}

NTSTATUS
OvsGetFlowIoctl(PVOID inputBuffer,
                PVOID outputBuffer)
{
    NTSTATUS status = STATUS_SUCCESS;
    OVS_DATAPATH *datapath = NULL;
    OvsFlow *flow;
    UINT32 getFlags, getActionsLen;
    OvsFlowGetInput *getInput;
    OvsFlowGetOutput *getOutput;
    UINT64 hash;
    UINT32 dpNo;
    LOCK_STATE_EX dpLockState;

    getInput = (OvsFlowGetInput *) inputBuffer;
    getFlags = getInput->getFlags;
    getActionsLen = getInput->actionsLen;

    if (outputBuffer == NULL) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    dpNo = getInput->dpNo;
    if (gOvsSwitchContext->dpNo != dpNo) {
        status = STATUS_INVALID_PARAMETER;
        goto exit;
    }

    datapath = &gOvsSwitchContext->datapath;
    ASSERT(datapath);
    OvsAcquireDatapathRead(datapath, &dpLockState, FALSE);
    flow = OvsLookupFlow(datapath, &getInput->key, &hash, FALSE);
    if (!flow) {
        status = STATUS_INVALID_PARAMETER;
        goto dp_unlock;
    }

    getOutput = (OvsFlowGetOutput *)outputBuffer;
    ReportFlowInfo(flow, getFlags, &getOutput->info);

dp_unlock:
    OvsReleaseDatapath(datapath, &dpLockState);
exit:
    return status;
}

NTSTATUS
OvsFlushFlowIoctl(UINT32 dpNo)
{
    NTSTATUS status = STATUS_SUCCESS;
    OVS_DATAPATH *datapath = NULL;
    LOCK_STATE_EX dpLockState;

    if (gOvsSwitchContext->dpNo != dpNo) {
        status = STATUS_INVALID_PARAMETER;
        goto exit;
    }

    datapath = &gOvsSwitchContext->datapath;
    ASSERT(datapath);
    OvsAcquireDatapathWrite(datapath, &dpLockState, FALSE);
    DeleteAllFlows(datapath);
    OvsReleaseDatapath(datapath, &dpLockState);

exit:
    return status;
}

UINT32
OvsFlowKeyAttrSize(void)
{
    return NlAttrTotalSize(4)   /* OVS_KEY_ATTR_PRIORITY */
         + NlAttrTotalSize(0)   /* OVS_KEY_ATTR_TUNNEL */
         + OvsTunKeyAttrSize()
         + NlAttrTotalSize(4)   /* OVS_KEY_ATTR_IN_PORT */
         + NlAttrTotalSize(4)   /* OVS_KEY_ATTR_SKB_MARK */
         + NlAttrTotalSize(4)   /* OVS_KEY_ATTR_DP_HASH */
         + NlAttrTotalSize(4)   /* OVS_KEY_ATTR_RECIRC_ID */
         + NlAttrTotalSize(12)  /* OVS_KEY_ATTR_ETHERNET */
         + NlAttrTotalSize(2)   /* OVS_KEY_ATTR_ETHERTYPE */
         + NlAttrTotalSize(4)   /* OVS_KEY_ATTR_VLAN */
         + NlAttrTotalSize(0)   /* OVS_KEY_ATTR_ENCAP */
         + NlAttrTotalSize(2)   /* OVS_KEY_ATTR_ETHERTYPE */
         + NlAttrTotalSize(40)  /* OVS_KEY_ATTR_IPV6 */
         + NlAttrTotalSize(2)   /* OVS_KEY_ATTR_ICMPV6 */
         + NlAttrTotalSize(28); /* OVS_KEY_ATTR_ND */
}

UINT32
OvsTunKeyAttrSize(void)
{
    /* Whenever adding new OVS_TUNNEL_KEY_ FIELDS, we should consider
     * updating this function.
     */
    return NlAttrTotalSize(8)    /* OVS_TUNNEL_KEY_ATTR_ID */
         + NlAttrTotalSize(4)    /* OVS_TUNNEL_KEY_ATTR_IPV4_SRC */
         + NlAttrTotalSize(4)    /* OVS_TUNNEL_KEY_ATTR_IPV4_DST */
         + NlAttrTotalSize(1)    /* OVS_TUNNEL_KEY_ATTR_TOS */
         + NlAttrTotalSize(1)    /* OVS_TUNNEL_KEY_ATTR_TTL */
         + NlAttrTotalSize(0)    /* OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT */
         + NlAttrTotalSize(0)    /* OVS_TUNNEL_KEY_ATTR_CSUM */
         + NlAttrTotalSize(0)    /* OVS_TUNNEL_KEY_ATTR_OAM */
         + NlAttrTotalSize(256)  /* OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS */
         + NlAttrTotalSize(2)    /* OVS_TUNNEL_KEY_ATTR_TP_SRC */
         + NlAttrTotalSize(2);   /* OVS_TUNNEL_KEY_ATTR_TP_DST */
}

#pragma warning( pop )
