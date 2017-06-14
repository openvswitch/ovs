/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include "NetlinkProto.h"
#include "Netlink.h"

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_NETLINK
#include "Debug.h"

/* ==========================================================================
 * This file provides simple netlink get, put and validation APIs.
 * Most of the code is on similar lines as userspace netlink implementation.
 *
 * TODO: Convert these methods to inline.
 * ==========================================================================
 */

/*
 * ---------------------------------------------------------------------------
 * Prepare netlink message headers. This API adds
 * NL_MSG_HDR + GENL_HDR + OVS_HDR to the tail of input NLBuf.
 * Attributes should be added by caller.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlFillOvsMsg(PNL_BUFFER nlBuf, UINT16 nlmsgType,
             UINT16 nlmsgFlags, UINT32 nlmsgSeq,
             UINT32 nlmsgPid, UINT8 genlCmd,
             UINT8 genlVer, UINT32 dpNo)
{
    BOOLEAN writeOk;
    OVS_MESSAGE msgOut;
    UINT32 offset = NlBufSize(nlBuf);

    /* To keep compiler happy for release build. */
    UNREFERENCED_PARAMETER(offset);
    ASSERT(NlBufAt(nlBuf, offset, 0) != 0);

    msgOut.nlMsg.nlmsgType = nlmsgType;
    msgOut.nlMsg.nlmsgFlags = nlmsgFlags;
    msgOut.nlMsg.nlmsgSeq = nlmsgSeq;
    msgOut.nlMsg.nlmsgPid = nlmsgPid;
    msgOut.nlMsg.nlmsgLen = sizeof(struct _OVS_MESSAGE);

    msgOut.genlMsg.cmd = genlCmd;
    msgOut.genlMsg.version = genlVer;
    msgOut.genlMsg.reserved = 0;

    msgOut.ovsHdr.dp_ifindex = dpNo;

    writeOk = NlMsgPutTail(nlBuf, (PCHAR)(&msgOut),
                           sizeof (struct _OVS_MESSAGE));

    return writeOk;
}

/*
 * ---------------------------------------------------------------------------
 * Prepare netlink message headers. This API adds
 * NL_MSG_HDR + GENL_HDR + OVS_HDR to the tail of input NLBuf.
 * Attributes should be added by caller.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlFillOvsMsgForNfGenMsg(PNL_BUFFER nlBuf, UINT16 nlmsgType,
                        UINT16 nlmsgFlags, UINT32 nlmsgSeq,
                        UINT32 nlmsgPid, UINT8 nfgenFamily,
                        UINT8 nfGenVersion, UINT32 dpNo)
{
    BOOLEAN writeOk;
    OVS_MESSAGE msgOut;
    UINT32 offset = NlBufSize(nlBuf);

    /* To keep compiler happy for release build. */
    UNREFERENCED_PARAMETER(offset);
    ASSERT(NlBufAt(nlBuf, offset, 0) != 0);

    msgOut.nlMsg.nlmsgType = nlmsgType;
    msgOut.nlMsg.nlmsgFlags = nlmsgFlags;
    msgOut.nlMsg.nlmsgSeq = nlmsgSeq;
    msgOut.nlMsg.nlmsgPid = nlmsgPid;
    msgOut.nlMsg.nlmsgLen = sizeof(struct _OVS_MESSAGE);

    msgOut.nfGenMsg.nfgenFamily = nfgenFamily;
    msgOut.nfGenMsg.version = nfGenVersion;
    msgOut.nfGenMsg.resId = 0;

    msgOut.ovsHdr.dp_ifindex = dpNo;

    writeOk = NlMsgPutTail(nlBuf, (PCHAR)(&msgOut),
                           sizeof (struct _OVS_MESSAGE));

    return writeOk;
}

/*
 * ---------------------------------------------------------------------------
 * Prepare NL_MSG_HDR only. This API appends a NL_MSG_HDR to the tail of
 * input NlBuf.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlFillNlHdr(PNL_BUFFER nlBuf, UINT16 nlmsgType,
            UINT16 nlmsgFlags, UINT32 nlmsgSeq,
            UINT32 nlmsgPid)
{
    BOOLEAN writeOk;
    NL_MSG_HDR msgOut;
    UINT32 offset = NlBufSize(nlBuf);

    /* To keep compiler happy for release build. */
    UNREFERENCED_PARAMETER(offset);
    ASSERT(NlBufAt(nlBuf, offset, 0) != 0);

    msgOut.nlmsgType = nlmsgType;
    msgOut.nlmsgFlags = nlmsgFlags;
    msgOut.nlmsgSeq = nlmsgSeq;
    msgOut.nlmsgPid = nlmsgPid;
    msgOut.nlmsgLen = sizeof(struct _NL_MSG_HDR);

    writeOk = NlMsgPutTail(nlBuf, (PCHAR)(&msgOut),
                           sizeof(struct _NL_MSG_HDR));

    return writeOk;
}

/*
 * ---------------------------------------------------------------------------
 * Prepare a 'OVS_MESSAGE_ERROR' message.
 * ---------------------------------------------------------------------------
 */
VOID
NlBuildErrorMsg(POVS_MESSAGE msgIn, POVS_MESSAGE_ERROR msgError,
                UINT errorCode, UINT32 *replyLen)
{
    NL_BUFFER nlBuffer;

    ASSERT(errorCode != NL_ERROR_PENDING);

    NlBufInit(&nlBuffer, (PCHAR)msgError, sizeof *msgError);
    NlFillNlHdr(&nlBuffer, NLMSG_ERROR, 0,
                msgIn->nlMsg.nlmsgSeq, msgIn->nlMsg.nlmsgPid);

    msgError->errorMsg.error = errorCode;
    msgError->errorMsg.nlMsg = msgIn->nlMsg;
    msgError->nlMsg.nlmsgLen = sizeof(OVS_MESSAGE_ERROR);

    *replyLen = msgError->nlMsg.nlmsgLen;
}

/*
 * ---------------------------------------------------------------------------
 * Adds Netlink Header to the NL_BUF.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutNlHdr(PNL_BUFFER buf, PNL_MSG_HDR nlMsg)
{
    if ((NlBufCopyAtOffset(buf, (PCHAR)nlMsg, NLMSG_HDRLEN, 0))) {
        return TRUE;
    }

    return FALSE;
}

/*
 * ---------------------------------------------------------------------------
 * Adds Genl Header to the NL_BUF.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutGenlHdr(PNL_BUFFER buf, PGENL_MSG_HDR genlMsg)
{
    if ((NlBufCopyAtOffset(buf, (PCHAR)genlMsg, GENL_HDRLEN, NLMSG_HDRLEN))) {
        return TRUE;
    }

    return FALSE;
}

/*
 * ---------------------------------------------------------------------------
 * Adds OVS Header to the NL_BUF.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutOvsHdr(PNL_BUFFER buf, POVS_HDR ovsHdr)
{
    if ((NlBufCopyAtOffset(buf, (PCHAR)ovsHdr, OVS_HDRLEN,
                           GENL_HDRLEN + NLMSG_HDRLEN))) {
        return TRUE;
    }

    return FALSE;
}

/*
 * ---------------------------------------------------------------------------
 * Adds data of length 'len' to the tail end of NL_BUF.
 * Refer nl_msg_put for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutTail(PNL_BUFFER buf, const PCHAR data, UINT32 len)
{
    len = NLMSG_ALIGN(len);
    if (NlBufCopyAtTail(buf, data, len)) {
        return TRUE;
    }

    return FALSE;
}

/*
 * ---------------------------------------------------------------------------
 * memsets length 'len' at tail end of NL_BUF.
 * Refer nl_msg_put_uninit for more details.
 * ---------------------------------------------------------------------------
 */
PCHAR
NlMsgPutTailUninit(PNL_BUFFER buf, UINT32 len)
{
    len = NLMSG_ALIGN(len);
    return NlBufCopyAtTailUninit(buf, len);
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute to the tail end of buffer. It does
 * not copy the attribute payload.
 * Refer nl_msg_put_unspec_uninit for more details.
 * ---------------------------------------------------------------------------
 */
PCHAR
NlMsgPutTailUnspecUninit(PNL_BUFFER buf, UINT16 type, UINT16 len)
{
    PCHAR ret = NULL;
    UINT16 totalLen = NLA_HDRLEN + len;
    PNL_ATTR nla = (PNL_ATTR)(NlMsgPutTailUninit(buf, totalLen));

    if (!nla) {
        goto done;
    }

    ret = (PCHAR)(nla + 1);
    nla->nlaLen = totalLen;
    nla->nlaType = type;

done:
    return ret;
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute to the tail end of buffer. It copies attribute
 * payload as well.
 * Refer nl_msg_put_unspec for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutTailUnspec(PNL_BUFFER buf, UINT16 type, PCHAR data, UINT16 len)
{
    BOOLEAN ret = TRUE;
    PCHAR nlaData = NlMsgPutTailUnspecUninit(buf, type, len);

    if (!nlaData) {
        ret = FALSE;
        goto done;
    }

    RtlCopyMemory(nlaData, data, len);

done:
    return ret;
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute of 'type' and no payload at the tail end of buffer.
 * Refer nl_msg_put_flag for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutTailFlag(PNL_BUFFER buf, UINT16 type)
{
    BOOLEAN ret = TRUE;
    PCHAR nlaData = NlMsgPutTailUnspecUninit(buf, type, 0);

    if (!nlaData) {
        ret = FALSE;
    }

    return ret;
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute of 'type' and 8 bit payload at the tail end of buffer.
 * Refer nl_msg_put_u8 for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutTailU8(PNL_BUFFER buf, UINT16 type, UINT8 value)
{
    return (NlMsgPutTailUnspec(buf, type, (PCHAR)(&value), sizeof(value)));
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute of 'type' and 16 bit payload at the tail end of buffer.
 * Refer nl_msg_put_u16 for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutTailU16(PNL_BUFFER buf, UINT16 type, UINT16 value)
{
    return (NlMsgPutTailUnspec(buf, type, (PCHAR)(&value), sizeof(value)));
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute of 'type' and 32 bit payload at the tail end of buffer.
 * Refer nl_msg_put_u32 for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutTailU32(PNL_BUFFER buf, UINT16 type, UINT32 value)
{
    return (NlMsgPutTailUnspec(buf, type, (PCHAR)(&value), sizeof(value)));
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute of 'type' and 64 bit payload at the tail end of buffer.
 * Refer nl_msg_put_u64 for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutTailU64(PNL_BUFFER buf, UINT16 type, UINT64 value)
{
    return (NlMsgPutTailUnspec(buf, type, (PCHAR)(&value), sizeof(value)));
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute of 'type' and string payload.
 * Refer nl_msg_put_string for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutTailString(PNL_BUFFER buf, UINT16 type, PCHAR value)
{
    size_t strLen = strlen(value) + 1;
#ifdef DBG
    /* Attribute length should come within 16 bits (NL_ATTR).
     * Not a likely case, hence validation only in debug mode. */
    if ((strLen + PAD_SIZE(strLen, NLA_ALIGNTO)) > MAXUINT16) {
        return FALSE;
    }
#endif

    /* typecast to keep compiler happy */
    return (NlMsgPutTailUnspec(buf, type, value,
                               (UINT16)strLen));
}

/*
 * ---------------------------------------------------------------------------
 * Adds data of length 'len' to the head of NL_BUF.
 * Refer nl_msg_push for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutHead(PNL_BUFFER buf, const PCHAR data, UINT32 len)
{
    len = NLMSG_ALIGN(len);
    if (NlBufCopyAtHead(buf, data, len)) {
        return TRUE;
    }

    return FALSE;
}

/*
 * ---------------------------------------------------------------------------
 * memsets length 'len' at head of NL_BUF.
 * Refer nl_msg_push_uninit for more details.
 * ---------------------------------------------------------------------------
 */
PCHAR
NlMsgPutHeadUninit(PNL_BUFFER buf, UINT32 len)
{
    len = NLMSG_ALIGN(len);
    return NlBufCopyAtHeadUninit(buf, len);
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute to the head of buffer. It does
 * not copy the attribute payload.
 * Refer nl_msg_push_unspec_uninit for more details.
 * ---------------------------------------------------------------------------
 */
PCHAR
NlMsgPutHeadUnspecUninit(PNL_BUFFER buf, UINT16 type, UINT16 len)
{
    PCHAR ret = NULL;
    UINT16 totalLen = NLA_HDRLEN + len;
    PNL_ATTR nla = (PNL_ATTR)(NlMsgPutHeadUninit(buf, totalLen));

    if (!nla) {
        goto done;
    }

    ret = (PCHAR)(nla + 1);
    nla->nlaLen = totalLen;
    nla->nlaType = type;

done:
    return ret;
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute to the head of buffer. It copies attribute
 * payload as well.
 * Refer nl_msg_push_unspec for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutHeadUnspec(PNL_BUFFER buf, UINT16 type, PCHAR data, UINT16 len)
{
    BOOLEAN ret = TRUE;
    PCHAR nlaData = NlMsgPutHeadUnspecUninit(buf, type, len);

    if (!nlaData) {
        ret = FALSE;
        goto done;
    }

    RtlCopyMemory(nlaData, data, len);

done:
    return ret;
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute of 'type' and no payload at the head of buffer.
 * Refer nl_msg_push_flag for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutHeadFlag(PNL_BUFFER buf, UINT16 type)
{
    BOOLEAN ret = TRUE;
    PCHAR nlaData = NlMsgPutHeadUnspecUninit(buf, type, 0);

    if (!nlaData) {
        ret = FALSE;
    }

    return ret;
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute of 'type' and 8 bit payload at the head of buffer.
 * Refer nl_msg_push_u8 for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutHeadU8(PNL_BUFFER buf, UINT16 type, UINT8 value)
{
    return (NlMsgPutHeadUnspec(buf, type, (PCHAR)(&value), sizeof(value)));
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute of 'type' and 16 bit payload at the head of buffer.
 * Refer nl_msg_push_u16 for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutHeadU16(PNL_BUFFER buf, UINT16 type, UINT16 value)
{
    return (NlMsgPutHeadUnspec(buf, type, (PCHAR)(&value), sizeof(value)));
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute of 'type' and 32 bit payload at the head of buffer.
 * Refer nl_msg_push_u32 for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutHeadU32(PNL_BUFFER buf, UINT16 type, UINT32 value)
{
    return (NlMsgPutHeadUnspec(buf, type, (PCHAR)(&value), sizeof(value)));
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute of 'type' and 64 bit payload at the head of buffer.
 * Refer nl_msg_push_u64 for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutHeadU64(PNL_BUFFER buf, UINT16 type, UINT64 value)
{
    return (NlMsgPutHeadUnspec(buf, type, (PCHAR)(&value), sizeof(value)));
}

/*
 * ---------------------------------------------------------------------------
 * Adds an attribute of 'type' and string payload.
 * Refer nl_msg_push_string for more details.
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutHeadString(PNL_BUFFER buf, UINT16 type, PCHAR value)
{
    size_t strLen = strlen(value) + 1;
#ifdef DBG
    /* Attribute length should come within 16 bits (NL_ATTR).
     * Not a likely case, hence validation only in debug mode. */
    if ((strLen + PAD_SIZE(strLen, NLA_ALIGNTO)) > MAXUINT16) {
        return FALSE;
    }
#endif

    /* typecast to keep compiler happy */
    return (NlMsgPutHeadUnspec(buf, type, value,
                               (UINT16)strLen));
}

/*
 * ---------------------------------------------------------------------------
 * Adds the header for nested netlink attributes. It
 * returns the offset of this header. If addition of header fails
 * then returned value of offset will be zero.
 * Refer nl_msg_start_nested for more details.
 * ---------------------------------------------------------------------------
 */
UINT32
NlMsgStartNested(PNL_BUFFER buf, UINT16 type)
{
    UINT32 offset = NlBufSize(buf);
    PCHAR nlaData = NULL;

    nlaData = NlMsgPutTailUnspecUninit(buf, type, 0);

    if (!nlaData) {
        /* Value zero must be reated as error by the caller.
         * This is because an attribute can never be added
         * at offset zero, it will always come after NL_MSG_HDR,
         * GENL_HDR and OVS_HEADER. */
        offset = 0;
    }

    return offset;
}

/*
 * ---------------------------------------------------------------------------
 * Finalizes the nested netlink attribute by updating the nla_len.
 * offset should be the one returned by NlMsgStartNested.
 * Refer nl_msg_end_nested for more details.
 * ---------------------------------------------------------------------------
 */
VOID
NlMsgEndNested(PNL_BUFFER buf, UINT32 offset)
{
    PNL_ATTR attr = (PNL_ATTR)(NlBufAt(buf, offset, sizeof *attr));

    /* Typecast to keep compiler happy.
     * Attribute length would never exceed MAX UINT16.*/
    attr->nlaLen = (UINT16)(NlBufSize(buf) - offset);
}

/*
 * --------------------------------------------------------------------------
 * Appends a nested Netlink attribute of the given 'type', with the 'size'
 * bytes of content starting at 'data', to 'msg'.
 * Refer nl_msg_put_nested for more details.
 * --------------------------------------------------------------------------
 */
BOOLEAN
NlMsgPutNested(PNL_BUFFER buf, UINT16 type,
               const PVOID data, UINT32 size)
{
    UINT32 offset = NlMsgStartNested(buf, type);
    BOOLEAN ret;

    ASSERT(offset);

    ret = NlMsgPutTail(buf, data, size);

    ASSERT(ret);

    NlMsgEndNested(buf, offset);

    return ret;
}

/* Accessing netlink message payload */

/*
 * ---------------------------------------------------------------------------
 * Netlink message accessing the payload.
 * ---------------------------------------------------------------------------
 */
PVOID
NlMsgAt(const PNL_MSG_HDR nlh, UINT32 offset)
{
    return ((PCHAR)nlh + offset);
}

/*
 * ---------------------------------------------------------------------------
 * Returns the size of netlink message.
 * ---------------------------------------------------------------------------
 */
UINT32
NlMsgSize(const PNL_MSG_HDR nlh)
{
    return nlh->nlmsgLen;
}

/*
 * ---------------------------------------------------------------------------
 * Aligns the size of Netlink message.
 * ---------------------------------------------------------------------------
 */
VOID
NlMsgAlignSize(const PNL_MSG_HDR nlh)
{
    nlh->nlmsgLen = NLMSG_ALIGN(nlh->nlmsgLen);
    return;
}

/*
 * ---------------------------------------------------------------------------
 * Sets the size of Netlink message.
 * ---------------------------------------------------------------------------
 */
VOID
NlMsgSetSize(const PNL_MSG_HDR nlh, UINT32 msgLen)
{
    nlh->nlmsgLen = msgLen;
}

/*
 * ---------------------------------------------------------------------------
 * Returns pointer to nlmsg payload.
 * ---------------------------------------------------------------------------
 */
PCHAR
NlHdrPayload(const PNL_MSG_HDR nlh)
{
    return ((PCHAR)nlh + NLMSG_HDRLEN);
}

/*
 * ---------------------------------------------------------------------------
 * Returns length of nlmsg payload.
 * ---------------------------------------------------------------------------
 */
UINT32
NlHdrPayloadLen(const PNL_MSG_HDR nlh)
{
    return nlh->nlmsgLen - NLMSG_HDRLEN;
}

/*
 * ---------------------------------------------------------------------------
 * Returns pointer to nlmsg attributes.
 * ---------------------------------------------------------------------------
 */
PNL_ATTR
NlMsgAttrs(const PNL_MSG_HDR nlh)
{
    return (PNL_ATTR) (NlHdrPayload(nlh) + GENL_HDRLEN + OVS_HDRLEN);
}

/*
 * ---------------------------------------------------------------------------
 * Returns size of to nlmsg attributes.
 * ---------------------------------------------------------------------------
 */
UINT32
NlMsgAttrsLen(const PNL_MSG_HDR nlh)
{
    return NlHdrPayloadLen(nlh) - GENL_HDRLEN - OVS_HDRLEN;
}

/*
 * ---------------------------------------------------------------------------
 * Returns size of to nfnlmsg attributes.
 * ---------------------------------------------------------------------------
 */
UINT32
NlNfMsgAttrsLen(const PNL_MSG_HDR nlh)
{
    return NlHdrPayloadLen(nlh) - NF_GEN_MSG_HDRLEN - OVS_HDRLEN;
}

/* Netlink message parse. */

/*
 * ---------------------------------------------------------------------------
 * Returns next netlink message in the stream.
 * ---------------------------------------------------------------------------
 */
PNL_MSG_HDR
NlMsgNext(const PNL_MSG_HDR nlh)
{
    return (PNL_MSG_HDR)((PCHAR)nlh +
            NLMSG_ALIGN(nlh->nlmsgLen));
}

/*
 * ---------------------------------------------------------------------------
 * Netlink Attr helper APIs.
 * ---------------------------------------------------------------------------
 */
INT
NlAttrIsValid(const PNL_ATTR nla, UINT32 maxlen)
{
    return (maxlen >= sizeof *nla
            && nla->nlaLen >= sizeof *nla
            && nla->nlaLen <= maxlen);
}

/*
 * ---------------------------------------------------------------------------
 * Returns alligned length of the attribute.
 * ---------------------------------------------------------------------------
 */
UINT32
NlAttrLenPad(const PNL_ATTR nla, UINT32 maxlen)
{
    UINT32 len = NLA_ALIGN(nla->nlaLen);

    return len <= maxlen ? len : nla->nlaLen;
}

/*
 * ---------------------------------------------------------------------------
 * Default minimum payload size for each type of attribute.
 * ---------------------------------------------------------------------------
 */
UINT32
NlAttrMinLen(NL_ATTR_TYPE type)
{
    switch (type) {
    case NL_A_NO_ATTR: return 0;
    case NL_A_UNSPEC: return 0;
    case NL_A_U8: return 1;
    case NL_A_U16: return 2;
    case NL_A_U32: return 4;
    case NL_A_U64: return 8;
    case NL_A_STRING: return 1;
    case NL_A_FLAG: return 0;
    case NL_A_NESTED: return 0;
    case N_NL_ATTR_TYPES:
    default:
    OVS_LOG_WARN("Unsupprted attribute type: %d", type);
    ASSERT(0);
    }

    /* To keep compiler happy */
    return 0;
}

/*
 * ---------------------------------------------------------------------------
 * Default maximum payload size for each type of attribute.
 * ---------------------------------------------------------------------------
 */
UINT32
NlAttrMaxLen(NL_ATTR_TYPE type)
{
    switch (type) {
    case NL_A_NO_ATTR: return SIZE_MAX;
    case NL_A_UNSPEC: return SIZE_MAX;
    case NL_A_U8: return 1;
    case NL_A_U16: return 2;
    case NL_A_U32: return 4;
    case NL_A_U64: return 8;
    case NL_A_STRING: return MAXUINT16;
    case NL_A_FLAG: return SIZE_MAX;
    case NL_A_NESTED: return SIZE_MAX;
    case N_NL_ATTR_TYPES:
    default:
    OVS_LOG_WARN("Unsupprted attribute type: %d", type);
    ASSERT(0);
    }

    /* To keep compiler happy */
    return 0;
}

/* Netlink attribute iteration. */

/*
 * ---------------------------------------------------------------------------
 * Returns the next attribute.
 * ---------------------------------------------------------------------------
 */
PNL_ATTR
NlAttrNext(const PNL_ATTR nla)
{
    return (PNL_ATTR)((UINT8 *)nla + NLA_ALIGN(nla->nlaLen));
}

/*
 * --------------------------------------------------------------------------
 * Returns the bits of 'nla->nlaType' that are significant for determining
 * its type.
 * --------------------------------------------------------------------------
 */
UINT16
NlAttrType(const PNL_ATTR nla)
{
   return nla->nlaType & NLA_TYPE_MASK;
}

/*
 * --------------------------------------------------------------------------
 * Returns the netlink attribute data.
 * --------------------------------------------------------------------------
 */
PVOID
NlAttrData(const PNL_ATTR nla)
{
    return ((PCHAR)nla + NLA_HDRLEN);
}

/*
 * ---------------------------------------------------------------------------
 * Returns the number of bytes in the payload of attribute 'nla'.
 * ---------------------------------------------------------------------------
 */
UINT32
NlAttrGetSize(const PNL_ATTR nla)
{
    return nla->nlaLen - NLA_HDRLEN;
}

/*
 * ---------------------------------------------------------------------------
 * Returns the first byte in the payload of attribute 'nla'.
 * ---------------------------------------------------------------------------
 */
const PVOID
NlAttrGet(const PNL_ATTR nla)
{
    ASSERT(nla->nlaLen >= NLA_HDRLEN);
    return nla + 1;
}

/*
 * ---------------------------------------------------------------------------
 * Asserts that 'nla''s payload is at least 'size' bytes long, and returns the
 * first byte of the payload.
 * ---------------------------------------------------------------------------
 */
const
PVOID NlAttrGetUnspec(const PNL_ATTR nla, UINT32 size)
{
    UNREFERENCED_PARAMETER(size);
    ASSERT(nla->nlaLen >= NLA_HDRLEN + size);
    return nla + 1;
}

/*
 * ---------------------------------------------------------------------------
 * Returns the 64-bit network byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 8 bytes long.
 * ---------------------------------------------------------------------------
 */
BE64
NlAttrGetBe64(const PNL_ATTR nla)
{
    return NL_ATTR_GET_AS(nla, BE64);
}

/*
 * ---------------------------------------------------------------------------
 * Returns the 32-bit network byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 4 bytes long.
 * ---------------------------------------------------------------------------
 */
BE32
NlAttrGetBe32(const PNL_ATTR nla)
{
    return NL_ATTR_GET_AS(nla, BE32);
}

/*
 * ---------------------------------------------------------------------------
 * Returns the 16-bit network byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 2 bytes long.
 * ---------------------------------------------------------------------------
 */
BE16
NlAttrGetBe16(const PNL_ATTR nla)
{
    return NL_ATTR_GET_AS(nla, BE16);
}

/*
 * ---------------------------------------------------------------------------
 * Returns the 8-bit network byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 1 byte long.
 * ---------------------------------------------------------------------------
 */
BE8
NlAttrGetBe8(const PNL_ATTR nla)
{
    return NL_ATTR_GET_AS(nla, BE8);
}

/*
 * ---------------------------------------------------------------------------
 * Returns the 8-bit value in 'nla''s payload.
 * ---------------------------------------------------------------------------
 */
UINT8
NlAttrGetU8(const PNL_ATTR nla)
{
    return NL_ATTR_GET_AS(nla, UINT8);
}

/*
 * ---------------------------------------------------------------------------
 * Returns the 16-bit host byte order value in 'nla''s payload.
 * Asserts that 'nla''s payload is at least 2 bytes long.
 * ---------------------------------------------------------------------------
 */
UINT16
NlAttrGetU16(const PNL_ATTR nla)
{
    return NL_ATTR_GET_AS(nla, UINT16);
}

/*
 * ---------------------------------------------------------------------------
 * Returns the 32-bit host byte order value in 'nla''s payload.
 * Asserts that 'nla''s payload is at least 4 bytes long.
 * ---------------------------------------------------------------------------
 */
UINT32
NlAttrGetU32(const PNL_ATTR nla)
{
    return NL_ATTR_GET_AS(nla, UINT32);
}

/*
 * ---------------------------------------------------------------------------
 * Returns the 64-bit host byte order value in 'nla''s payload.
 * Asserts that 'nla''s payload is at least 8 bytes long.
 * ---------------------------------------------------------------------------
 */
UINT64
NlAttrGetU64(const PNL_ATTR nla)
{
    return NL_ATTR_GET_AS(nla, UINT64);
}

/*
 * ---------------------------------------------------------------------------
 * Returns the string value in 'nla''s payload.
 * Returns NULL if it is not a proper '\0' terminated string.
 * ---------------------------------------------------------------------------
 */
PCHAR
NlAttrGetString(const PNL_ATTR nla)
{
    ASSERT(nla->nlaLen >= NLA_HDRLEN);
    if (!memchr(NlAttrGet(nla), '\0', NlAttrGetSize(nla))) {
        return NULL;
    }
    return NlAttrGet(nla);
}

/*
 * ---------------------------------------------------------------------------
 * Validate the netlink attribute against the policy
 * ---------------------------------------------------------------------------
 */
BOOLEAN
NlAttrValidate(const PNL_ATTR nla, const PNL_POLICY policy)
{
    UINT32 minLen;
    UINT32 maxLen;
    UINT32 len;
    BOOLEAN ret = FALSE;

    if ((policy->type == NL_A_NO_ATTR) ||
        (policy->type == NL_A_VAR_LEN) ||
        (policy->type == NL_A_NESTED)) {
        /* Do not validate anything for attributes of type var length */
        ret = TRUE;
        goto done;
    }

    /* Figure out min and max length. */
    minLen = policy->minLen;
    if (!minLen) {
        minLen = NlAttrMinLen(policy->type);
    }
    maxLen = policy->maxLen;
    if (!maxLen) {
        maxLen = NlAttrMaxLen(policy->type);
    }

    /* Verify length. */
    len = NlAttrGetSize(nla);
    if (len < minLen || len > maxLen) {
        OVS_LOG_WARN("Attribute: %p, len: %d, not in valid range, "
                     "min: %d, max: %d", nla, len, minLen, maxLen);
        goto done;
    }

    /* Strings must be null terminated and must not have embedded nulls. */
    if (policy->type == NL_A_STRING) {
        if (((PCHAR) nla)[nla->nlaLen - 1]) {
            OVS_LOG_WARN("Attributes %p lacks null at the end", nla);
            goto done;
        }

        if (memchr(nla + 1, '\0', len - 1) != NULL) {
            OVS_LOG_WARN("Attributes %p has bad length", nla);
            goto done;
        }
    }

    ret = TRUE;

done:
    return ret;
}

/*
 * ---------------------------------------------------------------------------
 * Returns an attribute of type 'type' from a series of
 * attributes.
 * ---------------------------------------------------------------------------
 */
const PNL_ATTR
NlAttrFind__(const PNL_ATTR attrs, UINT32 size, UINT16 type)
{
    PNL_ATTR iter = NULL;
    PNL_ATTR ret = NULL;
    INT left;

    NL_ATTR_FOR_EACH (iter, left, attrs, size) {
        if (NlAttrType(iter) == type) {
            ret = iter;
            goto done;
        }
    }

done:
    return ret;
}

/*
 * ---------------------------------------------------------------------------
 * Returns the first Netlink attribute within 'nla' with the specified
 * 'type'.
 *
 * This function does not validate the attribute's length.
 * ---------------------------------------------------------------------------
 */
const PNL_ATTR
NlAttrFindNested(const PNL_ATTR nla, UINT16 type)
{
    return NlAttrFind__((const PNL_ATTR)(NlAttrGet(nla)),
                         NlAttrGetSize(nla), type);
}

/*
 *----------------------------------------------------------------------------
 * Traverses all attributes in received buffer in order to insure all are valid
 *----------------------------------------------------------------------------
 */
BOOLEAN NlValidateAllAttrs(const PNL_MSG_HDR nlMsg, UINT32 attrOffset,
                           UINT32 totalAttrLen,
                           const NL_POLICY policy[], const UINT32 numPolicy)
{
    PNL_ATTR nla;
    INT left;
    BOOLEAN ret = TRUE;

    if ((NlMsgSize(nlMsg) < attrOffset)) {
        OVS_LOG_WARN("No attributes in nlMsg: %p at offset: %d",
            nlMsg, attrOffset);
        ret = FALSE;
        goto done;
    }

    NL_ATTR_FOR_EACH_UNSAFE(nla, left, NlMsgAt(nlMsg, attrOffset),
                            totalAttrLen)
    {
        if (!NlAttrIsValid(nla, left)) {
            ret = FALSE;
            goto done;
        }

        UINT16 type = NlAttrType(nla);
        if (type < numPolicy && policy[type].type != NL_A_NO_ATTR) {
            /* Typecasting to keep the compiler happy */
            const PNL_POLICY e = (const PNL_POLICY)(&policy[type]);
            if (!NlAttrValidate(nla, e)) {
                ret = FALSE;
                goto done;
            }
        }
    }

done:
    return ret;
}

/*
 *----------------------------------------------------------------------------
 * Parses the netlink message at a given offset (attrOffset)
 * as a series of attributes. A pointer to the attribute with type
 * 'type' is stored in attrs at index 'type'. policy is used to define the
 * attribute type validation parameters.
 * 'nla_offset' should be NLMSG_HDRLEN + GENL_HDRLEN + OVS_HEADER
 *
 * Returns BOOLEAN to indicate success/failure.
 *----------------------------------------------------------------------------
 */
BOOLEAN
NlAttrParse(const PNL_MSG_HDR nlMsg, UINT32 attrOffset,
            UINT32 totalAttrLen,
            const NL_POLICY policy[], const UINT32 numPolicy,
            PNL_ATTR attrs[], UINT32 numAttrs)
{
    PNL_ATTR nla;
    INT left;
    UINT32 iter;
    BOOLEAN ret = FALSE;
    UINT32 numPolicyAttr = MIN(numPolicy, numAttrs);

    RtlZeroMemory(attrs, numAttrs * sizeof *attrs);

    if ((NlMsgSize(nlMsg) < attrOffset)) {
        OVS_LOG_WARN("No attributes in nlMsg: %p at offset: %d",
                     nlMsg, attrOffset);
        goto done;
    }

    NL_ATTR_FOR_EACH (nla, left, NlMsgAt(nlMsg, attrOffset),
                      totalAttrLen)
    {
        UINT16 type = NlAttrType(nla);
        if (type < numPolicyAttr && policy[type].type != NL_A_NO_ATTR) {
            /* Typecasting to keep the compiler happy */
            const PNL_POLICY e = (const PNL_POLICY)(&policy[type]);
            if (!NlAttrValidate(nla, e)) {
                goto done;
            }

            if (attrs[type]) {
                OVS_LOG_WARN("Duplicate attribute in nlMsg: %p, "
                             "type: %u", nlMsg, type);
            }

            attrs[type] = nla;
        }
    }

    if (left) {
        OVS_LOG_ERROR("Attributes followed by garbage");
        goto done;
    }

    for (iter = 0; iter < numPolicyAttr; iter++) {
        const PNL_POLICY e = (const PNL_POLICY)(&policy[iter]);
        if (!e->optional && e->type != NL_A_NO_ATTR && !attrs[iter]) {
            OVS_LOG_ERROR("Required attr:%d missing", iter);
            goto done;
        }
    }

    ret = TRUE;

done:
    return ret;
}

/*
 *----------------------------------------------------------------------------
 * Parses the netlink message for nested attributes. attrOffset must be the
 * offset of nla which is the header of the nested attribute series.
 * Refer nl_parse_nested for more details.
 *
 * Returns BOOLEAN to indicate success/failure.
 *----------------------------------------------------------------------------
 */
BOOLEAN
NlAttrParseNested(const PNL_MSG_HDR nlMsg, UINT32 attrOffset,
                  UINT32 totalAttrLen,
                  const NL_POLICY policy[], const UINT32 numPolicy,
                  PNL_ATTR attrs[], UINT32 numAttrs)
{
    return NlAttrParse(nlMsg, attrOffset + NLA_HDRLEN,
                       totalAttrLen - NLA_HDRLEN, policy, numPolicy,
                       attrs, numAttrs);
}
