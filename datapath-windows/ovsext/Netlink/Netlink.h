/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013, 2014 Nicira, Inc.
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

#ifndef __NETLINK_H_
#define __NETLINK_H_ 1

#include "Types.h"
#include "NetlinkProto.h"
#include "NetlinkBuf.h"
#include "..\..\include\OvsDpInterface.h"

/*
 * Structure of any message passed between userspace and kernel.
 */
typedef struct _OVS_MESSAGE {
    NL_MSG_HDR nlMsg;
    GENL_MSG_HDR genlMsg;
    OVS_HDR ovsHdr;
    /* Variable length nl_attrs follow. */
} OVS_MESSAGE, *POVS_MESSAGE;

/*
 * Structure of an error message sent as a reply from kernel.
 */
typedef struct _OVS_MESSAGE_ERROR {
    NL_MSG_HDR nlMsg;
    NL_MSG_ERR errorMsg;
} OVS_MESSAGE_ERROR, *POVS_MESSAGE_ERROR;

/* Netlink attribute types. */
typedef enum
{
    NL_A_NO_ATTR = 0,
    NL_A_VAR_LEN,
    NL_A_UNSPEC,
    NL_A_U8,
    NL_A_U16,
    NL_A_BE16 = NL_A_U16,
    NL_A_U32,
    NL_A_BE32 = NL_A_U32,
    NL_A_U64,
    NL_A_BE64 = NL_A_U64,
    NL_A_STRING,
    NL_A_FLAG,
    NL_A_NESTED,
    N_NL_ATTR_TYPES
} NL_ATTR_TYPE;

/* Netlink attribute policy.
 * Specifies the policy for parsing for netlink attribute. */
typedef struct _NL_POLICY
{
    NL_ATTR_TYPE type;
    UINT32 minLen;
    UINT32 maxLen;
    BOOLEAN optional;
} NL_POLICY, *PNL_POLICY;

/* This macro is careful to check for attributes with bad lengths. */
#define NL_ATTR_FOR_EACH(ITER, LEFT, ATTRS, ATTRS_LEN)                  \
    for ((ITER) = (ATTRS), (LEFT) = (ATTRS_LEN);                        \
         NlAttrIsValid(ITER, LEFT);                                     \
         (LEFT) -= NlAttrLenPad(ITER, LEFT), (ITER) = NlAttrNext(ITER))

/* This macro does not check for attributes with bad lengths.  It should only
 * be used with messages from trusted sources or with messages that have
 * already been validated (e.g. with NL_ATTR_FOR_EACH).  */
#define NL_ATTR_FOR_EACH_UNSAFE(ITER, LEFT, ATTRS, ATTRS_LEN)           \
    for ((ITER) = (ATTRS), (LEFT) = (ATTRS_LEN);                        \
         (LEFT) > 0;                                                    \
         (LEFT) -= NLA_ALIGN((ITER)->nlaLen), (ITER) = NlAttrNext(ITER))

#define NL_ATTR_GET_AS(NLA, TYPE) \
        (*(TYPE*) NlAttrGetUnspec(nla, sizeof(TYPE)))

BOOLEAN NlFillOvsMsg(PNL_BUFFER nlBuf,
                     UINT16 nlmsgType, UINT16 nlmsgFlags,
                     UINT32 nlmsgSeq, UINT32 nlmsgPid,
                     UINT8 genlCmd, UINT8 genlVer, UINT32 dpNo);
BOOLEAN NlFillNlHdr(PNL_BUFFER nlBuf,
                    UINT16 nlmsgType, UINT16 nlmsgFlags,
                    UINT32 nlmsgSeq, UINT32 nlmsgPid);

VOID NlBuildErrorMsg(POVS_MESSAGE msgIn, POVS_MESSAGE_ERROR msgOut,
                     UINT errorCode);

/* Netlink message accessing the payload */
PVOID NlMsgAt(const PNL_MSG_HDR nlh, UINT32 offset);
UINT32 NlMsgSize(const PNL_MSG_HDR nlh);
VOID NlMsgAlignSize(const PNL_MSG_HDR nlh);
VOID NlMsgSetSize(const PNL_MSG_HDR nlh, UINT32 msgLen);
PCHAR NlHdrPayload(const PNL_MSG_HDR nlh);
UINT32 NlHdrPayloadLen(const PNL_MSG_HDR nlh);
PNL_ATTR NlMsgAttrs(const PNL_MSG_HDR nlh);
UINT32 NlMsgAttrsLen(const PNL_MSG_HDR nlh);

/* Netlink message parse */
PNL_MSG_HDR NlMsgNext(const PNL_MSG_HDR nlh);
INT NlAttrIsValid(const PNL_ATTR nla, UINT32 maxlen);
UINT32 NlAttrLenPad(const PNL_ATTR nla, UINT32 maxlen);

/* Netlink attribute parsing. */
UINT32 NlAttrMinLen(NL_ATTR_TYPE type);
UINT32 NlAttrMinLen(NL_ATTR_TYPE type);
PNL_ATTR NlAttrNext(const PNL_ATTR nla);
UINT16 NlAttrType(const PNL_ATTR nla);
PVOID NlAttrData(const PNL_ATTR nla);
UINT32 NlAttrGetSize(const PNL_ATTR nla);
const PVOID NlAttrGet(const PNL_ATTR nla);
const PVOID NlAttrGetUnspec(const PNL_ATTR nla, UINT32 size);
BE64 NlAttrGetBe64(const PNL_ATTR nla);
BE32 NlAttrGetBe32(const PNL_ATTR nla);
UINT8 NlAttrGetU8(const PNL_ATTR nla);
UINT16 NlAttrGetU16(const PNL_ATTR nla);
UINT32 NlAttrGetU32(const PNL_ATTR nla);
UINT64 NlAttrGetU64(const PNL_ATTR nla);
const PNL_ATTR NlAttrFind__(const PNL_ATTR attrs,
                            UINT32 size, UINT16 type);
const PNL_ATTR NlAttrFindNested(const PNL_ATTR nla,
                                UINT16 type);
BOOLEAN NlAttrParse(const PNL_MSG_HDR nlMsg, UINT32 attrOffset,
                    UINT32 totalAttrLen, const NL_POLICY policy[],
                    PNL_ATTR attrs[], UINT32 n_attrs);
BOOLEAN NlAttrParseNested(const PNL_MSG_HDR nlMsg, UINT32 attrOffset,
                          UINT32 totalAttrLen, const NL_POLICY policy[],
                          PNL_ATTR attrs[], UINT32 n_attrs);
/*
 * --------------------------------------------------------------------------
 * Returns the length of attribute.
 * --------------------------------------------------------------------------
 */
static __inline UINT16
NlAttrLen(const PNL_ATTR nla)
{
    return nla->nlaLen;
}

/*
 * ---------------------------------------------------------------------------
 * Default maximum payload size for each type of attribute.
 * ---------------------------------------------------------------------------
 */
UINT32
static __inline NlAttrSize(UINT32 payloadSize)
{
    return NLA_HDRLEN + payloadSize;
}

/*
 * ---------------------------------------------------------------------------
 * Total length including padding.
 * ---------------------------------------------------------------------------
 */
UINT32
static __inline NlAttrTotalSize(UINT32 payloadSize)
{
    return NLA_ALIGN(NlAttrSize(payloadSize));
}

/* Netlink attribute validation */
BOOLEAN NlAttrValidate(const PNL_ATTR, const PNL_POLICY);

/* Put APis */
BOOLEAN NlMsgPutNlHdr(PNL_BUFFER buf, PNL_MSG_HDR nlMsg);
BOOLEAN NlMsgPutGenlHdr(PNL_BUFFER buf, PGENL_MSG_HDR genlMsg);
BOOLEAN NlMsgPutOvsHdr(PNL_BUFFER buf, POVS_HDR ovsHdr);

BOOLEAN NlMsgPutTail(PNL_BUFFER buf, const PCHAR data, UINT32 len);
PCHAR NlMsgPutTailUninit(PNL_BUFFER buf, UINT32 len);
PCHAR NlMsgPutTailUnspecUninit(PNL_BUFFER buf, UINT16 type, UINT16 len);
BOOLEAN NlMsgPutTailUnspec(PNL_BUFFER buf, UINT16 type, PCHAR data, UINT16 len);
BOOLEAN NlMsgPutTailFlag(PNL_BUFFER buf, UINT16 type);
BOOLEAN NlMsgPutTailU8(PNL_BUFFER buf, UINT16 type, UINT8 value);
BOOLEAN NlMsgPutTailU16(PNL_BUFFER buf, UINT16 type, UINT16 value);
BOOLEAN NlMsgPutTailU32(PNL_BUFFER buf, UINT16 type, UINT32 value);
BOOLEAN NlMsgPutTailU64(PNL_BUFFER buf, UINT16 type, UINT64 value);
BOOLEAN NlMsgPutTailString(PNL_BUFFER buf, UINT16 type, PCHAR value);

BOOLEAN NlMsgPutHead(PNL_BUFFER buf, const PCHAR data, UINT32 len);
PCHAR NlMsgPutHeadUninit(PNL_BUFFER buf, UINT32 len);
PCHAR NlMsgPutHeadUnspecUninit(PNL_BUFFER buf, UINT16 type, UINT16 len);
BOOLEAN NlMsgPutHeadUnspec(PNL_BUFFER buf, UINT16 type, PCHAR data, UINT16 len);
BOOLEAN NlMsgPutHeadFlag(PNL_BUFFER buf, UINT16 type);
BOOLEAN NlMsgPutHeadU8(PNL_BUFFER buf, UINT16 type, UINT8 value);
BOOLEAN NlMsgPutHeadU16(PNL_BUFFER buf, UINT16 type, UINT16 value);
BOOLEAN NlMsgPutHeadU32(PNL_BUFFER buf, UINT16 type, UINT32 value);
BOOLEAN NlMsgPutHeadU64(PNL_BUFFER buf, UINT16 type, UINT64 value);
BOOLEAN NlMsgPutHeadString(PNL_BUFFER buf, UINT16 type, PCHAR value);
UINT32 NlMsgStartNested(PNL_BUFFER buf, UINT16 type);
VOID NlMsgEndNested(PNL_BUFFER buf, UINT32 offset);
VOID NlMsgPutNested(PNL_BUFFER buf, UINT16 type,
                    const PVOID data, UINT32 size);

/* These variants are convenient for iterating nested attributes. */
#define NL_NESTED_FOR_EACH(ITER, LEFT, A)                               \
    NL_ATTR_FOR_EACH(ITER, LEFT, NlAttrGet(A), NlAttrGetSize(A))
#define NL_NESTED_FOR_EACH_UNSAFE(ITER, LEFT, A)                        \
    NL_ATTR_FOR_EACH_UNSAFE(ITER, LEFT, NlAttrGet(A), NlAttrGetSize(A))

#endif /* __NETLINK_H_ */
