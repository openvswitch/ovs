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

/* ==========================================================================
 * This is a simple buffer mangement framework specific for netlink protocol.
 * The name could be confused with ovsext/BufferMgmt.c. Ovsext/BufferMgmt.c
 * deals with buffer mgmt for NBLs. Where as this framework deals with
 * management of buffer that holds a netlink message.
 *
 * This framework provides APIs for putting/accessing data in a buffer. These
 * APIs are used by driver's netlink protocol implementation.
 *
 * We can see this framework as a subset of ofpbuf in ovs userspace.
 *
 * This framework is NOT a generic buffer management framework (ofpbuf
 * is a generic buffer mgmt framework) and provides only the functioanlities
 * which would be useful for netlink protocol. Some of the key features are:
 *
 * a. It DOES NOT support automatic buffer reallocation.
 *    i. A netlink input/output message is a static buffer.
 * b. The unused space is at the tail.
 * c. There is no notion of headdroom.
 * ==========================================================================
 */
#include <ndis.h>
#include <netiodef.h>
#include <intsafe.h>
#include <ntintsafe.h>
#include <ntstrsafe.h>
#include <Strsafe.h>

#ifdef OVS_DBG_MOD
#undef OVS_DBG_MOD
#endif
#define OVS_DBG_MOD OVS_DBG_NETLINK
#include "Debug.h"
#include "NetlinkBuf.h"

/* Returns used space in the buffer */
#define NL_BUF_USED_SPACE(_buf)                   (_buf->bufLen -            \
                                                   _buf->bufRemLen)

/* Validates that offset is within buffer boundaries and will not
 * create holes in the buffer.*/
#define NL_BUF_IS_VALID_OFFSET(_buf, _offset)     (_offset <=                \
                                                   NL_BUF_TAIL_OFFSET(_buf) ? 1 : 0)

/* Validates if new data of size _size can be added at offset _offset.
 * This macor assumes that offset validation has been done.*/
#define NL_BUF_CAN_ADD(_buf, _size, _offset)      (((_offset + _size <=      \
                                                  _buf->bufLen) && (_size    \
                                                  <= _buf->bufRemLen)) ?     \
                                                  1 : 0)

/* Returns the offset of tail wrt buffer head */
#define NL_BUF_TAIL_OFFSET(_buf)                  (_buf->tail - _buf->head)

static __inline VOID
_NlBufCopyAtTailUnsafe(PNL_BUFFER nlBuf, PCHAR data, UINT32 len);
static __inline VOID
_NlBufCopyAtOffsetUnsafe(PNL_BUFFER nlBuf, PCHAR data,
                         UINT32 len, UINT32 offset);

/*
 * --------------------------------------------------------------------------
 * NlBufInit --
 *
 *    Initializes NL_BUF with buffer pointer and length.
 * --------------------------------------------------------------------------
 */
VOID
NlBufInit(PNL_BUFFER nlBuf, PCHAR base, UINT32 size)
{
    ASSERT(nlBuf);
    nlBuf->head = nlBuf->tail = base;
    nlBuf->bufLen = nlBuf->bufRemLen = size;
}

/*
 * --------------------------------------------------------------------------
 * NlBufDeInit --
 *
 *    Resets the buffer variables to NULL.
 * --------------------------------------------------------------------------
 */
VOID
NlBufDeInit(PNL_BUFFER nlBuf)
{
    ASSERT(nlBuf);
    nlBuf->head = nlBuf->tail = NULL;
    nlBuf->bufLen = nlBuf->bufRemLen = 0;
}

/*
 * --------------------------------------------------------------------------
 * NlBufCopyAtTail --
 *
 *    Copies the data to the tail end of the buffer.
 * --------------------------------------------------------------------------
 */
BOOLEAN
NlBufCopyAtTail(PNL_BUFFER nlBuf, PCHAR data, UINT32 len)
{
    BOOLEAN ret = TRUE;

    ASSERT(nlBuf);

    /* Check if we have enough space */
    if (!NL_BUF_CAN_ADD(nlBuf, len, NL_BUF_TAIL_OFFSET(nlBuf))) {
        ret = FALSE;
        goto done;
    }

    _NlBufCopyAtTailUnsafe(nlBuf, data, len);

done:
    return ret;
}

/*
 * --------------------------------------------------------------------------
 * NlBufCopyAtHead --
 *
 *    Copies the data to the head of the buffer.
 *    It can be seen as special case of NlBufCopyAtOffset with input
 *    offset zero.
 * --------------------------------------------------------------------------
 */
BOOLEAN
NlBufCopyAtHead(PNL_BUFFER nlBuf, PCHAR data, UINT32 len)
{
    BOOLEAN ret = TRUE;

    ASSERT(nlBuf);

    /* Check if we have enough space */
    if (!NL_BUF_CAN_ADD(nlBuf, len, 0)) {
        ret = FALSE;
        goto done;
    }

    if (nlBuf->head == nlBuf->tail) {
        /* same as inserting in tail */
        _NlBufCopyAtTailUnsafe(nlBuf, data, len);
        goto done;
    }

    _NlBufCopyAtOffsetUnsafe(nlBuf, data, len, 0);

done:
    return ret;
}

/*
 * --------------------------------------------------------------------------
 * NlBufCopyAtOffset --
 *
 *    Inserts data at input offset in the buffer.
 *    If the offset is earlier then tail end then it first creates
 *    space of size input length at input offset by moving the existing
 *    data forward.
 * --------------------------------------------------------------------------
 */
BOOLEAN
NlBufCopyAtOffset(PNL_BUFFER nlBuf, PCHAR data, UINT32 len, UINT32 offset)
{
    PCHAR dest = NULL;
    BOOLEAN ret = TRUE;

    ASSERT(nlBuf);

    /* Check if input offset is valid and has enough space */
    if ((!NL_BUF_IS_VALID_OFFSET(nlBuf, offset)) ||
        (!NL_BUF_CAN_ADD(nlBuf, len, offset))) {
        ret = FALSE;
        goto done;
    }

    dest = nlBuf->head + offset;

    if (dest == nlBuf->tail) {
        /* same as inserting in tail */
        _NlBufCopyAtTailUnsafe(nlBuf, data, len);
        goto done;
    }

    _NlBufCopyAtOffsetUnsafe(nlBuf, data, len, offset);

done:
    return ret;
}

/*
 * --------------------------------------------------------------------------
 * NlBufCopyAtTailUninit --
 *
 *    Memsets the buffer portion of length len at tail end with zero.
 * --------------------------------------------------------------------------
 */
PCHAR
NlBufCopyAtTailUninit(PNL_BUFFER nlBuf, UINT32 len)
{
    PCHAR ret;

    ret = nlBuf->tail;
    if ((NlBufCopyAtTail(nlBuf, NULL, len)) == FALSE) {
        ret = NULL;
    }

    return ret;
}

/*
 * --------------------------------------------------------------------------
 * NlBufCopyAtHeadUninit --
 *
 *    Memsets the buffer portion of length len at head with zero.
 * --------------------------------------------------------------------------
 */
PCHAR
NlBufCopyAtHeadUninit(PNL_BUFFER nlBuf, UINT32 len)
{
    PCHAR ret = NULL;

    if ((NlBufCopyAtHead(nlBuf, NULL, len)) == FALSE) {
        goto done;
    }

    ret = nlBuf->head;

done:
    return ret;
}

/*
 * --------------------------------------------------------------------------
 * NlBufCopyAtOffsetUninit --
 *
 *    Memsets the buffer portion of length len at head with zero.
 *
 *    If the offset is earlier then tail end then it first creates
 *    space of size input length at input offset by moving the existing
 *    data forward.
 * --------------------------------------------------------------------------
 */
PCHAR
NlBufCopyAtOffsetUninit(PNL_BUFFER nlBuf, UINT32 len, UINT32 offset)
{
    PCHAR ret = NULL;

    if ((NlBufCopyAtOffset(nlBuf, NULL, len, offset)) == FALSE) {
        goto done;
    }

    ret = nlBuf->head + offset;

done:
    return ret;
}

/*
 * --------------------------------------------------------------------------
 * NlBufAt --
 *
 *    Returns pointer to buffer at input offset.
 *    bufLen is used to verify that expected data length
 *    is within valid boundaries. Here by boundaries we mean
 *    within head and tail.
 * --------------------------------------------------------------------------
 */
PCHAR
NlBufAt(PNL_BUFFER nlBuf, UINT32 offset, UINT32 bufLen)
{
    PCHAR ret = NULL;

    ASSERT(nlBuf);

    if ((!NL_BUF_IS_VALID_OFFSET(nlBuf, offset))) {
        goto done;
    }

    /* Check if requested buffer is within head and tail */
    if ((offset + bufLen) > NL_BUF_USED_SPACE(nlBuf)) {
        goto done;
    }

    ret = nlBuf->head + offset;
done:
    return ret;
}

/* *_Unsafe functions does not do any validation. */

/*
 * --------------------------------------------------------------------------
 * _NlBufCopyAtTailUnsafe --
 *
 *    Helper function for NlBufCopyAtTail.
 * --------------------------------------------------------------------------
 */
static __inline VOID
_NlBufCopyAtTailUnsafe(PNL_BUFFER nlBuf, PCHAR data, UINT32 len)
{
    if (data) {
        RtlCopyMemory(nlBuf->tail, data, len);
    } else {
        RtlZeroMemory(nlBuf->tail, len);
    }

    nlBuf->tail += len;
    nlBuf->bufRemLen -= len;
}

/*
 * --------------------------------------------------------------------------
 * _NlBufCopyAtOffsetUnsafe --
 *
 *    Helper function for NlBufCopyAtOffset.
 * --------------------------------------------------------------------------
 */
static __inline VOID
_NlBufCopyAtOffsetUnsafe(PNL_BUFFER nlBuf, PCHAR data,
                         UINT32 len, UINT32 offset)
{
    PCHAR dest = NULL;

    dest = nlBuf->head + offset;

    RtlMoveMemory(dest+len, dest, NL_BUF_USED_SPACE(nlBuf) - offset);

    if (data) {
        RtlCopyMemory(dest, data, len);
    } else {
        RtlZeroMemory(dest, len);
    }

    nlBuf->tail += len;
    nlBuf->bufRemLen -= len;
}
