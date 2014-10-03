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

#ifndef __NETLINK_BUF_H_
#define __NETLINK_BUF_H_ 1

typedef struct _NL_BUF {
    PCHAR head;         /* start address of the buffer */
    PCHAR tail;         /* first empty byte of the buffer */
    UINT32 bufLen;      /* original length of buffer */
    UINT32 bufRemLen;   /* remaining length of buffer */
} NL_BUFFER, *PNL_BUFFER;

VOID NlBufInit(PNL_BUFFER nlBuf, PCHAR base, UINT32 size);
VOID NlBufDeInit(PNL_BUFFER nlBuf);

BOOLEAN NlBufCopyAtTail(PNL_BUFFER nlBuf, PCHAR data, UINT32 len);
BOOLEAN NlBufCopyAtHead(PNL_BUFFER nlBuf, PCHAR data, UINT32 len);
BOOLEAN NlBufCopyAtOffset(PNL_BUFFER nlBuf, PCHAR data,
                          UINT32 len, UINT32 offset);

PCHAR NlBufCopyAtTailUninit(PNL_BUFFER nlBuf, UINT32 len);
PCHAR NlBufCopyAtHeadUninit(PNL_BUFFER nlBuf, UINT32 len);
PCHAR NlBufCopyAtOffsetUninit(PNL_BUFFER nlBuf, UINT32 len, UINT32 offset);

PCHAR NlBufAt(PNL_BUFFER nlBuf, UINT32 offset, UINT32 len);

/*
 * --------------------------------------------------------------------------
 * NlBufSize --
 *
 *    Returns the used size of buffer.
 * --------------------------------------------------------------------------
 */
static __inline UINT32
NlBufSize(PNL_BUFFER nlBuf)
{
    ASSERT(nlBuf);
    return (nlBuf->bufLen - nlBuf->bufRemLen);
}

/*
 * --------------------------------------------------------------------------
 * NlBufRemLen --
 *
 *    Returns the unused size of buffer.
 * --------------------------------------------------------------------------
 */
static __inline UINT32
NlBufRemLen(PNL_BUFFER nlBuf)
{
    ASSERT(nlBuf);
    return (nlBuf->bufRemLen);
}

#endif /* __NETLINK_BUF_H_ */
