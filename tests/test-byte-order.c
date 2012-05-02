/*
 * Copyright (c) 2010, 2011 Nicira, Inc.
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

#include <config.h>
#include "byte-order.h"
#include <assert.h>
#include <inttypes.h>

int
main(void)
{
#ifndef __CHECKER__
    /* I picked some random numbers. */
    const uint16_t s = 0xc9bd;
    const uint32_t l = 0xffe56ae8;
    const uint64_t ll = UINT64_C(0xb6fe878a9117ecdb);

    assert(htons(ntohs(s)) == s);
    assert(ntohs(htons(s)) == s);
    assert(CONSTANT_HTONS(ntohs(s)) == s);
    assert(ntohs(CONSTANT_HTONS(s)) == s);
    assert(ntohs(CONSTANT_HTONS(l)) == (uint16_t) l);
    assert(ntohs(CONSTANT_HTONS(ll)) == (uint16_t) ll);

    assert(htonl(ntohl(l)) == l);
    assert(ntohl(htonl(l)) == l);
    assert(CONSTANT_HTONL(ntohl(l)) == l);
    assert(ntohl(CONSTANT_HTONL(l)) == l);
    assert(ntohl(CONSTANT_HTONL(ll)) == (uint32_t) ll);

    assert(htonll(ntohll(ll)) == ll);
    assert(ntohll(htonll(ll)) == ll);
    assert(CONSTANT_HTONLL(ntohll(ll)) == ll);
    assert(ntohll(CONSTANT_HTONLL(ll)));
#else  /* __CHECKER__ */
/* Making sparse happy with this code makes it unreadable, so don't bother. */
#endif

    return 0;
}
