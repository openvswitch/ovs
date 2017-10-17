/* Copyright (c) 2008, 2009, 2010 Nicira, Inc.
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

#ifndef OPENVSWITCH_UUID_H
#define OPENVSWITCH_UUID_H 1

#include "openvswitch/util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UUID_BIT 128            /* Number of bits in a UUID. */
#define UUID_OCTET (UUID_BIT / 8) /* Number of bytes in a UUID. */

/* A Universally Unique IDentifier (UUID) compliant with RFC 4122.
 *
 * Each of the parts is stored in host byte order, but the parts themselves are
 * ordered from left to right.  That is, (parts[0] >> 24) is the first 8 bits
 * of the UUID when output in the standard form, and (parts[3] & 0xff) is the
 * final 8 bits. */
struct uuid {
    uint32_t parts[4];
};
BUILD_ASSERT_DECL(sizeof(struct uuid) == UUID_OCTET);

#ifdef __cplusplus
}
#endif

#endif /* uuid.h */
