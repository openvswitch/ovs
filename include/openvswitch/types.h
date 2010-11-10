/*
 * Copyright (c) 2010 Nicira Networks.
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

#ifndef OPENVSWITCH_TYPES_H
#define OPENVSWITCH_TYPES_H 1

#include <stdint.h>

#ifdef __CHECKER__
#define OVS_BITWISE __attribute__((bitwise))
#define OVS_FORCE __attribute__((force))
#else
#define OVS_BITWISE
#define OVS_FORCE
#endif

/* The ovs_be<N> types indicate that an object is in big-endian, not
 * native-endian, byte order.  They are otherwise equivalent to uint<N>_t.
 *
 * The OVS_BITWISE annotation allows the sparse checker to issue warnings
 * for incorrect use of values in network byte order. */
typedef uint16_t OVS_BITWISE ovs_be16;
typedef uint32_t OVS_BITWISE ovs_be32;
typedef uint64_t OVS_BITWISE ovs_be64;

#endif /* openvswitch/types.h */
