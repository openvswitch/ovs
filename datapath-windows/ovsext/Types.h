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

#ifndef __TYPES_H_
#define __TYPES_H_ 1

/* Defines the userspace specific data types
 * for files included from user space. */
typedef unsigned long long uint64, uint64_t, ovs_be64, u64;
typedef long long int64, int64_t;
typedef unsigned int uint32, uint32_t, ovs_be32, u32;
typedef unsigned short uint16, uint16_t, ovs_be16, u16;
typedef unsigned char uint8, uint8_t, u8;
typedef uint64 __u64, __be64;
typedef uint32 __u32, __be32;
typedef uint16 __u16, __be16;
typedef uint8 __u8;

/* Defines the  userspace specific data types for file
 * included within kernel only. */
typedef UINT8 BE8;
typedef UINT16 BE16;
typedef UINT32 BE32;
typedef UINT64 BE64;

#define ETH_ALEN 6

#define SIZE_MAX MAXUINT32

#endif /* __TYPES_H_ */
