/*
 * Copyright (c) 2008, 2011, 2015 Nicira, Inc.
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

#ifndef CSUM_H
#define CSUM_H 1

#include <stddef.h>
#include <stdint.h>
#include "openvswitch/types.h"

struct in6_addr;

ovs_be16 csum(const void *, size_t);
uint32_t csum_continue(uint32_t partial, const void *, size_t);
ovs_be16 csum_finish(uint32_t partial);
ovs_be16 recalc_csum16(ovs_be16 old_csum, ovs_be16 old_u16, ovs_be16 new_u16);
ovs_be16 recalc_csum32(ovs_be16 old_csum, ovs_be32 old_u32, ovs_be32 new_u32);
ovs_be16 recalc_csum48(ovs_be16 old_csum, const struct eth_addr old_mac,
                       const struct eth_addr new_mac);
ovs_be16 recalc_csum128(ovs_be16 old_csum, ovs_16aligned_be32 old_u32[4],
                        const struct in6_addr *);

#ifndef __CHECKER__
/* Adds the 16 bits in 'new' to the partial IP checksum 'partial' and returns
 * the updated checksum.  (To start a new checksum, pass 0 for 'partial'.  To
 * obtain the finished checksum, pass the return value to csum_finish().) */
static inline uint32_t
csum_add16(uint32_t partial, ovs_be16 new)
{
    return partial + new;
}

/* Adds the 32 bits in 'new' to the partial IP checksum 'partial' and returns
 * the updated checksum.  (To start a new checksum, pass 0 for 'partial'.  To
 * obtain the finished checksum, pass the return value to csum_finish().) */
static inline uint32_t
csum_add32(uint32_t partial, ovs_be32 new)
{
    return partial + (new >> 16) + (new & 0xffff);
}
#else
uint32_t csum_add16(uint32_t partial, ovs_be16);
uint32_t csum_add32(uint32_t partial, ovs_be32);
#endif

#endif /* csum.h */
