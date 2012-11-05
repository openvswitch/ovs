/*
 * Copyright (c) 2008, 2011 Nicira, Inc.
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

ovs_be16 csum(const void *, size_t);
uint32_t csum_add16(uint32_t partial, ovs_be16);
uint32_t csum_add32(uint32_t partial, ovs_be32);
uint32_t csum_continue(uint32_t partial, const void *, size_t);
ovs_be16 csum_finish(uint32_t partial);
ovs_be16 recalc_csum16(ovs_be16 old_csum, ovs_be16 old_u16, ovs_be16 new_u16);
ovs_be16 recalc_csum32(ovs_be16 old_csum, ovs_be32 old_u32, ovs_be32 new_u32);
ovs_be16 recalc_csum128(ovs_be16 old_csum, ovs_be32 old_u32[4],
                        const ovs_be32 new_u32[4]);

#endif /* csum.h */
