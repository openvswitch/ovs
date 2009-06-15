/*
 * Copyright (c) 2008 Nicira Networks.
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

uint16_t csum(const void *, size_t);
uint32_t csum_add16(uint32_t partial, uint16_t);
uint32_t csum_add32(uint32_t partial, uint32_t);
uint32_t csum_continue(uint32_t partial, const void *, size_t);
uint16_t csum_finish(uint32_t partial);
uint16_t recalc_csum16(uint16_t old_csum, uint16_t old_u16, uint16_t new_u16);
uint16_t recalc_csum32(uint16_t old_csum, uint32_t old_u32, uint32_t new_u32);

#endif /* csum.h */
