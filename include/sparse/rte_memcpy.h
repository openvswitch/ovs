/* Copyright (c) 2017 Nicira, Inc.
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

#ifndef RTE_MEMCPY_H
#define RTE_MEMCPY_H 1

#ifndef __CHECKER__
#error "Use this header only with sparse.  It is not a correct implementation."
#endif

/* Include the same headers as the real rte_memcpy(). */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <rte_vect.h>

/* Declare the same functions as the real rte_memcpy.h, without defining them.
 * This gives sparse the information it needs without provoking sparse's
 * complaints about the implementations. */
void rte_mov16(uint8_t *, const uint8_t *);
void rte_mov32(uint8_t *, const uint8_t *);
void rte_mov64(uint8_t *, const uint8_t *);
void rte_mov128(uint8_t *, const uint8_t *);
void rte_mov256(uint8_t *, const uint8_t *);
void *rte_memcpy(void *, const void *, size_t);

#endif  /* RTE_MEMCPY_H_WRAPPER */
