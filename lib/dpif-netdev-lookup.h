/*
 * Copyright (c) 2020 Intel Corporation.
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

#ifndef DPIF_NETDEV_LOOKUP_H
#define DPIF_NETDEV_LOOKUP_H 1

#include <config.h>
#include "dpif-netdev.h"
#include "dpif-netdev-private.h"

/* Function to perform a probe for the subtable bit fingerprint.
 * Returns NULL if not valid, or a valid function pointer to call for this
 * subtable on success.
 */
typedef
dpcls_subtable_lookup_func (*dpcls_subtable_probe_func)(uint32_t u0_bit_count,
                                                        uint32_t u1_bit_count);

/* Prototypes for subtable implementations */
dpcls_subtable_lookup_func
dpcls_subtable_autovalidator_probe(uint32_t u0_bit_count,
                                   uint32_t u1_bit_count);

/* Probe function to select a specialized version of the generic lookup
 * implementation. This provides performance benefit due to compile-time
 * optimizations such as loop-unrolling. These are enabled by the compile-time
 * constants in the specific function implementations.
 */
dpcls_subtable_lookup_func
dpcls_subtable_generic_probe(uint32_t u0_bit_count, uint32_t u1_bit_count);

/* Probe function for AVX-512 gather implementation */
dpcls_subtable_lookup_func
dpcls_subtable_avx512_gather_probe(uint32_t u0_bit_cnt, uint32_t u1_bit_cnt);


/* Subtable registration and iteration helpers */
struct dpcls_subtable_lookup_info_t {
    /* higher priority gets used over lower values. This allows deployments
     * to select the best implementation for the use-case.
     */
    uint8_t prio;

    /* Probe function: tests if the (u0,u1) combo is supported. If not
     * supported, this function returns NULL. If supported, a function pointer
     * is returned which when called will perform the lookup on the subtable.
     */
    dpcls_subtable_probe_func probe;

    /* Human readable name, used in setting subtable priority commands */
    const char *name;
};

int32_t dpcls_subtable_set_prio(const char *name, uint8_t priority);

dpcls_subtable_lookup_func
dpcls_subtable_get_best_impl(uint32_t u0_bit_count, uint32_t u1_bit_count);

/* Retrieve the array of lookup implementations for iteration.
 * On error, returns a negative number.
 * On success, returns the size of the arrays pointed to by the out parameter.
 */
int32_t
dpcls_subtable_lookup_info_get(struct dpcls_subtable_lookup_info_t **out_ptr);

#endif /* dpif-netdev-lookup.h */
