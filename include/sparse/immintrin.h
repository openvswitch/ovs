/* Copyright (c) 2024 Red Hat, Inc.
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

#ifndef __CHECKER__
#error "Use this header only with sparse.  It is not a correct implementation."
#endif

/* Sparse doesn't know some types used by AVX512 and some other headers.
 * Mark those headers as already included to avoid failures.  This is fragile,
 * so may need adjustments with compiler changes. */
#define _AVX512BF16INTRIN_H_INCLUDED
#define _AVX512BF16VLINTRIN_H_INCLUDED
#define _AVXNECONVERTINTRIN_H_INCLUDED
#define _KEYLOCKERINTRIN_H_INCLUDED
#define __AVX512FP16INTRIN_H_INCLUDED
#define __AVX512FP16VLINTRIN_H_INCLUDED
/* GCC >=14 changed the '__AVX512FP16INTRIN_H_INCLUDED' to have only single
 * underscore.  We need both to keep compatibility between various GCC
 * versions. */
#define _AVX512FP16INTRIN_H_INCLUDED

#include_next <immintrin.h>
