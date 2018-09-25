/*
 * Copyright (c) 2018 Nicira, Inc.
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

#ifndef __BITS_FLOATN_SPARSE
#define __BITS_FLOATN_SPARSE 1

/* "sparse" claims to be a recent version of GCC but doesn't support IEEE 754
 * binary128, so we define macros to make that clear. */

#define __HAVE_FLOAT128 0
#define __HAVE_FLOAT64X 0

#ifdef HAVE_BITS_FLOATN_COMMON_H
/* Introduced in glibc 2.27 */
#include <bits/floatn-common.h>
#endif

#endif /* <bits/floatn.h> for sparse */
