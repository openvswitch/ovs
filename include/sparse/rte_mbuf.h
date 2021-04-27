/* Copyright (c) 2020 Intel, Inc.
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

/* sparse doesn't know about gcc atomic builtins. */
#ifndef __ATOMIC_ACQ_REL
#define __ATOMIC_ACQ_REL 0
#define __ATOMIC_RELAXED 1
#define __atomic_add_fetch(p, val, memorder) (*(p) = *(p) + (val))
#define __atomic_store_n(p, val, memorder) (*(p) = (val))
#endif

/* Get actual <rte_mbuf.h> definitions for us to annotate and build on. */
#include_next <rte_mbuf.h>
