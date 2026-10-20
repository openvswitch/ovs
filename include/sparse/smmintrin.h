/* Copyright (c) 2026 Red Hat, LLC.
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

#define __builtin_ia32_crc32si(crc, value) ((unsigned int) 0)
#define __builtin_ia32_crc32di(crc, value) ((unsigned long long) 0)

/* Get actual <smmintrin.h> definitions for us to annotate and build on. */
#include_next <smmintrin.h>
