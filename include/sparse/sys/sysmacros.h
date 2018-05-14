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

#ifndef __SYS_SYSMACROS_SPARSE
#define __SYS_SYSMACROS_SPARSE 1

/* "sparse" doesn't like the large constants in <bits/sysmacros.h>, complaining
 * that they are so large that they have type "unsigned long long".  This
 * header avoids the problem. */

unsigned int major(dev_t);
unsigned int minor(dev_t);
dev_t makedev(unsigned int, unsigned int);

#endif /* <sys/sysmacros.h> for sparse */
