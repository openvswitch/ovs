/*
 * Copyright (c) 2011 Nicira, Inc.
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

#ifndef __SYS_WAIT_SPARSE
#define __SYS_WAIT_SPARSE 1

#include_next <sys/wait.h>

#undef wait
#define wait(a) rpl_wait(a)
pid_t rpl_wait(int *);

#undef waitpid
#define waitpid(a, b, c) rpl_waitpid(a, b, c)
pid_t rpl_waitpid(pid_t, int *, int);

#endif /* <sys/wait.h> for sparse */
