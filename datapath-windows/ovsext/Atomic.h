/*
 * Copyright (c) 2014 VMware, Inc.
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

#ifndef __ATOMIC_H_
#define __ATOMIC_H_ 1

static __inline UINT64
atomic_add64(UINT64 *ptr, UINT32 val)
{
    return InterlockedAdd64((LONGLONG volatile *) ptr, (LONGLONG) val);
}

static __inline UINT64
atomic_inc64(UINT64 *ptr)
{
    return InterlockedIncrement64((LONGLONG volatile *) ptr);
}

#endif /* __ATOMIC_H_ */
