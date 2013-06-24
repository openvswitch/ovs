/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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

#ifndef COMPILER_H
#define COMPILER_H 1

#if __GNUC__ && !__CHECKER__
#define NO_RETURN __attribute__((__noreturn__))
#define OVS_UNUSED __attribute__((__unused__))
#define PRINTF_FORMAT(FMT, ARG1) __attribute__((__format__(printf, FMT, ARG1)))
#define STRFTIME_FORMAT(FMT) __attribute__((__format__(__strftime__, FMT, 0)))
#define MALLOC_LIKE __attribute__((__malloc__))
#define ALWAYS_INLINE __attribute__((always_inline))
#define WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#define SENTINEL(N) __attribute__((sentinel(N)))
#define OVS_LIKELY(CONDITION) __builtin_expect(!!(CONDITION), 1)
#define OVS_UNLIKELY(CONDITION) __builtin_expect(!!(CONDITION), 0)
#else
#define NO_RETURN
#define OVS_UNUSED
#define PRINTF_FORMAT(FMT, ARG1)
#define STRFTIME_FORMAT(FMT)
#define MALLOC_LIKE
#define ALWAYS_INLINE
#define WARN_UNUSED_RESULT
#define SENTINEL(N)
#define OVS_LIKELY(CONDITION) (!!(CONDITION))
#define OVS_UNLIKELY(CONDITION) (!!(CONDITION))
#endif

#ifdef __CHECKER__
/* "sparse" annotations for mutexes and mutex-like constructs.
 *
 * In a function prototype, OVS_ACQUIRES(MUTEX) indicates that the function
 * must be called without MUTEX acquired and that it returns with MUTEX
 * acquired.  OVS_RELEASES(MUTEX) indicates the reverse.  OVS_MUST_HOLD
 * indicates that the function must be called with MUTEX acquired by the
 * caller and that the function does not release MUTEX.
 *
 * In practice, sparse ignores the MUTEX argument.  It need not even be a
 * valid expression.  It is meant to indicate to human readers what mutex is
 * being acquired.
 *
 * Since sparse ignores MUTEX, it need not be an actual mutex.  It can be
 * any construct on which paired acquire and release semantics make sense:
 * read/write locks, temporary memory allocations, whatever.
 *
 * OVS_ACQUIRE, OVS_RELEASE, and OVS_HOLDS are suitable for use within macros,
 * where there is no function prototype to annotate. */
#define OVS_ACQUIRES(MUTEX) __attribute__((context(MUTEX, 0, 1)))
#define OVS_RELEASES(MUTEX) __attribute__((context(MUTEX, 1, 0)))
#define OVS_MUST_HOLD(MUTEX) __attribute__((context(MUTEX, 1, 1)))
#define OVS_ACQUIRE(MUTEX) __context__(MUTEX, 0, 1)
#define OVS_RELEASE(MUTEX) __context__(MUTEX, 1, 0)
#define OVS_HOLDS(MUTEX) __context__(MUTEX, 1, 1)
#else
#define OVS_ACQUIRES(MUTEX)
#define OVS_RELEASES(MUTEX)
#define OVS_MUST_HOLD(MUTEX)
#define OVS_ACQUIRE(MUTEX)
#define OVS_RELEASE(MUTEX)
#define OVS_HOLDS(MUTEX)
#endif

/* ISO C says that a C implementation may choose any integer type for an enum
 * that is sufficient to hold all of its values.  Common ABIs (such as the
 * System V ABI used on i386 GNU/Linux) always use a full-sized "int", even
 * when a smaller type would suffice.
 *
 * In GNU C, "enum __attribute__((packed)) name { ... }" defines 'name' as an
 * enum compatible with a type that is no bigger than necessary.  This is the
 * intended use of OVS_PACKED_ENUM.
 *
 * OVS_PACKED_ENUM is intended for use only as a space optimization, since it
 * only works with GCC.  That means that it must not be used in wire protocols
 * or otherwise exposed outside of a single process. */
#if __GNUC__ && !__CHECKER__
#define OVS_PACKED_ENUM __attribute__((__packed__))
#else
#define OVS_PACKED_ENUM
#endif

#endif /* compiler.h */
