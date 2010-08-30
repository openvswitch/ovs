/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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

#ifndef UTIL_H
#define UTIL_H 1

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "compiler.h"

#ifndef va_copy
#ifdef __va_copy
#define va_copy __va_copy
#else
#define va_copy(dst, src) ((dst) = (src))
#endif
#endif

#ifndef __cplusplus
/* Build-time assertion building block. */
#define BUILD_ASSERT__(EXPR) \
        sizeof(struct { unsigned int build_assert_failed : (EXPR) ? 1 : -1; })

/* Build-time assertion for use in a statement context. */
#define BUILD_ASSERT(EXPR) (void) BUILD_ASSERT__(EXPR)

/* Build-time assertion for use in a declaration context. */
#define BUILD_ASSERT_DECL(EXPR) \
        extern int (*build_assert(void))[BUILD_ASSERT__(EXPR)]
#else /* __cplusplus */
#include <boost/static_assert.hpp>
#define BUILD_ASSERT BOOST_STATIC_ASSERT
#define BUILD_ASSERT_DECL BOOST_STATIC_ASSERT
#endif /* __cplusplus */

extern const char *program_name;

/* Returns the number of elements in ARRAY. */
#define ARRAY_SIZE(ARRAY) (sizeof ARRAY / sizeof *ARRAY)

/* Returns X / Y, rounding up.  X must be nonnegative to round correctly. */
#define DIV_ROUND_UP(X, Y) (((X) + ((Y) - 1)) / (Y))

/* Returns X rounded up to the nearest multiple of Y. */
#define ROUND_UP(X, Y) (DIV_ROUND_UP(X, Y) * (Y))

/* Returns X rounded down to the nearest multiple of Y. */
#define ROUND_DOWN(X, Y) ((X) / (Y) * (Y))

/* Returns true if X is a power of 2, otherwise false. */
#define IS_POW2(X) ((X) && !((X) & ((X) - 1)))

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif

#define NOT_REACHED() abort()

/* Given POINTER, the address of the given MEMBER in a STRUCT object, returns
   the STRUCT object. */
#define CONTAINER_OF(POINTER, STRUCT, MEMBER)                           \
        ((STRUCT *) (void *) ((char *) (POINTER) - offsetof (STRUCT, MEMBER)))

#ifdef  __cplusplus
extern "C" {
#endif

void set_program_name(const char *);

void ovs_print_version(char *date, char *time,
                       uint8_t min_ofp, uint8_t max_ofp);
#define OVS_PRINT_VERSION(min_ofp, max_ofp) \
        ovs_print_version(__DATE__, __TIME__, (min_ofp), (max_ofp))

void out_of_memory(void) NO_RETURN;
void *xmalloc(size_t) MALLOC_LIKE;
void *xcalloc(size_t, size_t) MALLOC_LIKE;
void *xzalloc(size_t) MALLOC_LIKE;
void *xrealloc(void *, size_t);
void *xmemdup(const void *, size_t) MALLOC_LIKE;
char *xmemdup0(const char *, size_t) MALLOC_LIKE;
char *xstrdup(const char *) MALLOC_LIKE;
char *xasprintf(const char *format, ...) PRINTF_FORMAT(1, 2) MALLOC_LIKE;
char *xvasprintf(const char *format, va_list) PRINTF_FORMAT(1, 0) MALLOC_LIKE;
void *x2nrealloc(void *p, size_t *n, size_t s);

void ovs_strlcpy(char *dst, const char *src, size_t size);

void ovs_fatal(int err_no, const char *format, ...)
    PRINTF_FORMAT(2, 3) NO_RETURN;
void ovs_error(int err_no, const char *format, ...) PRINTF_FORMAT(2, 3);
void ovs_hex_dump(FILE *, const void *, size_t, uintptr_t offset, bool ascii);

bool str_to_int(const char *, int base, int *);
bool str_to_long(const char *, int base, long *);
bool str_to_llong(const char *, int base, long long *);
bool str_to_uint(const char *, int base, unsigned int *);
bool str_to_ulong(const char *, int base, unsigned long *);
bool str_to_ullong(const char *, int base, unsigned long long *);

bool str_to_double(const char *, double *);

int hexit_value(int c);

char *get_cwd(void);
char *dir_name(const char *file_name);
char *abs_file_name(const char *dir, const char *file_name);

void ignore(bool x OVS_UNUSED);

#ifdef  __cplusplus
}
#endif

#endif /* util.h */
