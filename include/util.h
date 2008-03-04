/* Copyright (C) 2007 Board of Trustees, Leland Stanford Jr. University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef UTIL_H
#define UTIL_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "compiler.h"

#ifndef __cplusplus
/* Build-time assertion for use in a statement context. */
#define BUILD_ASSERT(EXPR) \
        sizeof(struct { unsigned int build_assert_failed : (EXPR) ? 1 : -1; })

/* Build-time assertion for use in a declaration context. */
#define BUILD_ASSERT_DECL(EXPR) \
        extern int (*build_assert(void))[BUILD_ASSERT(EXPR)]
#else /* __cplusplus */
#include <boost/static_assert.hpp>
#define BUILD_ASSERT BOOST_STATIC_ASSERT
#define BUILD_ASSERT_DECL BOOST_STATIC_ASSERT
#endif /* __cplusplus */

extern const char *program_name;

#define ARRAY_SIZE(ARRAY) (sizeof ARRAY / sizeof *ARRAY)
#define ROUND_UP(X, Y) (((X) + ((Y) - 1)) / (Y) * (Y))
#define ROUND_DOWN(X, Y) ((X) / (Y) * (Y))
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))

#define NOT_REACHED() abort()
#define NOT_IMPLEMENTED() abort()
#define NOT_TESTED() ((void) 0) /* XXX should print a message. */

/* Given POINTER, the address of the given MEMBER in a STRUCT object, returns
   the STRUCT object. */
#define CONTAINER_OF(POINTER, STRUCT, MEMBER)                           \
        ((STRUCT *) ((char *) (POINTER) - offsetof (STRUCT, MEMBER)))

#ifdef  __cplusplus
extern "C" {
#endif

void set_program_name(const char *);

void *xmalloc(size_t);
void *xcalloc(size_t, size_t);
void *xrealloc(void *, size_t);
char *xstrdup(const char *);
char *xasprintf(const char *format, ...) PRINTF_FORMAT(1, 2);

void fatal(int err_no, const char *format, ...) PRINTF_FORMAT(2, 3) NO_RETURN;
void error(int err_no, const char *format, ...) PRINTF_FORMAT(2, 3);
void debug(int err_no, const char *format, ...) PRINTF_FORMAT(2, 3);
void debug_msg(int err_no, const char *format, ...) PRINTF_FORMAT(2, 3);
void hex_dump(FILE *, const void *, size_t, uintptr_t offset, bool ascii);

#ifdef  __cplusplus
}
#endif

#endif /* util.h */
