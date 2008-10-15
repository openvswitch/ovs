/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
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

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif

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

void out_of_memory(void);
void *xmalloc(size_t);
void *xcalloc(size_t, size_t);
void *xrealloc(void *, size_t);
void *xmemdup(const void *, size_t);
char *xmemdup0(const char *, size_t);
char *xstrdup(const char *);
char *xasprintf(const char *format, ...) PRINTF_FORMAT(1, 2);
char *xvasprintf(const char *format, va_list) PRINTF_FORMAT(1, 0);

#ifndef HAVE_STRLCPY
void strlcpy(char *dst, const char *src, size_t size);
#endif

void ofp_fatal(int err_no, const char *format, ...)
    PRINTF_FORMAT(2, 3) NO_RETURN;
void ofp_error(int err_no, const char *format, ...) PRINTF_FORMAT(2, 3);
void ofp_hex_dump(FILE *, const void *, size_t, uintptr_t offset, bool ascii);

#ifdef  __cplusplus
}
#endif

#endif /* util.h */
