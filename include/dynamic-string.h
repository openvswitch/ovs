/* Copyright (C) 2008 Board of Trustees, Leland Stanford Jr. University.
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

#ifndef DYNAMIC_STRING_H
#define DYNAMIC_STRING_H 1

#include <stdarg.h>
#include <stddef.h>
#include "compiler.h"

struct ds {
    char *string;       /* Null-terminated string. */
    size_t length;      /* Bytes used, not including null terminator. */
    size_t allocated;   /* Bytes allocated, not including null terminator. */
};

#define DS_EMPTY_INITIALIZER { NULL, 0, 0 }

void ds_init(struct ds *);
void ds_reserve(struct ds *, size_t min_length);
void ds_put_format(struct ds *, const char *, ...) PRINTF_FORMAT(2, 3);
void ds_put_format_valist(struct ds *, const char *, va_list)
    PRINTF_FORMAT(2, 0);
char *ds_cstr(struct ds *);
void ds_destroy(struct ds *);

#endif /* dynamic-string.h */
