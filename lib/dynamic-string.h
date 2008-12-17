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

#ifndef DYNAMIC_STRING_H
#define DYNAMIC_STRING_H 1

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "compiler.h"

struct tm;

struct ds {
    char *string;       /* Null-terminated string. */
    size_t length;      /* Bytes used, not including null terminator. */
    size_t allocated;   /* Bytes allocated, not including null terminator. */
};

#define DS_EMPTY_INITIALIZER { NULL, 0, 0 }

void ds_init(struct ds *);
void ds_clear(struct ds *);
void ds_truncate(struct ds *, size_t new_length);
void ds_reserve(struct ds *, size_t min_length);
char *ds_put_uninit(struct ds *, size_t n);
void ds_put_char(struct ds *, char);
void ds_put_char_multiple(struct ds *, char, size_t n);
void ds_put_buffer(struct ds *, const char *, size_t n);
void ds_put_cstr(struct ds *, const char *);
void ds_put_format(struct ds *, const char *, ...) PRINTF_FORMAT(2, 3);
void ds_put_format_valist(struct ds *, const char *, va_list)
    PRINTF_FORMAT(2, 0);
void ds_put_printable(struct ds *, const char *, size_t);
void ds_put_strftime(struct ds *, const char *, const struct tm *)
    STRFTIME_FORMAT(2);
void ds_put_hex_dump(struct ds *ds, const void *buf_, size_t size,
                     uintptr_t ofs, bool ascii);
int ds_get_line(struct ds *, FILE *);

char *ds_cstr(struct ds *);
void ds_destroy(struct ds *);

int ds_last(const struct ds *);
void ds_chomp(struct ds *, int c);

#endif /* dynamic-string.h */
