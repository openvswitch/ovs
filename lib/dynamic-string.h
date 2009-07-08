/*
 * Copyright (c) 2008 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
