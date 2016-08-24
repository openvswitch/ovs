/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2016 Nicira, Inc.
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

#include <config.h>
#include "openvswitch/dynamic-string.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "timeval.h"
#include "util.h"

/* Initializes 'ds' as an empty string buffer. */
void
ds_init(struct ds *ds)
{
    ds->string = NULL;
    ds->length = 0;
    ds->allocated = 0;
}

/* Sets 'ds''s length to 0, effectively clearing any existing content.  Does
 * not free any memory. */
void
ds_clear(struct ds *ds)
{
    ds->length = 0;
}

/* Reduces 'ds''s length to no more than 'new_length'.  (If its length is
 * already 'new_length' or less, does nothing.)  */
void
ds_truncate(struct ds *ds, size_t new_length)
{
    if (ds->length > new_length) {
        ds->length = new_length;
        ds->string[new_length] = '\0';
    }
}

/* Ensures that at least 'min_length + 1' bytes (including space for a null
 * terminator) are allocated for ds->string, allocating or reallocating memory
 * as necessary. */
void
ds_reserve(struct ds *ds, size_t min_length)
{
    if (min_length > ds->allocated || !ds->string) {
        ds->allocated += MAX(min_length, ds->allocated);
        ds->allocated = MAX(8, ds->allocated);
        ds->string = xrealloc(ds->string, ds->allocated + 1);
    }
}

/* Appends space for 'n' bytes to the end of 'ds->string', increasing
 * 'ds->length' by the same amount, and returns the first appended byte.  The
 * caller should fill in all 'n' bytes starting at the return value. */
char *
ds_put_uninit(struct ds *ds, size_t n)
{
    ds_reserve(ds, ds->length + n);
    ds->length += n;
    ds->string[ds->length] = '\0';
    return &ds->string[ds->length - n];
}

void
ds_put_char__(struct ds *ds, char c)
{
    *ds_put_uninit(ds, 1) = c;
}

/* Appends unicode code point 'uc' to 'ds' in UTF-8 encoding. */
void
ds_put_utf8(struct ds *ds, int uc)
{
    if (uc <= 0x7f) {
        ds_put_char(ds, uc);
    } else if (uc <= 0x7ff) {
        ds_put_char(ds, 0xc0 | (uc >> 6));
        ds_put_char(ds, 0x80 | (uc & 0x3f));
    } else if (uc <= 0xffff) {
        ds_put_char(ds, 0xe0 | (uc >> 12));
        ds_put_char(ds, 0x80 | ((uc >> 6) & 0x3f));
        ds_put_char(ds, 0x80 | (uc & 0x3f));
    } else if (uc <= 0x10ffff) {
        ds_put_char(ds, 0xf0 | (uc >> 18));
        ds_put_char(ds, 0x80 | ((uc >> 12) & 0x3f));
        ds_put_char(ds, 0x80 | ((uc >> 6) & 0x3f));
        ds_put_char(ds, 0x80 | (uc & 0x3f));
    } else {
        /* Invalid code point.  Insert the Unicode general substitute
         * REPLACEMENT CHARACTER. */
        ds_put_utf8(ds, 0xfffd);
    }
}

void
ds_put_char_multiple(struct ds *ds, char c, size_t n)
{
    memset(ds_put_uninit(ds, n), c, n);
}

void
ds_put_buffer(struct ds *ds, const char *s, size_t n)
{
    memcpy(ds_put_uninit(ds, n), s, n);
}

void
ds_put_cstr(struct ds *ds, const char *s)
{
    size_t s_len = strlen(s);
    memcpy(ds_put_uninit(ds, s_len), s, s_len);
}

void
ds_put_and_free_cstr(struct ds *ds, char *s)
{
    ds_put_cstr(ds, s);
    free(s);
}

void
ds_put_format(struct ds *ds, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    ds_put_format_valist(ds, format, args);
    va_end(args);
}

void
ds_put_format_valist(struct ds *ds, const char *format, va_list args_)
{
    va_list args;
    size_t available;
    int needed;

    va_copy(args, args_);
    available = ds->string ? ds->allocated - ds->length + 1 : 0;
    needed = vsnprintf(&ds->string[ds->length], available, format, args);
    va_end(args);

    if (needed < available) {
        ds->length += needed;
    } else {
        ds_reserve(ds, ds->length + needed);

        va_copy(args, args_);
        available = ds->allocated - ds->length + 1;
        needed = vsnprintf(&ds->string[ds->length], available, format, args);
        va_end(args);

        ovs_assert(needed < available);
        ds->length += needed;
    }
}

void
ds_put_printable(struct ds *ds, const char *s, size_t n)
{
    ds_reserve(ds, ds->length + n);
    while (n-- > 0) {
        unsigned char c = *s++;
        if (c < 0x20 || c > 0x7e || c == '\\' || c == '"') {
            ds_put_format(ds, "\\%03o", (int) c);
        } else {
            ds_put_char(ds, c);
        }
    }
}

/* Writes the current time with optional millisecond resolution to 'string'
 * based on 'template'.
 * The current time is either localtime or UTC based on 'utc'. */
void
ds_put_strftime_msec(struct ds *ds, const char *template, long long int when,
                     bool utc)
{
    struct tm_msec tm;
    if (utc) {
        gmtime_msec(when, &tm);
    } else {
        localtime_msec(when, &tm);
    }

    for (;;) {
        size_t avail = ds->string ? ds->allocated - ds->length + 1 : 0;
        size_t used = strftime_msec(&ds->string[ds->length], avail, template,
                                    &tm);
        if (used) {
            ds->length += used;
            return;
        }
        ds_reserve(ds, ds->length + (avail < 32 ? 64 : 2 * avail));
    }
}

/* Returns a malloc()'d string for time 'when' based on 'template', in local
 * time or UTC based on 'utc'. */
char *
xastrftime_msec(const char *template, long long int when, bool utc)
{
    struct ds s;

    ds_init(&s);
    ds_put_strftime_msec(&s, template, when, utc);
    return s.string;
}

int
ds_get_line(struct ds *ds, FILE *file)
{
    ds_clear(ds);
    for (;;) {
        int c = getc(file);
        if (c == EOF) {
            return ds->length ? 0 : EOF;
        } else if (c == '\n') {
            return 0;
        } else {
            ds_put_char(ds, c);
        }
    }
}

/* Reads a line from 'file' into 'ds', clearing anything initially in 'ds'.
 * Deletes comments introduced by "#" and skips lines that contains only white
 * space (after deleting comments).
 *
 * If 'line_numberp' is nonnull, increments '*line_numberp' by the number of
 * lines read from 'file'.
 *
 * Returns 0 if successful, EOF if no non-blank line was found. */
int
ds_get_preprocessed_line(struct ds *ds, FILE *file, int *line_numberp)
{
    while (!ds_get_line(ds, file)) {
        char *line = ds_cstr(ds);
        char *comment;

        if (line_numberp) {
            ++*line_numberp;
        }

        /* Delete comments. */
        comment = strchr(line, '#');
        if (comment) {
            *comment = '\0';
        }

        /* Return successfully unless the line is all spaces. */
        if (line[strspn(line, " \t\n")] != '\0') {
            return 0;
        }
    }
    return EOF;
}

/* Reads a line from 'file' into 'ds' and does some preprocessing on it:
 *
 *    - If the line begins with #, prints it on stdout and reads the next line.
 *
 *    - Otherwise, if the line contains an # somewhere else, strips it and
 *      everything following it (as a comment).
 *
 *    - If (after comment removal) the line contains only white space, prints
 *      a blank line on stdout and reads the next line.
 *
 *    - Otherwise, returns the line to the caller.
 *
 * This is useful in some of the OVS tests, where we want to check that parsing
 * and then re-formatting some kind of data does not change it, but we also
 * want to be able to put comments in the input.
 *
 * Returns 0 if successful, EOF if no non-blank line was found. */
int
ds_get_test_line(struct ds *ds, FILE *file)
{
    for (;;) {
        char *s, *comment;
        int retval;

        retval = ds_get_line(ds, file);
        if (retval) {
            return retval;
        }

        s = ds_cstr(ds);
        if (*s == '#') {
            puts(s);
            continue;
        }

        comment = strchr(s, '#');
        if (comment) {
            *comment = '\0';
        }
        if (s[strspn(s, " \t\n")] == '\0') {
            putchar('\n');
            continue;
        }

        return 0;
    }
}

char *
ds_cstr(struct ds *ds)
{
    if (!ds->string) {
        ds_reserve(ds, 0);
    }
    ds->string[ds->length] = '\0';
    return ds->string;
}

const char *
ds_cstr_ro(const struct ds *ds)
{
    return ds_cstr(CONST_CAST(struct ds *, ds));
}

/* Returns a null-terminated string representing the current contents of 'ds',
 * which the caller is expected to free with free(), then clears the contents
 * of 'ds'. */
char *
ds_steal_cstr(struct ds *ds)
{
    char *s = ds_cstr(ds);
    ds_init(ds);
    return s;
}

void
ds_destroy(struct ds *ds)
{
    free(ds->string);
}

/* Swaps the content of 'a' and 'b'. */
void
ds_swap(struct ds *a, struct ds *b)
{
    struct ds temp = *a;
    *a = *b;
    *b = temp;
}

void
ds_put_hex(struct ds *ds, const void *buf_, size_t size)
{
    const uint8_t *buf = buf_;
    bool printed = false;
    int i;

    for (i = 0; i < size; i++) {
        uint8_t val = buf[i];
        if (val || printed) {
            if (!printed) {
                ds_put_format(ds, "0x%"PRIx8, val);
            } else {
                ds_put_format(ds, "%02"PRIx8, val);
            }
            printed = true;
        }
    }
    if (!printed) {
        ds_put_char(ds, '0');
    }
}

/* Writes the 'size' bytes in 'buf' to 'string' as hex bytes arranged 16 per
 * line.  Numeric offsets are also included, starting at 'ofs' for the first
 * byte in 'buf'.  If 'ascii' is true then the corresponding ASCII characters
 * are also rendered alongside. */
void
ds_put_hex_dump(struct ds *ds, const void *buf_, size_t size,
                uintptr_t ofs, bool ascii)
{
    const uint8_t *buf = buf_;
    const size_t per_line = 16; /* Maximum bytes per line. */

    while (size > 0) {
        size_t start, end, n;
        size_t i;

        /* Number of bytes on this line. */
        start = ofs % per_line;
        end = per_line;
        if (end - start > size)
            end = start + size;
        n = end - start;

        /* Print line. */
        ds_put_format(ds, "%08"PRIxMAX"  ",
                      (uintmax_t) ROUND_DOWN(ofs, per_line));
        for (i = 0; i < start; i++) {
            ds_put_format(ds, "   ");
        }
        for (; i < end; i++) {
            ds_put_format(ds, "%02x%c",
                          buf[i - start], i == per_line / 2 - 1? '-' : ' ');
        }
        if (ascii) {
            for (; i < per_line; i++)
                ds_put_format(ds, "   ");
            ds_put_format(ds, "|");
            for (i = 0; i < start; i++)
                ds_put_format(ds, " ");
            for (; i < end; i++) {
                int c = buf[i - start];
                ds_put_char(ds, c >= 32 && c < 127 ? c : '.');
            }
            for (; i < per_line; i++)
                ds_put_format(ds, " ");
            ds_put_format(ds, "|");
        } else {
            ds_chomp(ds, ' ');
        }
        ds_put_format(ds, "\n");

        ofs += n;
        buf += n;
        size -= n;
    }
}

int
ds_last(const struct ds *ds)
{
    return ds->length > 0 ? (unsigned char) ds->string[ds->length - 1] : EOF;
}

bool
ds_chomp(struct ds *ds, int c)
{
    if (ds->length > 0 && ds->string[ds->length - 1] == (char) c) {
        ds->string[--ds->length] = '\0';
        return true;
    } else {
        return false;
    }
}

void
ds_clone(struct ds *dst, struct ds *source)
{
    dst->length = source->length;
    dst->allocated = dst->length;
    dst->string = xmalloc(dst->allocated + 1);
    memcpy(dst->string, source->string, dst->allocated + 1);
}
