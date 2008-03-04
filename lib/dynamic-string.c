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

#include "dynamic-string.h"
#include <assert.h>
#include <stdlib.h>
#include "util.h"

void
ds_init(struct ds *ds)
{
    ds->string = NULL;
    ds->length = 0;
    ds->allocated = 0;
}

void
ds_reserve(struct ds *ds, size_t min_length)
{
    if (min_length > ds->allocated || !ds->string) {
        ds->allocated += MAX(min_length, ds->allocated);
        ds->allocated = MAX(8, ds->allocated);
        ds->string = xrealloc(ds->string, ds->allocated + 1);
    }
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
        size_t available;

        ds_reserve(ds, ds->length + needed);

        va_copy(args, args_);
        available = ds->allocated - ds->length + 1;
        needed = vsnprintf(&ds->string[ds->length], available, format, args);
        va_end(args);

        assert(needed < available);
        ds->length += needed;
    }
}

char *
ds_cstr(struct ds *ds)
{
    if (!ds->string) {
        ds_reserve(ds, 0);
        ds->string[0] = '\0';
    }
    return ds->string;
}

void
ds_destroy(struct ds *ds)
{
    free(ds->string);
}
