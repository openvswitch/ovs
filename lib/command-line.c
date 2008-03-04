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

#include "command-line.h"
#include <getopt.h>
#include <limits.h>
#include "util.h"
#include "vlog.h"

/* Given the GNU-style long options in 'options', returns a string that may be
 * passed to getopt() with the corresponding short options.  The caller is
 * responsible for freeing the string. */
char *
long_options_to_short_options(const struct option options[])
{
    char short_options[UCHAR_MAX * 3 + 1];
    char *p = short_options;
    
    for (; options->name; options++) {
        const struct option *o = options;
        if (o->flag == NULL && o->val > 0 && o->val <= UCHAR_MAX) {
            *p++ = o->val;
            if (o->has_arg == required_argument) {
                *p++ = ':';
            } else if (o->has_arg == optional_argument) {
                *p++ = ':';
                *p++ = ':';
            }
        }
    }
    *p = '\0';
    
    return xstrdup(short_options);
}

