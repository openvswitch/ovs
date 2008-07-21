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

#include <config.h>
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

