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

#ifndef SVEC_H
#define SVEC_H 1

#include <stdbool.h>
#include <stddef.h>

struct svec {
    char **names;
    size_t n;
    size_t allocated;
};

#define SVEC_EMPTY_INITIALIZER { NULL, 0, 0 }

void svec_init(struct svec *);
void svec_destroy(struct svec *);
void svec_clear(struct svec *);
void svec_add(struct svec *, const char *);
void svec_add_nocopy(struct svec *, char *);
void svec_append(struct svec *, const struct svec *);
void svec_terminate(struct svec *);
void svec_sort(struct svec *);
void svec_unique(struct svec *);
void svec_diff(const struct svec *a, const struct svec *b,
               struct svec *a_only, struct svec *both, struct svec *b_only);
bool svec_contains(const struct svec *, const char *);
bool svec_is_sorted(const struct svec *);
void svec_swap(struct svec *a, struct svec *b);
void svec_print(const struct svec *svec, const char *title);
void svec_parse_words(struct svec *svec, const char *words);
bool svec_equal(const struct svec *, const struct svec *);
char *svec_join(const struct svec *, const char *delimiter);

#endif /* svec.h */
