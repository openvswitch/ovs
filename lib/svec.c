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
#include "svec.h"
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "dynamic-string.h"
#include "util.h"

#define THIS_MODULE VLM_svec
#include "vlog.h"

void
svec_init(struct svec *svec)
{
    svec->names = NULL;
    svec->n = 0;
    svec->allocated = 0;
}

void
svec_destroy(struct svec *svec)
{
    svec_clear(svec);
    free(svec->names);
}

void
svec_clear(struct svec *svec) 
{
    size_t i;

    for (i = 0; i < svec->n; i++) {
        free(svec->names[i]);
    }
    svec->n = 0;
}

void
svec_add(struct svec *svec, const char *name)
{
    svec_add_nocopy(svec, xstrdup(name));
}

static void
svec_expand(struct svec *svec)
{
    if (svec->n >= svec->allocated) {
        svec->names = x2nrealloc(svec->names, &svec->allocated,
                                 sizeof *svec->names);
    }
}

void
svec_add_nocopy(struct svec *svec, char *name)
{
    svec_expand(svec);
    svec->names[svec->n++] = name;
}

void
svec_append(struct svec *svec, const struct svec *other)
{
    size_t i;
    for (i = 0; i < other->n; i++) {
        svec_add(svec, other->names[i]);
    }
}

void
svec_terminate(struct svec *svec)
{
    svec_expand(svec);
    svec->names[svec->n] = NULL;
}

static int
compare_strings(const void *a_, const void *b_)
{
    char *const *a = a_;
    char *const *b = b_;
    return strcmp(*a, *b);
}

void
svec_sort(struct svec *svec)
{
    qsort(svec->names, svec->n, sizeof *svec->names, compare_strings);
}

void
svec_unique(struct svec *svec)
{
    assert(svec_is_sorted(svec));
    if (svec->n > 1) {
        /* This algorithm is lazy and sub-optimal, but it's "obviously correct"
         * and asymptotically optimal . */
        struct svec tmp;
        size_t i;

        svec_init(&tmp);
        svec_add(&tmp, svec->names[0]);
        for (i = 1; i < svec->n; i++) {
            if (strcmp(svec->names[i - 1], svec->names[i])) {
                svec_add(&tmp, svec->names[i]);
            }
        }
        svec_swap(&tmp, svec);
        svec_destroy(&tmp);
    }
}

void
svec_diff(const struct svec *a, const struct svec *b,
          struct svec *a_only, struct svec *both, struct svec *b_only)
{
    size_t i, j;

    assert(svec_is_sorted(a));
    assert(svec_is_sorted(b));
    if (a_only) {
        svec_init(a_only);
    }
    if (both) {
        svec_init(both);
    }
    if (b_only) {
        svec_init(b_only);
    }
    for (i = j = 0; i < a->n && j < b->n; ) {
        int cmp = strcmp(a->names[i], b->names[j]);
        if (cmp < 0) {
            if (a_only) {
                svec_add(a_only, a->names[i]);
            }
            i++;
        } else if (cmp > 0) {
            if (b_only) {
                svec_add(b_only, b->names[j]);
            }
            j++;
        } else {
            if (both) {
                svec_add(both, a->names[i]);
            }
            i++;
            j++;
        }
    }
    if (a_only) {
        for (; i < a->n; i++) {
            svec_add(a_only, a->names[i]);
        }
    }
    if (b_only) {
        for (; j < b->n; j++) {
            svec_add(b_only, b->names[j]);
        }
    }
}

bool
svec_contains(const struct svec *svec, const char *name)
{
    assert(svec_is_sorted(svec));
    return bsearch(&name, svec->names, svec->n, sizeof *svec->names,
                   compare_strings) != NULL;
}

bool
svec_is_sorted(const struct svec *svec)
{
    size_t i;

    for (i = 1; i < svec->n; i++) {
        if (strcmp(svec->names[i - 1], svec->names[i]) > 0) {
            return false;
        }
    }
    return true;
}

void
svec_swap(struct svec *a, struct svec *b)
{
    struct svec tmp = *a;
    *a = *b;
    *b = tmp;
}

void
svec_print(const struct svec *svec, const char *title)
{
    size_t i;

    printf("%s:\n", title);
    for (i = 0; i < svec->n; i++) {
        printf("\"%s\"\n", svec->names[i]);
    }
}

/* Breaks 'words' into words at white space, respecting shell-like quoting
 * conventions, and appends the words to 'svec'. */
void
svec_parse_words(struct svec *svec, const char *words)
{
    struct ds word = DS_EMPTY_INITIALIZER;
    const char *p, *q;

    for (p = words; *p != '\0'; p = q) {
        int quote = 0;

        while (isspace((unsigned char) *p)) {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        ds_clear(&word);
        for (q = p; *q != '\0'; q++) {
            if (*q == quote) {
                quote = 0;
            } else if (*q == '\'' || *q == '"') {
                quote = *q;
            } else if (*q == '\\' && (!quote || quote == '"')) {
                q++;
                if (*q == '\0') {
                    VLOG_WARN("%s: ends in trailing backslash", words);
                    break;
                }
                ds_put_char(&word, *q);
            } else if (isspace((unsigned char) *q) && !quote) {
                q++;
                break;
            } else {
                ds_put_char(&word, *q);
            }
        }
        svec_add(svec, ds_cstr(&word));
        if (quote) {
            VLOG_WARN("%s: word ends inside quoted string", words);
        }
    }
    ds_destroy(&word);
}

bool
svec_equal(const struct svec *a, const struct svec *b)
{
    size_t i;

    if (a->n != b->n) {
        return false;
    }
    for (i = 0; i < a->n; i++) {
        if (strcmp(a->names[i], b->names[i])) {
            return false;
        }
    }
    return true;
}

char *
svec_join(const struct svec *svec, const char *delimiter)
{
    struct ds ds;
    size_t i;

    ds_init(&ds);
    for (i = 0; i < svec->n; i++) {
        if (i) {
            ds_put_cstr(&ds, delimiter);
        }
        ds_put_cstr(&ds, svec->names[i]);
    }
    return ds_cstr(&ds);
}
