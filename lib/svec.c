/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include "svec.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "openvswitch/dynamic-string.h"
#include "random.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(svec);

void
svec_init(struct svec *svec)
{
    svec->names = NULL;
    svec->n = 0;
    svec->allocated = 0;
}

void
svec_clone(struct svec *svec, const struct svec *other)
{
    svec_init(svec);
    svec_append(svec, other);
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

bool
svec_is_empty(const struct svec *svec)
{
    return svec->n == 0;
}

void
svec_add(struct svec *svec, const char *name)
{
    svec_add_nocopy(svec, xstrdup(name));
}

void
svec_del(struct svec *svec, const char *name)
{
    size_t offset;

    offset = svec_find(svec, name);
    if (offset != SIZE_MAX) {
        free(svec->names[offset]);
        memmove(&svec->names[offset], &svec->names[offset + 1],
                sizeof *svec->names * (svec->n - offset - 1));
        svec->n--;
    }
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
    if (svec->n) {
        qsort(svec->names, svec->n, sizeof *svec->names, compare_strings);
    }
}

void
svec_sort_unique(struct svec *svec)
{
    svec_sort(svec);
    svec_unique(svec);
}

void
svec_unique(struct svec *svec)
{
    ovs_assert(svec_is_sorted(svec));
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
svec_compact(struct svec *svec)
{
    size_t i, j;

    for (i = j = 0; i < svec->n; i++) {
        if (svec->names[i] != NULL) {
            svec->names[j++] = svec->names[i];
        }
    }
    svec->n = j;
}

static void
swap_strings(char **a, char **b)
{
    char *tmp = *a;
    *a = *b;
    *b = tmp;
}

void
svec_shuffle(struct svec *svec)
{
    for (size_t i = 0; i < svec->n; i++) {
        size_t j = i + random_range(svec->n - i);
        swap_strings(&svec->names[i], &svec->names[j]);
    }
}

void
svec_diff(const struct svec *a, const struct svec *b,
          struct svec *a_only, struct svec *both, struct svec *b_only)
{
    size_t i, j;

    ovs_assert(svec_is_sorted(a));
    ovs_assert(svec_is_sorted(b));
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
    return svec_find(svec, name) != SIZE_MAX;
}

size_t
svec_find(const struct svec *svec, const char *name)
{
    char **p;

    ovs_assert(svec_is_sorted(svec));
    p = bsearch(&name, svec->names, svec->n, sizeof *svec->names,
                compare_strings);
    return p ? p - svec->names : SIZE_MAX;
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

bool
svec_is_unique(const struct svec *svec)
{
    return svec_get_duplicate(svec) == NULL;
}

const char *
svec_get_duplicate(const struct svec *svec)
{
    ovs_assert(svec_is_sorted(svec));
    if (svec->n > 1) {
        size_t i;
        for (i = 1; i < svec->n; i++) {
            if (!strcmp(svec->names[i - 1], svec->names[i])) {
                return svec->names[i];
            }
        }
    }
    return NULL;
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
svec_join(const struct svec *svec,
          const char *delimiter, const char *terminator)
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
    ds_put_cstr(&ds, terminator);
    return ds_cstr(&ds);
}

const char *
svec_back(const struct svec *svec)
{
    ovs_assert(svec->n);
    return svec->names[svec->n - 1];
}

void
svec_pop_back(struct svec *svec)
{
    ovs_assert(svec->n);
    free(svec->names[--svec->n]);
}
