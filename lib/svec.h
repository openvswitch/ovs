/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
void svec_clone(struct svec *, const struct svec *);
void svec_destroy(struct svec *);
void svec_clear(struct svec *);
void svec_add(struct svec *, const char *);
void svec_add_nocopy(struct svec *, char *);
void svec_del(struct svec *, const char *);
void svec_append(struct svec *, const struct svec *);
void svec_terminate(struct svec *);
void svec_sort(struct svec *);
void svec_sort_unique(struct svec *);
void svec_unique(struct svec *);
void svec_compact(struct svec *);
void svec_diff(const struct svec *a, const struct svec *b,
               struct svec *a_only, struct svec *both, struct svec *b_only);
bool svec_contains(const struct svec *, const char *);
size_t svec_find(const struct svec *, const char *);
bool svec_is_sorted(const struct svec *);
bool svec_is_unique(const struct svec *);
const char *svec_get_duplicate(const struct svec *);
void svec_swap(struct svec *a, struct svec *b);
void svec_print(const struct svec *svec, const char *title);
void svec_parse_words(struct svec *svec, const char *words);
bool svec_equal(const struct svec *, const struct svec *);
char *svec_join(const struct svec *,
                const char *delimiter, const char *terminator);
const char *svec_back(const struct svec *);
void svec_pop_back(struct svec *);

#endif /* svec.h */
