/*
 * Copyright (c) 2008, 2009, 2011 Nicira, Inc.
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

#ifndef SVEC_H
#define SVEC_H 1

#include <stdbool.h>
#include <stddef.h>

#ifdef  __cplusplus
extern "C" {
#endif

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
bool svec_is_empty(const struct svec *);
void svec_add(struct svec *, const char *);
void svec_add_nocopy(struct svec *, char *);
void svec_del(struct svec *, const char *);
void svec_append(struct svec *, const struct svec *);
void svec_terminate(struct svec *);
void svec_sort(struct svec *);
void svec_sort_unique(struct svec *);
void svec_unique(struct svec *);
void svec_compact(struct svec *);
void svec_shuffle(struct svec *);
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

/* Iterates over the names in SVEC, assigning each name in turn to NAME and its
 * index to INDEX. */
#define SVEC_FOR_EACH(INDEX, NAME, SVEC)        \
    for ((INDEX) = 0;                           \
         ((INDEX) < (SVEC)->n                   \
          ? (NAME) = (SVEC)->names[INDEX], 1    \
          : 0);                                 \
         (INDEX)++)

#ifdef  __cplusplus
}
#endif

#endif /* svec.h */
