/* Copyright (c) 2009 Nicira, Inc.
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

#include "sort.h"

#include "random.h"

static size_t
partition(size_t p, size_t r,
          int (*compare)(size_t a, size_t b, void *aux),
          void (*swap)(size_t a, size_t b, void *aux),
          void *aux)
{
    size_t x = r - 1;
    size_t i, j;

    i = p;
    for (j = p; j < x; j++) {
        if (compare(j, x, aux) <= 0) {
            swap(i++, j, aux);
        }
    }
    swap(i, x, aux);
    return i;
}

static void
quicksort(size_t p, size_t r,
          int (*compare)(size_t a, size_t b, void *aux),
          void (*swap)(size_t a, size_t b, void *aux),
          void *aux)
{
    size_t i, q;

    if (r - p < 2) {
        return;
    }

    i = random_range(r - p) + p;
    if (r - 1 != i) {
        swap(r - 1, i, aux);
    }

    q = partition(p, r, compare, swap, aux);
    quicksort(p, q, compare, swap, aux);
    quicksort(q, r, compare, swap, aux);
}

void
sort(size_t count,
     int (*compare)(size_t a, size_t b, void *aux),
     void (*swap)(size_t a, size_t b, void *aux),
     void *aux)
{
    quicksort(0, count, compare, swap, aux);
}
