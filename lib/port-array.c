/*
 * Copyright (c) 2008, 2010 Nicira Networks.
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
#include "port-array.h"
#include <stdlib.h>

static struct port_array_l2 l2_sentinel;
static struct port_array_l3 l3_sentinel;
static bool inited;

/* Initializes 'pa' as an empty port_array. */
void
port_array_init(struct port_array *pa)
{
    size_t i;
    if (!inited) {
        inited = true;
        for (i = 0; i < PORT_ARRAY_L2_SIZE; i++) {
            l2_sentinel.l2[i] = &l3_sentinel;
        }
    }
    for (i = 0; i < PORT_ARRAY_L1_SIZE; i++) {
        pa->l1[i] = &l2_sentinel;
    }
}

/* Frees all the memory allocated for 'pa'.  It is the client's responsibility
 * to free memory that 'pa' elements point to. */
void
port_array_destroy(struct port_array *pa)
{
    unsigned int l1_idx;

    for (l1_idx = 0; l1_idx < PORT_ARRAY_L1_SIZE; l1_idx++) {
        struct port_array_l2 *l2 = pa->l1[l1_idx];

        if (l2 != &l2_sentinel) {
            unsigned int l2_idx;

            for (l2_idx = 0; l2_idx < PORT_ARRAY_L2_SIZE; l2_idx++) {
                struct port_array_l3 *l3 = l2->l2[l2_idx];
                if (l3 != &l3_sentinel) {
                    free(l3);
                }
            }
            free(l2);
        }
    }
}

/* Clears all elements of 'pa' to null pointers. */
void
port_array_clear(struct port_array *pa)
{
    port_array_destroy(pa);
    port_array_init(pa);
}

/* Sets 'pa' element numbered 'idx' to 'p'. */
void
port_array_set(struct port_array *pa, uint16_t idx, void *p)
{
    struct port_array_l2 **l2p, *l2;
    struct port_array_l3 **l3p, *l3;

    /* Traverse level 1. */
    l2p = &pa->l1[PORT_ARRAY_L1(idx)];
    if (*l2p == &l2_sentinel) {
        *l2p = xmemdup(&l2_sentinel, sizeof l2_sentinel);
    }
    l2 = *l2p;

    /* Traverse level 2. */
    l3p = &l2->l2[PORT_ARRAY_L2(idx)];
    if (*l3p == &l3_sentinel) {
        *l3p = xmemdup(&l3_sentinel, sizeof l3_sentinel);
    }
    l3 = *l3p;

    /* Set level 3. */
    l3->l3[PORT_ARRAY_L3(idx)] = p;
}

/* Sets 'pa' element numbered 'idx' to NULL. */
void
port_array_delete(struct port_array *pa, uint16_t idx)
{
    unsigned int l1_idx = PORT_ARRAY_L1(idx);
    unsigned int l2_idx = PORT_ARRAY_L2(idx);
    unsigned int l3_idx = PORT_ARRAY_L3(idx);

    pa->l1[l1_idx]->l2[l2_idx]->l3[l3_idx] = NULL;
}

static void *
next(const struct port_array *pa, unsigned int *idxp)
{
    unsigned int idx = *idxp;

    /* Using shift-right directly here, instead of PORT_ARRAY_L1(idx), ensures
     * that with an initially too-big value of '*idxp' we will skip the outer
     * loop and return NULL. */
    unsigned int l1_idx = idx >> PORT_ARRAY_L1_SHIFT;
    unsigned int l2_idx = PORT_ARRAY_L2(idx);
    unsigned int l3_idx = PORT_ARRAY_L3(idx);
    while (l1_idx < PORT_ARRAY_L1_SIZE) {
        struct port_array_l2 *l2 = pa->l1[l1_idx];
        if (l2 != &l2_sentinel) {
            while (l2_idx < PORT_ARRAY_L2_SIZE) {
                struct port_array_l3 *l3 = l2->l2[l2_idx];
                if (l3 != &l3_sentinel) {
                    while (l3_idx < PORT_ARRAY_L3_SIZE) {
                        void *p = l3->l3[l3_idx];
                        if (p) {
                            *idxp = ((l1_idx << PORT_ARRAY_L1_SHIFT)
                                     | (l2_idx << PORT_ARRAY_L2_SHIFT)
                                     | (l3_idx << PORT_ARRAY_L3_SHIFT));
                            return p;
                        }
                        l3_idx++;
                    }
                }
                l2_idx++;
                l3_idx = 0;
            }
        }
        l1_idx++;
        l2_idx = 0;
        l3_idx = 0;
    }
    *idxp = PORT_ARRAY_SIZE;
    return NULL;
}

/* Returns the value of the lowest-numbered non-empty element of 'pa', and sets
 * '*idxp' to that element's index.  If 'pa' is entirely empty, returns a null
 * pointer and sets '*idxp' to 65536.  */
void *
port_array_first(const struct port_array *pa, unsigned int *idxp)
{
    *idxp = 0;
    return next(pa, idxp);
}

/* Returns the value of the lowest-numbered non-empty element of 'pa' greater
 * than the initial value of '*idxp', and sets '*idxp' to that element's index.
 * If 'pa' contains no non-empty elements with indexes greater than the initial
 * value of '*idxp', returns a null pointer and sets '*idxp' to 65536.  */
void *
port_array_next(const struct port_array *pa, unsigned int *idxp)
{
    ++*idxp;
    return next(pa, idxp);
}

/* Returns the number of non-null elements of 'pa'. */
unsigned int
port_array_count(const struct port_array *pa)
{
    unsigned int l1_idx, l2_idx, l3_idx;
    unsigned int count;

    count = 0;
    for (l1_idx = 0; l1_idx < PORT_ARRAY_L1_SIZE; l1_idx++) {
        struct port_array_l2 *l2 = pa->l1[l1_idx];
        if (l2 != &l2_sentinel) {
            for (l2_idx = 0; l2_idx < PORT_ARRAY_L2_SIZE; l2_idx++) {
                struct port_array_l3 *l3 = l2->l2[l2_idx];
                if (l3 != &l3_sentinel) {
                    for (l3_idx = 0; l3_idx < PORT_ARRAY_L3_SIZE; l3_idx++) {
                        if (l3->l3[l3_idx]) {
                            count++;
                        }
                    }
                }
            }
        }
    }
    return count;
}
