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
#include "port-array.h"

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
