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

#ifndef PORT_ARRAY_H
#define PORT_ARRAY_H 1

#include <assert.h>
#include "openflow/openflow.h"
#include "util.h"

static inline uint16_t
port_array_extract_bits__(uint16_t data, int start, int count)
{
    return (data >> start) & ((1u << count) - 1);
}

/* Level 1: most-significant bits. */
#define PORT_ARRAY_L1_BITS 5
#define PORT_ARRAY_L1_SHIFT (PORT_ARRAY_L3_BITS + PORT_ARRAY_L2_BITS)
#define PORT_ARRAY_L1_SIZE (1u << PORT_ARRAY_L1_BITS)
#define PORT_ARRAY_L1(IDX) \
    port_array_extract_bits__(IDX, PORT_ARRAY_L1_SHIFT, PORT_ARRAY_L1_BITS)

/* Level 2: middle bits. */
#define PORT_ARRAY_L2_BITS 5
#define PORT_ARRAY_L2_SHIFT PORT_ARRAY_L3_BITS
#define PORT_ARRAY_L2_SIZE (1u << PORT_ARRAY_L2_BITS)
#define PORT_ARRAY_L2(IDX) \
    port_array_extract_bits__(IDX, PORT_ARRAY_L2_SHIFT, PORT_ARRAY_L2_BITS)

/* Level 3: least-significant bits. */
#define PORT_ARRAY_L3_BITS 6
#define PORT_ARRAY_L3_SHIFT 0
#define PORT_ARRAY_L3_SIZE (1u << PORT_ARRAY_L3_BITS)
#define PORT_ARRAY_L3(IDX) \
    port_array_extract_bits__(IDX, PORT_ARRAY_L3_SHIFT, PORT_ARRAY_L3_BITS)

#define PORT_ARRAY_SIZE (1u << (PORT_ARRAY_L1_BITS      \
                                + PORT_ARRAY_L2_BITS    \
                                + PORT_ARRAY_L3_BITS))

BUILD_ASSERT_DECL(PORT_ARRAY_SIZE > 0xffff);

/* A "sparse array" of up to 65536 elements (numbered 0...65535), implemented
 * as a 3-level trie.  Most efficient when the elements are clustered
 * together. */
struct port_array {
    struct port_array_l2 *l1[1u << PORT_ARRAY_L1_BITS];
};

struct port_array_l2 {
    struct port_array_l3 *l2[1u << PORT_ARRAY_L2_BITS];
};

struct port_array_l3 {
    void *l3[1u << PORT_ARRAY_L3_BITS];
};

/* Returns the value of the element numbered 'idx' in 'pa', or a null pointer
 * if no element numbered 'idx' has been set. */
static inline void *
port_array_get(const struct port_array *pa, uint16_t idx)
{
    unsigned int l1_idx = PORT_ARRAY_L1(idx);
    unsigned int l2_idx = PORT_ARRAY_L2(idx);
    unsigned int l3_idx = PORT_ARRAY_L3(idx);
    return pa->l1[l1_idx]->l2[l2_idx]->l3[l3_idx];
}

void port_array_init(struct port_array *);
void port_array_destroy(struct port_array *);
void port_array_set(struct port_array *, uint16_t idx, void *);
void *port_array_first(const struct port_array *, unsigned int *);
void *port_array_next(const struct port_array *, unsigned int *);

#endif /* port-array.h */
