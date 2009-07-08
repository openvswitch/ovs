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
void port_array_clear(struct port_array *);
void port_array_set(struct port_array *, uint16_t idx, void *);
void *port_array_first(const struct port_array *, unsigned int *);
void *port_array_next(const struct port_array *, unsigned int *);
unsigned int port_array_count(const struct port_array *);

#define PORT_ARRAY_FOR_EACH(DATA, ARRAY, PORT_NO)                       \
    for ((DATA) = port_array_first(ARRAY, &(PORT_NO)); (DATA) != NULL;  \
         (DATA) = port_array_next(ARRAY, &(PORT_NO)))

#endif /* port-array.h */
