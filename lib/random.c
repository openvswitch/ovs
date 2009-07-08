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

#include <config.h>
#include "random.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>

#include "util.h"

void
random_init(void)
{
    static bool inited = false;
    if (!inited) {
        struct timeval tv;
        inited = true;
        if (gettimeofday(&tv, NULL) < 0) {
            ovs_fatal(errno, "gettimeofday");
        }
        srand(tv.tv_sec ^ tv.tv_usec);
    }
}

void
random_bytes(void *p_, size_t n)
{
    uint8_t *p = p_;
    random_init();
    while (n--) {
        *p++ = rand();
    }
}

uint8_t
random_uint8(void)
{
    random_init();
    return rand();
}

uint16_t
random_uint16(void)
{
    if (RAND_MAX >= UINT16_MAX) {
        random_init();
        return rand();
    } else {
        uint16_t x;
        random_bytes(&x, sizeof x);
        return x;
    }
}

uint32_t
random_uint32(void)
{
    if (RAND_MAX >= UINT32_MAX) {
        random_init();
        return rand();
    } else if (RAND_MAX == INT32_MAX) {
        random_init();
        return rand() | ((rand() & 1u) << 31);
    } else {
        uint32_t x;
        random_bytes(&x, sizeof x);
        return x;
    }
}

int
random_range(int max) 
{
    return random_uint32() % max;
}
