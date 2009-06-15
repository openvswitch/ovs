/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
