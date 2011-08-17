/*
 * Copyright (c) 2011 Nicira Networks.
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

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "random.h"
#include "util.h"

static void
check_log_2_floor(uint32_t x, int n)
{
    if (log_2_floor(x) != n) {
        fprintf(stderr, "log_2_floor(%"PRIu32") is %d but should be %d\n",
                x, log_2_floor(x), n);
        abort();
    }
}

static void
check_ctz(uint32_t x, int n)
{
    if (ctz(x) != n) {
        fprintf(stderr, "ctz(%"PRIu32") is %d but should be %d\n",
                x, ctz(x), n);
        abort();
    }
}

int
main(void)
{
    int n;

    for (n = 0; n < 32; n++) {
        /* Check minimum x such that f(x) == n. */
        check_log_2_floor(1 << n, n);
        check_ctz(1 << n, n);

        /* Check maximum x such that f(x) == n. */
        check_log_2_floor((1 << n) | ((1 << n) - 1), n);
        check_ctz(UINT32_MAX << n, n);

        /* Check a random value in the middle. */
        check_log_2_floor((random_uint32() & ((1 << n) - 1)) | (1 << n), n);
        check_ctz((random_uint32() | 1) << n, n);
    }

    /* Check ctz(0).
     * (log_2_floor(0) is undefined.) */
    check_ctz(0, 32);

    return 0;
}
