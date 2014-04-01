/*
 * Copyright (c) 2008, 2009, 2010, 2014 Nicira, Inc.
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
#include "ovstest.h"
#include <stdio.h>
#include <string.h>

static void
test_random_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum { N_ROUNDS = 10000 };
    unsigned long long int total;
    int hist16[8][16];
    int hist2[32];
    int i;

    random_set_seed(1);

    total = 0;
    memset(hist2, 0, sizeof hist2);
    memset(hist16, 0, sizeof hist16);
    for (i = 0; i < N_ROUNDS; i++) {
        uint32_t x;
        int j;

        x = random_uint32();

        total += x;

        for (j = 0; j < 32; j++) {
            if (x & (1u << j)) {
                hist2[j]++;
            }
        }

        for (j = 0; j < 8; j++) {
            hist16[j][(x >> (j * 4)) & 15]++;
        }
    }

    printf("average=%08llx\n", total / N_ROUNDS);

    printf("\nbit      0     1\n");
    for (i = 0; i < 32; i++) {
        printf("%3d %5d %5d\n", i, N_ROUNDS - hist2[i], hist2[i]);
    }
    printf("(expected values are %d)\n", N_ROUNDS / 2);

    printf("\nnibble   0   1   2   3   4   5   6   7   8   9  10  11  12  "
           "13  14  15\n");
    for (i = 0; i < 8; i++) {
        int j;

        printf("%6d", i);
        for (j = 0; j < 16; j++) {
            printf(" %3d", hist16[i][j]);
        }
        printf("\n");
    }
    printf("(expected values are %d)\n", N_ROUNDS / 16);
}

OVSTEST_REGISTER("test-random", test_random_main);
