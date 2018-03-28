/*
 * Copyright (c) 2018 Red Hat, Inc.
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
#undef NDEBUG
#include "stopwatch.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include "ovstest.h"
#include "util.h"

#define MAX_SAMPLES 100
#define UNIT SW_MS

struct test_data {
    const char *name;
    unsigned long long samples[MAX_SAMPLES];
    size_t num_samples;
    struct stopwatch_stats expected_stats;
};

static struct test_data data_sets[] = {
    {
        .name = "1-interval-zero-length",
        .samples = { 0, 0 },
        .num_samples = 2,
        .expected_stats = {
            .count = 1,
            .unit = UNIT,
            .max = 0,
            .min = 0,
            .pctl_95 = 0,
            .ewma_50 = 0,
            .ewma_1 = 0,
        },
    },
    {
        .name = "1-interval-unit-length",
        .samples = { 0, 1 },
        .num_samples = 2,
        .expected_stats = {
            .count = 1,
            .unit = UNIT,
            .max = 1,
            .min = 1,
            .pctl_95 = 0,
            .ewma_50 = 1,
            .ewma_1 = 1,
        },
    },
    {
        .name = "10-intervals-unit-length",
        .samples = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 },
        .num_samples = 11,
        .expected_stats = {
            .count = 10,
            .unit = UNIT,
            .max = 1,
            .min = 1,
            .pctl_95 = 1,
            .ewma_50 = 1,
            .ewma_1 = 1,
        },
    },
    {
        .name = "10-intervals-linear-growth",
        .samples = { 1, 2, 4, 7, 11, 16, 22, 29, 37, 46, 56 },
        .num_samples = 11,
        .expected_stats = {
            .count = 10,
            .unit = UNIT,
            .max = 10,
            .min = 1,
            .pctl_95 = 10.0,
            .ewma_50 = 9.0,
            .ewma_1 = 1.4,
        },
    },
    {
        .name = "60-intervals-unit-length",
        .samples = { 1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
                    11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                    21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                    31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                    41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
                    51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
                    61, },
        .num_samples = 61,
        .expected_stats = {
            .count = 60,
            .unit = UNIT,
            .max = 1,
            .min = 1,
            .pctl_95 = 1,
            .ewma_50 = 1,
            .ewma_1 = 1,
        },
    },
    {
        .name = "60-intervals-linear-growth",
        .samples = {   1,    2,    4,    7,   11,   16,   22,   29,   37,   46,
                      56,   67,   79,   92,  106,  121,  137,  154,  172,  191,
                     211,  232,  254,  277,  301,  326,  352,  379,  407,  436,
                     466,  497,  529,  562,  596,  631,  667,  704,  742,  781,
                     821,  862,  904,  947,  991, 1036, 1082, 1129, 1177, 1226,
                    1276, 1327, 1379, 1432, 1486, 1541, 1597, 1654, 1712, 1771,
                    1831, },
        .num_samples = 61,
        .expected_stats = {
            .count = 60,
            .unit = UNIT,
            .max = 60,
            .min = 1,
            /* 95th percentile is actually closer to 57, but the estimate is
             * pretty dang close */
            .pctl_95 = 56,
            .ewma_50 = 59,
            .ewma_1 = 15.7,
        },
    },
};

#define ASSERT_MSG(COND, MSG, ...)                  \
    if (!(COND)) {                                  \
        fprintf(stderr, MSG "\n", ##__VA_ARGS__);   \
        assert(COND);                               \
    }

#define ASSERT_ULL_EQ(a, b)                                 \
    ASSERT_MSG(a == b,                                      \
               "Assertion '%s == %s' failed: %llu == %llu", \
               #a, #b, a, b)

#define ASSERT_DOUBLE_EQ(a, b, eps)                                 \
    ASSERT_MSG(fabs(a - b) < eps,                                   \
               "Assertion '|%s - %s| < %s' failed: |%g - %g| < %g", \
               #a, #b, #eps, a, b, eps)

#define ASSERT_STATS_EQ(a, b)                               \
    do {                                                    \
        ASSERT_ULL_EQ((a)->count, (b)->count);              \
        ASSERT_ULL_EQ((a)->max, (b)->max);                  \
        ASSERT_ULL_EQ((a)->min, (b)->min);                  \
        ASSERT_DOUBLE_EQ((a)->pctl_95, (b)->pctl_95, 1e-1); \
        ASSERT_DOUBLE_EQ((a)->ewma_50, (b)->ewma_50, 1e-1); \
        ASSERT_DOUBLE_EQ((a)->ewma_1, (b)->ewma_1, 1e-1);   \
    } while (0)

static void
test_stopwatch_calculate_stats(void)
{
    struct test_data *d;

    for (size_t i = 0; i < ARRAY_SIZE(data_sets); i++) {
        d = &data_sets[i];

        fprintf(stderr, "TEST '%s'\n", d->name);

        stopwatch_create(d->name, UNIT);
        for (size_t j = 0; j < d->num_samples - 1; j ++) {
            stopwatch_start(d->name, d->samples[j]);
            stopwatch_stop(d->name, d->samples[j + 1]);
        }
        stopwatch_sync();

        struct stopwatch_stats stats = { .unit = UNIT };
        stopwatch_get_stats(d->name, &stats);
        ASSERT_STATS_EQ(&stats, &d->expected_stats);

        printf(".");
    }
}

static void
test_stopwatch_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    test_stopwatch_calculate_stats();
    printf("\n");
}

OVSTEST_REGISTER("test-stopwatch", test_stopwatch_main);
