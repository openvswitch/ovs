/*
 * Copyright (c) 2021 NVIDIA Corporation.
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

#ifndef _MOV_AVG_H
#define _MOV_AVG_H 1

#include <math.h>

/* Moving average helpers. */

/* Cumulative Moving Average.
 *
 * Computes the arithmetic mean over a whole series of value.
 * Online equivalent of sum(V) / len(V).
 *
 * As all values have equal weight, this average will
 * be slow to show recent changes in the series.
 *
 */

struct mov_avg_cma {
    unsigned long long int count;
    double mean;
    double sum_dsquared;
};

#define MOV_AVG_CMA_INITIALIZER \
    { .count = 0, .mean = .0, .sum_dsquared = .0 }

static inline void
mov_avg_cma_init(struct mov_avg_cma *cma)
{
    *cma = (struct mov_avg_cma) MOV_AVG_CMA_INITIALIZER;
}

static inline void
mov_avg_cma_update(struct mov_avg_cma *cma, double new_val)
{
    double new_mean;

    cma->count++;
    new_mean = cma->mean + (new_val - cma->mean) / cma->count;

    cma->sum_dsquared += (new_val - new_mean) * (new_val - cma->mean);
    cma->mean = new_mean;
}

static inline double
mov_avg_cma(struct mov_avg_cma *cma)
{
    return cma->mean;
}

static inline double
mov_avg_cma_std_dev(struct mov_avg_cma *cma)
{
    double variance = 0.0;

    if (cma->count > 1) {
        variance = cma->sum_dsquared / (cma->count - 1);
    }

    return sqrt(variance);
}

/* Exponential Moving Average.
 *
 * Each value in the series has an exponentially decreasing weight,
 * the older they get the less weight they have.
 *
 * The smoothing factor 'alpha' must be within 0 < alpha < 1.
 * The closer this factor to zero, the more equal the weight between
 * recent and older values. As it approaches one, the more recent values
 * will have more weight.
 *
 * The EMA can be thought of as an estimator for the next value when measures
 * are dependent. In this case, it can make sense to consider the mean square
 * error of the prediction. An 'alpha' minimizing this error would be the
 * better choice to improve the estimation.
 *
 * A common way to choose 'alpha' is to use the following formula:
 *
 *   a = 2 / (N + 1)
 *
 * With this 'alpha', the EMA will have the same 'center of mass' as an
 * equivalent N-values Simple Moving Average.
 *
 * When using this factor, the N last values of the EMA will have a sum weight
 * converging toward 0.8647, meaning that those values will account for 86% of
 * the average[1].
 *
 * [1] https://en.wikipedia.org/wiki/Moving_average#Exponential_moving_average
 */

struct mov_avg_ema {
    double alpha; /* 'Smoothing' factor. */
    double mean;
    double variance;
    bool initialized;
};

/* Choose alpha explicitly. */
#define MOV_AVG_EMA_INITIALIZER_ALPHA(a) { \
    .initialized = false, \
    .alpha = (a), .variance = 0.0, .mean = 0.0 \
}

/* Choose alpha to consider 'N' past periods as 86% of the EMA. */
#define MOV_AVG_EMA_INITIALIZER(n_elem) \
    MOV_AVG_EMA_INITIALIZER_ALPHA(2.0 / ((double)(n_elem) + 1.0))

static inline void
mov_avg_ema_init_alpha(struct mov_avg_ema *ema,
                       double alpha)
{
    *ema = (struct mov_avg_ema) MOV_AVG_EMA_INITIALIZER_ALPHA(alpha);
}

static inline void
mov_avg_ema_init(struct mov_avg_ema *ema,
                 unsigned long long int n_elem)
{
    *ema = (struct mov_avg_ema) MOV_AVG_EMA_INITIALIZER(n_elem);
}

static inline void
mov_avg_ema_update(struct mov_avg_ema *ema, double new_val)
{
    const double alpha = ema->alpha;
    double alpha_diff;
    double diff;

    if (!ema->initialized) {
        ema->initialized = true;
        ema->mean = new_val;
        return;
    }

    diff = new_val - ema->mean;
    alpha_diff = alpha * diff;

    ema->variance = (1.0 - alpha) * (ema->variance + alpha_diff * diff);
    ema->mean = ema->mean + alpha_diff;
}

static inline double
mov_avg_ema(struct mov_avg_ema *ema)
{
    return ema->mean;
}

static inline double
mov_avg_ema_std_dev(struct mov_avg_ema *ema)
{
    return sqrt(ema->variance);
}

#endif /* _MOV_AVG_H */
