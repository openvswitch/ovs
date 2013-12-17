/*
 * Copyright (c) 2010, 2012, 2013 Nicira, Inc.
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

#include "multipath.h"

#include <assert.h>
#include <getopt.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include "flow.h"
#include "ofp-actions.h"
#include "util.h"

int
main(int argc, char *argv[])
{
    enum { MP_MAX_LINKS = 63 };
    struct ofpact_multipath mp;
    bool ok = true;
    char *error;
    int n;

    set_program_name(argv[0]);

    if (argc != 2) {
        ovs_fatal(0, "usage: %s multipath_action", program_name);
    }

    error = multipath_parse(&mp, argv[1]);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    for (n = 1; n <= MP_MAX_LINKS; n++) {
        enum { N_FLOWS = 65536 };
        double disruption, perfect, distribution;
        int histogram[MP_MAX_LINKS];
        double sum_dev2, stddev;
        int changed;
        int i;

        changed = 0;
        memset(histogram, 0, sizeof histogram);
        for (i = 0; i < N_FLOWS; i++) {
            int old_link, new_link;
            struct flow_wildcards wc;
            struct flow flow;

            flow_random_hash_fields(&flow);

            mp.max_link = n - 1;
            multipath_execute(&mp, &flow, &wc);
            old_link = flow.regs[0];

            mp.max_link = n;
            multipath_execute(&mp, &flow, &wc);
            new_link = flow.regs[0];

            assert(old_link >= 0 && old_link < n);
            assert(new_link >= 0 && new_link < n + 1);

            histogram[old_link]++;
            changed += old_link != new_link;
        }

        sum_dev2 = 0.0;
        for (i = 0; i < n; i++) {
            double mean = (double) N_FLOWS / n;
            double deviation = histogram[i] - mean;

            sum_dev2 += deviation * deviation;
        }
        stddev = sqrt(sum_dev2 / n);

        disruption = (double) changed / N_FLOWS;
        perfect = 1.0 / (n + 1);
        distribution = stddev / ((double) N_FLOWS / n);
        printf("%2d -> %2d: disruption=%.2f (perfect=%.2f); "
               "stddev/expected=%.4f\n",
               n, n + 1, disruption, perfect, distribution);

        switch (mp.algorithm) {
        case NX_MP_ALG_MODULO_N:
            if (disruption < (n < 2 ? .25 : .5)) {
                fprintf(stderr, "%d -> %d: disruption=%.2f < .5\n",
                        n, n + 1, disruption);
                ok = false;
            }
            break;

        case NX_MP_ALG_HASH_THRESHOLD:
            if (disruption < .48 || disruption > .52) {
                fprintf(stderr, "%d -> %d: disruption=%.2f not approximately "
                        ".5\n", n, n + 1, disruption);
                ok = false;
            }
            break;

        case NX_MP_ALG_ITER_HASH:
            if (!(n & (n - 1))) {
                break;
            }
            /* Fall through. */
        case NX_MP_ALG_HRW:
            if (fabs(disruption - perfect) >= .01) {
                fprintf(stderr, "%d -> %d: disruption=%.5f differs from "
                        "perfect=%.5f by more than .01\n",
                        n, n + 1, disruption, perfect);
                ok = false;
            }
            break;

        default:
            OVS_NOT_REACHED();
        }
    }

    return ok ? 0 : 1;
}
