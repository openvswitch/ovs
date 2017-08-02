/* Copyright (c) 2011, 2012, 2013, 2014, 2017 Nicira, Inc.
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
#include <math.h>
#include <stdlib.h>
#include "bundle.h"
#include "flow.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "ovstest.h"
#include "util.h"

#define N_FLOWS  50000
#define MAX_SLAVES 8 /* Maximum supported by this test framework. */

struct slave {
    ofp_port_t slave_id;

    bool enabled;
    size_t flow_count;
};

struct slave_group {
    size_t n_slaves;
    struct slave slaves[MAX_SLAVES];
};

static struct slave *
slave_lookup(struct slave_group *sg, ofp_port_t slave_id)
{
    size_t i;

    for (i = 0; i < sg->n_slaves; i++) {
        if (sg->slaves[i].slave_id == slave_id) {
            return &sg->slaves[i];
        }
    }

    return NULL;
}

static bool
slave_enabled_cb(ofp_port_t slave_id, void *aux)
{
    struct slave *slave;

    slave = slave_lookup(aux, slave_id);
    return slave ? slave->enabled : false;
}

static struct ofpact_bundle *
parse_bundle_actions(char *actions)
{
    struct ofpact_bundle *bundle;
    struct ofpbuf ofpacts;
    struct ofpact *action;
    char *error;

    ofpbuf_init(&ofpacts, 0);
    error = bundle_parse_load(actions, NULL, &ofpacts);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    action = ofpacts.data;
    bundle = ofpact_get_BUNDLE(xmemdup(action, action->len));
    ofpbuf_uninit(&ofpacts);

    if (bundle->n_slaves > MAX_SLAVES) {
        ovs_fatal(0, "At most %u slaves are supported", MAX_SLAVES);
    }

    return bundle;
}

static const char *
mask_str(uint8_t mask, size_t n_bits)
{
    static char str[9];
    size_t i;

    n_bits = MIN(n_bits, 8);
    for (i = 0; i < n_bits; i++) {
        str[i] = (1 << i) & mask ? '1' : '0';
    }
    str[i] = '\0';

    return str;
}

static void
test_bundle_main(int argc, char *argv[])
{
    bool ok = true;
    struct ofpact_bundle *bundle;
    struct flow *flows;
    size_t i, n_permute, old_n_enabled;
    struct slave_group sg;
    int old_active;

    set_program_name(argv[0]);

    if (argc != 2) {
        ovs_fatal(0, "usage: %s bundle_action", program_name);
    }

    bundle = parse_bundle_actions(argv[1]);

    /* Generate 'slaves' array. */
    sg.n_slaves = 0;
    for (i = 0; i < bundle->n_slaves; i++) {
        ofp_port_t slave_id = bundle->slaves[i];

        if (slave_lookup(&sg, slave_id)) {
            ovs_fatal(0, "Redundant slaves are not supported. ");
        }

        sg.slaves[sg.n_slaves].slave_id = slave_id;
        sg.n_slaves++;
    }

    /* Generate flows. */
    flows = xmalloc(N_FLOWS * sizeof *flows);
    for (i = 0; i < N_FLOWS; i++) {
        flow_random_hash_fields(&flows[i]);
        flows[i].regs[0] = ofp_to_u16(OFPP_NONE);
    }

    /* Cycles through each possible liveness permutation for the given
     * n_slaves.  The initial state is equivalent to all slaves down, so we
     * skip it by starting at i = 1. We do one extra iteration to cover
     * transitioning from the final state back to the initial state. */
    old_n_enabled = 0;
    old_active = -1;
    n_permute = 1 << sg.n_slaves;
    for (i = 1; i <= n_permute + 1; i++) {
        struct slave *slave;
        size_t j, n_enabled, changed;
        double disruption, perfect;
        uint8_t mask;
        int active;

        mask = i % n_permute;

        /* Gray coding ensures that in each iteration exactly one slave
         * changes its liveness.  This makes the expected disruption a bit
         * easier to calculate, and is likely similar to how failures will be
         * experienced in the wild. */
        mask = mask ^ (mask >> 1);

        /* Initialize slaves. */
        n_enabled = 0;
        for (j = 0; j < sg.n_slaves; j++) {
            slave = &sg.slaves[j];
            slave->flow_count = 0;
            slave->enabled = ((1 << j) & mask) != 0;

            if (slave->enabled) {
                n_enabled++;
            }
        }

        active = -1;
        for (j = 0; j < sg.n_slaves; j++) {
            if (sg.slaves[j].enabled) {
                active = j;
                break;
            }
        }

        changed = 0;
        for (j = 0; j < N_FLOWS; j++) {
            struct flow *flow = &flows[j];
            ofp_port_t old_slave_id, ofp_port;
            struct flow_wildcards wc;

            old_slave_id = u16_to_ofp(flow->regs[0]);
            ofp_port = bundle_execute(bundle, flow, &wc, slave_enabled_cb,
                                      &sg);
            flow->regs[0] = ofp_to_u16(ofp_port);

            if (ofp_port != OFPP_NONE) {
                slave_lookup(&sg, ofp_port)->flow_count++;
            }

            if (old_slave_id != ofp_port) {
                changed++;
            }
        }

        if (bundle->algorithm == NX_BD_ALG_ACTIVE_BACKUP) {
            perfect = active == old_active ? 0.0 : 1.0;
        } else {
            if (old_n_enabled || n_enabled) {
                perfect = 1.0 / MAX(old_n_enabled, n_enabled);
            } else {
                /* This will happen when 'sg.n_slaves' is 0. */
                perfect = 0;
            }
        }

        disruption = changed / (double)N_FLOWS;
        printf("%s: disruption=%.2f (perfect=%.2f)",
               mask_str(mask, sg.n_slaves), disruption, perfect);

        for (j = 0 ; j < sg.n_slaves; j++) {
            slave = &sg.slaves[j];
            double flow_percent;

            flow_percent = slave->flow_count / (double)N_FLOWS;
            printf( " %.2f", flow_percent);

            if (slave->enabled) {
                double perfect_fp;

                if (bundle->algorithm == NX_BD_ALG_ACTIVE_BACKUP) {
                    perfect_fp = j == active ? 1.0 : 0.0;
                } else {
                    perfect_fp = 1.0 / n_enabled;
                }

                if (fabs(flow_percent - perfect_fp) >= .01) {
                    fprintf(stderr, "%s: slave %d: flow_percentage=%.5f for"
                            " differs from perfect=%.5f by more than .01\n",
                            mask_str(mask, sg.n_slaves), slave->slave_id,
                            flow_percent, perfect_fp);
                    ok = false;
                }
            } else if (slave->flow_count) {
                fprintf(stderr, "%s: slave %d: disabled slave received"
                        " flows.\n", mask_str(mask, sg.n_slaves),
                        slave->slave_id);
                ok = false;
            }
        }
        printf("\n");

        if (fabs(disruption - perfect) >= .01) {
            fprintf(stderr, "%s: disruption=%.5f differs from perfect=%.5f by"
                    " more than .01\n", mask_str(mask, sg.n_slaves),
                    disruption, perfect);
            ok = false;
        }

        old_active = active;
        old_n_enabled = n_enabled;
    }

    free(bundle);
    free(flows);
    exit(ok ? 0 : 1);
}

OVSTEST_REGISTER("test-bundle", test_bundle_main);
