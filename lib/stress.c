/*
 * Copyright (c) 2010, 2011 Nicira, Inc.
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
#include "stress.h"
#include <stdlib.h>
#include <string.h>
#include "unixctl.h"
#include "dynamic-string.h"
#include "random.h"
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(stress);

/* The stress options. */
#if USE_LINKER_SECTIONS
extern struct stress_option *__start_stress_options[];
extern struct stress_option *__stop_stress_options[];
#define stress_options __start_stress_options
#define n_stress_options (__stop_stress_options - __start_stress_options)
#else  /* !USE_LINKER_SECTIONS */
#undef STRESS_OPTION
#define STRESS_OPTION(NAME, DESCRIPTION, RECOMMENDED, MIN, MAX, DEFAULT) \
        STRESS_OPTION__(NAME, DESCRIPTION, RECOMMENDED, MIN, MAX, DEFAULT);
#include "stress.def"
#undef STRESS_OPTION

struct stress_option *stress_options[] = {
#define STRESS_OPTION(NAME, DESCRIPTION, RECOMMENDED, MIN, MAX, DEFAULT) \
        &stress_##NAME,
#include "stress.def"
#undef STRESS_OPTION
};
#define n_stress_options ARRAY_SIZE(stress_options)
#endif  /* !USE_LINKER_SECTIONS */

/* Enable stress options? */
static bool stress_enabled;

static void
stress_reset(struct stress_option *option)
{
    if (!option->period || !stress_enabled) {
        option->counter = UINT_MAX;
    } else if (!option->random) {
        option->counter = option->period;
    } else if (option->period < UINT32_MAX / 2) {
        /* Random distribution with mean of option->period. */
        option->counter = random_uint32() % ((2 * option->period) - 1) + 1;
    } else {
        option->counter = random_uint32();
    }
}

static void
stress_enable(bool enable)
{
    if (stress_enabled != enable) {
        int i;

        stress_enabled = enable;
        for (i = 0; i < n_stress_options; i++) {
            stress_reset(stress_options[i]);
        }
    }
}

bool
stress_sample_slowpath__(struct stress_option *option)
{
    stress_reset(option);
    if (option->period && stress_enabled) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);

        option->hits++;
        VLOG_DBG_RL(&rl, "%s hit (%llu total)", option->name, option->hits);

        return true;
    } else {
        return false;
    }
}

static void
stress_set(struct stress_option *option, unsigned int period, bool random)
{
    if (period > option->max) {
        period = option->max;
    }
    if (period < option->min) {
        period = option->min;
    }
    if (period != option->period || random != option->random) {
        option->random = random;
        option->period = period;
        stress_reset(option);
    }
}

static void
stress_unixctl_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    int i, found = 0;
    struct ds results;

    ds_init(&results);
    ds_put_cstr(&results, "NAME (DESCRIPTION)\n");
    ds_put_format(&results, "%11s %10s %10s %10s\n",
                  "PERIOD", "MODE", "COUNTER", "HITS");
    ds_put_format(&results, "%11s %10s %10s %10s\n",
                  "RECOMMENDED", "MINIMUM", "MAXIMUM", "DEFAULT");
    for (i = 0; i < n_stress_options; i++) {
        struct stress_option *option = stress_options[i];
        if (!argv[1] || strstr(option->name, argv[1])) {
            ds_put_format(&results, "\n%s (%s)\n",
                          option->name, option->description);
            if (option->period) {
                ds_put_format(&results, "%11u %10s ", option->period,
                              option->random ? "random" : "periodic");
                if (stress_enabled) {
                    ds_put_format(&results, "%10u", option->counter);
                } else {
                    ds_put_cstr(&results, "     n/a");
                }
            } else {
                ds_put_format(&results, "%11s %10s %10s",
                              "disabled", "n/a", "n/a");
            }
            ds_put_format(&results, " %10llu\n", option->hits);
            ds_put_format(&results, "%11u %10u %10u ",
                          option->recommended, option->min, option->max);
            if (!option->def) {
                ds_put_format(&results, "%10s", "disabled");
            } else {
                ds_put_format(&results, "%10u", option->def);
            }
            ds_put_char(&results, '\n');
            found++;
        }
    }
    if (found) {
        unixctl_command_reply(conn, ds_cstr(&results));
    } else {
        unixctl_command_reply_error(conn, NULL);
    }
    ds_destroy(&results);
}

static void
stress_unixctl_enable(struct unixctl_conn *conn, int argc OVS_UNUSED,
                      const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    stress_enable(true);
    unixctl_command_reply(conn, NULL);
}

static void
stress_unixctl_disable(struct unixctl_conn *conn, int argc OVS_UNUSED,
                       const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    stress_enable(false);
    unixctl_command_reply(conn, NULL);
}

static void
stress_unixctl_set(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[], void *aux OVS_UNUSED)
{
    const char *option_name = argv[1];
    const char *option_val = argv[2];
    int i;

    for (i = 0; i < n_stress_options; i++) {
        struct stress_option *option = stress_options[i];
        if (!strcmp(option_name, option->name)) {
            unsigned int period = strtoul(option_val, NULL, 0);
            bool random = !strcmp(argv[3], "random");

            stress_set(option, period, random);
            unixctl_command_reply(conn, NULL);
            return;
        }
    }

    unixctl_command_reply_error(conn, NULL);
}

/* Exposes ovs-appctl access to the stress options.
 *
 * This function is not required to simply reference stress options and have
 * them fire at their default periods.
 */
void
stress_init_command(void)
{
    unixctl_command_register("stress/list", "", 0, 1,
                             stress_unixctl_list, NULL);
    unixctl_command_register("stress/set", "option period [random | periodic]",
                             2, 3, stress_unixctl_set, NULL);
    unixctl_command_register("stress/enable", "", 0, 0,
                             stress_unixctl_enable, NULL);
    unixctl_command_register("stress/disable", "", 0, 0,
                             stress_unixctl_disable, NULL);
}
