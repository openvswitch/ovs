/*
 * Copyright (c) 2011, 2012 Nicira, Inc.
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

#include <stdio.h>

#include "dynamic-string.h"
#include "flow.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "util.h"
#include "vlog.h"

static int
parse_keys(void)
{
    int exit_code = 0;
    struct ds in;

    ds_init(&in);
    vlog_set_levels_from_string("odp_util:console:dbg");
    while (!ds_get_test_line(&in, stdin)) {
        enum odp_key_fitness fitness;
        struct ofpbuf odp_key;
        struct flow flow;
        struct ds out;
        int error;

        /* Convert string to OVS DP key. */
        ofpbuf_init(&odp_key, 0);
        error = odp_flow_key_from_string(ds_cstr(&in), NULL, &odp_key);
        if (error) {
            printf("odp_flow_key_from_string: error\n");
            goto next;
        }

        /* Convert odp_key to flow. */
        fitness = odp_flow_key_to_flow(odp_key.data, odp_key.size, &flow);
        switch (fitness) {
        case ODP_FIT_PERFECT:
            break;

        case ODP_FIT_TOO_LITTLE:
            printf("ODP_FIT_TOO_LITTLE: ");
            break;

        case ODP_FIT_TOO_MUCH:
            printf("ODP_FIT_TOO_MUCH: ");
            break;

        case ODP_FIT_ERROR:
            printf("odp_flow_key_to_flow: error\n");
            goto next;
        }

        /* Convert cls_rule back to odp_key. */
        ofpbuf_uninit(&odp_key);
        ofpbuf_init(&odp_key, 0);
        odp_flow_key_from_flow(&odp_key, &flow);

        if (odp_key.size > ODPUTIL_FLOW_KEY_BYTES) {
            printf ("too long: %zu > %d\n",
                    odp_key.size, ODPUTIL_FLOW_KEY_BYTES);
            exit_code = 1;
        }

        /* Convert odp_key to string. */
        ds_init(&out);
        odp_flow_key_format(odp_key.data, odp_key.size, &out);
        puts(ds_cstr(&out));
        ds_destroy(&out);

    next:
        ofpbuf_uninit(&odp_key);
    }
    ds_destroy(&in);

    return exit_code;
}

static int
parse_actions(void)
{
    struct ds in;

    ds_init(&in);
    vlog_set_levels_from_string("odp_util:console:dbg");
    while (!ds_get_test_line(&in, stdin)) {
        struct ofpbuf odp_actions;
        struct ds out;
        int error;

        /* Convert string to OVS DP actions. */
        ofpbuf_init(&odp_actions, 0);
        error = odp_actions_from_string(ds_cstr(&in), NULL, &odp_actions);
        if (error) {
            printf("odp_actions_from_string: error\n");
            goto next;
        }

        /* Convert odp_actions back to string. */
        ds_init(&out);
        format_odp_actions(&out, odp_actions.data, odp_actions.size);
        puts(ds_cstr(&out));
        ds_destroy(&out);

    next:
        ofpbuf_uninit(&odp_actions);
    }
    ds_destroy(&in);

    return 0;
}

int
main(int argc, char *argv[])
{
    if (argc == 2 &&!strcmp(argv[1], "parse-keys")) {
        return parse_keys();
    } else if (argc == 2 && !strcmp(argv[1], "parse-actions")) {
        return parse_actions();
    } else {
        ovs_fatal(0, "usage: %s parse-keys | parse-actions", argv[0]);
    }
}
