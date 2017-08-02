/*
 * Copyright (c) 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include "odp-util.h"
#include <stdio.h>
#include "openvswitch/dynamic-string.h"
#include "flow.h"
#include "openvswitch/match.h"
#include "openvswitch/ofpbuf.h"
#include "ovstest.h"
#include "util.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/vlog.h"

static int
parse_keys(bool wc_keys)
{
    int exit_code = 0;
    struct ds in;

    ds_init(&in);
    vlog_set_levels_from_string_assert("odp_util:console:dbg");
    while (!ds_get_test_line(&in, stdin)) {
        enum odp_key_fitness fitness;
        struct ofpbuf odp_key;
        struct ofpbuf odp_mask;
        struct flow flow;
        struct ds out;
        int error;

        /* Convert string to OVS DP key. */
        ofpbuf_init(&odp_key, 0);
        ofpbuf_init(&odp_mask, 0);
        error = odp_flow_from_string(ds_cstr(&in), NULL,
                                     &odp_key, &odp_mask);
        if (error) {
            printf("odp_flow_from_string: error\n");
            goto next;
        }

        if (!wc_keys) {
            struct odp_flow_key_parms odp_parms = {
                .flow = &flow,
                .support = {
                    .recirc = true,
                    .ct_state = true,
                    .ct_zone = true,
                    .ct_mark = true,
                    .ct_label = true,
                    .max_vlan_headers = SIZE_MAX,
                },
            };

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
            odp_flow_key_from_flow(&odp_parms, &odp_key);

            if (odp_key.size > ODPUTIL_FLOW_KEY_BYTES) {
                printf ("too long: %"PRIu32" > %d\n",
                        odp_key.size, ODPUTIL_FLOW_KEY_BYTES);
                exit_code = 1;
            }
        }

        /* Convert odp_key to string. */
        ds_init(&out);
        if (wc_keys) {
            odp_flow_format(odp_key.data, odp_key.size,
                            odp_mask.data, odp_mask.size, NULL, &out, false);
        } else {
            odp_flow_key_format(odp_key.data, odp_key.size, &out);
        }
        puts(ds_cstr(&out));
        ds_destroy(&out);

    next:
        ofpbuf_uninit(&odp_key);
        ofpbuf_uninit(&odp_mask);
    }
    ds_destroy(&in);

    return exit_code;
}

static int
parse_actions(void)
{
    struct ds in;

    ds_init(&in);
    vlog_set_levels_from_string_assert("odp_util:console:dbg");
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
        format_odp_actions(&out, odp_actions.data, odp_actions.size, NULL);
        puts(ds_cstr(&out));
        ds_destroy(&out);

    next:
        ofpbuf_uninit(&odp_actions);
    }
    ds_destroy(&in);

    return 0;
}

static int
parse_filter(char *filter_parse)
{
    struct ds in;
    struct flow flow_filter;
    struct flow_wildcards wc_filter;
    char *error, *filter = NULL;

    vlog_set_levels_from_string_assert("odp_util:console:dbg");
    if (filter_parse && !strncmp(filter_parse, "filter=", 7)) {
        filter = xstrdup(filter_parse + 7);
        memset(&flow_filter, 0, sizeof(flow_filter));
        memset(&wc_filter, 0, sizeof(wc_filter));

        error = parse_ofp_exact_flow(&flow_filter, &wc_filter, NULL, filter,
                                     NULL);
        if (error) {
            ovs_fatal(0, "Failed to parse filter (%s)", error);
        }
    } else {
        ovs_fatal(0, "No filter to parse.");
    }

    ds_init(&in);
    while (!ds_get_test_line(&in, stdin)) {
        struct ofpbuf odp_key;
        struct ofpbuf odp_mask;
        struct ds out;

        /* Convert string to OVS DP key. */
        ofpbuf_init(&odp_key, 0);
        ofpbuf_init(&odp_mask, 0);
        if (odp_flow_from_string(ds_cstr(&in), NULL, &odp_key, &odp_mask)) {
            printf("odp_flow_from_string: error\n");
            goto next;
        }

        if (filter) {
            struct flow flow;
            struct flow_wildcards wc;
            struct match match, match_filter;
            struct minimatch minimatch;

            odp_flow_key_to_flow(odp_key.data, odp_key.size, &flow);
            odp_flow_key_to_mask(odp_mask.data, odp_mask.size, &wc, &flow);
            match_init(&match, &flow, &wc);

            match_init(&match_filter, &flow_filter, &wc);
            match_init(&match_filter, &match_filter.flow, &wc_filter);
            minimatch_init(&minimatch, &match_filter);

            if (!minimatch_matches_flow(&minimatch, &match.flow)) {
                minimatch_destroy(&minimatch);
                goto next;
            }
            minimatch_destroy(&minimatch);
        }
        /* Convert odp_key to string. */
        ds_init(&out);
        odp_flow_format(odp_key.data, odp_key.size,
                        odp_mask.data, odp_mask.size, NULL, &out, false);
        puts(ds_cstr(&out));
        ds_destroy(&out);

    next:
        ofpbuf_uninit(&odp_key);
        ofpbuf_uninit(&odp_mask);
    }
    ds_destroy(&in);

    free(filter);
    return 0;
}

static void
test_odp_main(int argc, char *argv[])
{
    int exit_code = 0;

    set_program_name(argv[0]);
    if (argc == 2 &&!strcmp(argv[1], "parse-keys")) {
        exit_code =parse_keys(false);
    } else if (argc == 2 &&!strcmp(argv[1], "parse-wc-keys")) {
        exit_code =parse_keys(true);
    } else if (argc == 2 && !strcmp(argv[1], "parse-actions")) {
        exit_code = parse_actions();
    } else if (argc == 3 && !strcmp(argv[1], "parse-filter")) {
        exit_code =parse_filter(argv[2]);
    } else {
        ovs_fatal(0, "usage: %s parse-keys | parse-wc-keys | parse-actions", argv[0]);
    }

    exit(exit_code);
}

OVSTEST_REGISTER("test-odp", test_odp_main);
