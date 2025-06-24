/*
 * Copyright (c) 2009, 2010, 2014 Nicira, Inc.
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
#include "openvswitch/json.h"
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include "ovstest.h"
#include "random.h"
#include "timeval.h"
#include "util.h"

/* --pretty: If set, the JSON output is pretty-printed, instead of printed as
 * compactly as possible.  */
static int pretty = 0;

/* --multiple: If set, the input is a sequence of JSON objects or arrays,
 * instead of exactly one object or array. */
static int multiple = 0;

static void test_json_equal(const struct json *a, const struct json *b,
                            bool allow_the_same);

static void
test_json_equal_object(const struct shash *a, const struct shash *b,
                       bool allow_the_same)
{
    struct shash_node *a_node;

    ovs_assert(allow_the_same || a != b);

    if (a == b) {
        return;
    }

    ovs_assert(shash_count(a) == shash_count(b));

    SHASH_FOR_EACH (a_node, a) {
        struct shash_node *b_node = shash_find(b, a_node->name);

        ovs_assert(b_node);
        test_json_equal(a_node->data, b_node->data, allow_the_same);
    }
}

static void
test_json_equal_array(const struct json *a, const struct json *b,
                      bool allow_the_same)
{
    ovs_assert(allow_the_same || a != b);

    if (a == b) {
        return;
    }

    size_t n = json_array_size(a);
    ovs_assert(n == json_array_size(b));

    for (size_t i = 0; i < n; i++) {
        test_json_equal(json_array_at(a, i), json_array_at(b, i),
                        allow_the_same);
    }
}

static void
test_json_equal(const struct json *a, const struct json *b,
                bool allow_the_same)
{
    ovs_assert(allow_the_same || a != b);
    ovs_assert(a && b);

    if (a == b) {
        ovs_assert(a->count > 1);
        return;
    }

    ovs_assert(a->type == b->type);

    switch (a->type) {
    case JSON_OBJECT:
        test_json_equal_object(a->object, b->object, allow_the_same);
        return;

    case JSON_ARRAY:
        test_json_equal_array(a, b, allow_the_same);
        return;

    case JSON_STRING:
        ovs_assert(json_string(a) != json_string(b));
        ovs_assert(!strcmp(json_string(a), json_string(b)));
        return;

    case JSON_SERIALIZED_OBJECT:
        ovs_assert(json_serialized_object(a) != json_serialized_object(b));
        ovs_assert(!strcmp(json_serialized_object(a),
                           json_serialized_object(b)));
        return;

    case JSON_NULL:
    case JSON_FALSE:
    case JSON_TRUE:
        return;

    case JSON_INTEGER:
        ovs_assert(a->integer == b->integer);
        return;

    case JSON_REAL:
        ovs_assert(a->real == b->real);
        return;

    case JSON_N_TYPES:
    default:
        OVS_NOT_REACHED();
    }
}

static void
test_json_clone(struct json *json)
{
    struct json *copy, *deep_copy;

    copy = json_clone(json);

    ovs_assert(json_equal(json, copy));
    test_json_equal(json, copy, true);
    ovs_assert(json->count == 2);

    json_destroy(copy);
    ovs_assert(json->count == 1);

    deep_copy = json_deep_clone(json);

    ovs_assert(json_equal(json, deep_copy));
    test_json_equal(json, deep_copy, false);
    ovs_assert(json->count == 1);
    ovs_assert(deep_copy->count == 1);

    json_destroy(deep_copy);
    ovs_assert(json->count == 1);
}

static bool
print_test_and_free_json(struct json *json)
{
    bool ok;
    if (json->type == JSON_STRING) {
        printf("error: %s\n", json_string(json));
        ok = false;
    } else {
        char *s = json_to_string(json, JSSF_SORT | (pretty ? JSSF_PRETTY : 0));
        puts(s);
        free(s);
        ok = true;
    }
    test_json_clone(json);
    json_destroy(json);
    return ok;
}

static bool
refill(FILE *file, void *buffer, size_t buffer_size, size_t *n, size_t *used)
{
    *used = 0;
    if (feof(file)) {
        *n = 0;
        return false;
    } else {
        *n = fread(buffer, 1, buffer_size, file);
        if (ferror(file)) {
            ovs_fatal(errno, "Error reading input file");
        }
        return *n > 0;
    }
}

static bool
parse_multiple(FILE *stream)
{
    struct json_parser *parser;
    char buffer[BUFSIZ];
    size_t n, used;
    bool ok;

    parser = NULL;
    n = used = 0;
    ok = true;
    while (used < n || refill(stream, buffer, sizeof buffer, &n, &used)) {
        if (!parser && isspace((unsigned char) buffer[used])) {
            /* Skip white space. */
            used++;
        } else {
            if (!parser) {
                parser = json_parser_create(0);
            }

            used += json_parser_feed(parser, &buffer[used], n - used);
            if (used < n) {
                if (!print_test_and_free_json(json_parser_finish(parser))) {
                    ok = false;
                }
                parser = NULL;
            }
        }
    }
    if (parser) {
        if (!print_test_and_free_json(json_parser_finish(parser))) {
            ok = false;
        }
    }
    return ok;
}

static void
test_json_main(int argc, char *argv[])
{
    const char *input_file;
    FILE *stream;
    bool ok;

    set_program_name(argv[0]);

    for (;;) {
        static const struct option options[] = {
            {"pretty", no_argument, &pretty, 1},
            {"multiple", no_argument, &multiple, 1},
        };
        int option_index = 0;
        int c = getopt_long (argc, argv, "", options, &option_index);

        if (c == -1) {
            break;
        }
        switch (c) {
        case 0:
            break;

        case '?':
            exit(1);

        default:
            abort();
        }
    }

    if (argc - optind != 1) {
        ovs_fatal(0, "usage: %s [--pretty] [--multiple] INPUT.json",
                  program_name);
    }

    input_file = argv[optind];
    stream = !strcmp(input_file, "-") ? stdin : fopen(input_file, "r");
    if (!stream) {
        ovs_fatal(errno, "Cannot open \"%s\"", input_file);
    }

    if (multiple) {
        ok = parse_multiple(stream);
    } else {
        ok = print_test_and_free_json(json_from_stream(stream));
    }

    fclose(stream);

    exit(!ok);
}

OVSTEST_REGISTER("test-json", test_json_main);

static void
json_string_benchmark_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct {
        int n;
        int quote_probablility;
        int special_probability;
        int iter;
    } configs[] = {
        { 100000,     0, 0, 1000, },
        { 100000,     2, 1, 1000, },
        { 100000,    10, 1, 1000, },
        { 10000000,   0, 0, 100,  },
        { 10000000,   2, 1, 100,  },
        { 10000000,  10, 1, 100,  },
        { 100000000,  0, 0, 10.   },
        { 100000000,  2, 1, 10,   },
        { 100000000, 10, 1, 10,   },
    };

    printf("  SIZE      Q  S         TO STRING      FROM STRING\n");
    printf("----------------------------------------------------\n");

    for (int i = 0; i < ARRAY_SIZE(configs); i++) {
        int iter = configs[i].iter;
        int n = configs[i].n;
        char *str = xzalloc(n);

        for (int j = 0; j < n - 1; j++) {
            int r = random_range(100);

            if (r < configs[i].special_probability) {
                str[j] = random_range(' ' - 1) + 1;
            } else if (r < (configs[i].special_probability
                            + configs[i].quote_probablility)) {
                str[j] = '"';
            } else {
                str[j] = random_range(256 - ' ') + ' ';
            }
        }

        printf("%-11d %-2d %-2d: ", n, configs[i].quote_probablility,
                                       configs[i].special_probability);
        fflush(stdout);

        struct json *json = json_array_create_1(
                                json_string_create_nocopy(str));
        uint64_t start = time_msec();

        char **res = xzalloc(iter * sizeof *res);
        for (int j = 0; j < iter; j++) {
            res[j] = json_to_string(json, 0);
        }

        printf("%12.3lf ms", (double) (time_msec() - start) / iter);

        struct json **json_parsed = xzalloc(iter * sizeof *json_parsed);

        start = time_msec();
        for (int j = 0; j < iter; j++) {
            json_parsed[j] = json_from_string(res[j]);
        }
        printf("%12.3lf ms\n", (double) (time_msec() - start) / iter);

        for (int j = 0; j < iter; j++) {
            ovs_assert(json_equal(json, json_parsed[j]));
            json_destroy(json_parsed[j]);
            free(res[j]);
        }
        json_destroy(json);
        free(res);
        free(json_parsed);
    }

    exit(0);
}

OVSTEST_REGISTER("json-string-benchmark", json_string_benchmark_main);
