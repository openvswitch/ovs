/* Copyright (c) 2008, 2009  Nicira Networks
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

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cfg.h"
#include "command-line.h"
#include "svec.h"
#include "timeval.h"
#include "util.h"

#define THIS_MODULE VLM_cfg_mod
#include "vlog.h"

/* Configuration when we first read the configuration file. */
static struct svec orig_cfg = SVEC_EMPTY_INITIALIZER;

static void
usage(char *prog_name, int exit_code)
{
    printf("Usage: %s --config-file=FILE ACTIONS\n"
           "\nConfig:\n"
           "  -T, --timeout=MS        wait at most MS milliseconds for lock\n"
           "  -F, --config-file=FILE  use configuration FILE\n"
           "\nActions:\n"
           "  -a, --add=ENTRY         add ENTRY\n"
           "  -d, --del-entry=ENTRY   delete ENTRY\n"
           "  -D, --del-section=KEY   delete section matching KEY\n"
           "  --del-match=PATTERN     delete entries matching shell PATTERN\n"
           "  -q, --query=KEY         return all entries matching KEY\n"
           "  -c, --log-changes       log changes up to this point\n"
           "\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n",
           prog_name);
    exit(exit_code);
}

static void 
open_config(char *config_file, int timeout) 
{
    int error;

    cfg_init();
    error = cfg_set_file(config_file);
    if (error) {
        ovs_fatal(error, "failed to add configuration file \"%s\"",
                config_file);
    }

    error = cfg_lock(NULL, timeout);
    if (error) {
        ovs_fatal(error, "could not lock configuration file\n");
    }

    cfg_get_all(&orig_cfg);
}

static void
print_vals(char *key)
{
    struct svec vals;
    int i;

    svec_init(&vals);
    cfg_get_all_strings(&vals, "%s", key);

    for (i=0; i<vals.n; i++) {
        printf("%s\n", vals.names[i]);
    }
}

static void
log_diffs(void)
{
    struct svec new_cfg, removed, added;
    size_t i;

    svec_init(&new_cfg);
    cfg_get_all(&new_cfg);
    svec_diff(&orig_cfg, &new_cfg, &removed, NULL, &added);
    if (removed.n || added.n) {
        VLOG_INFO("configuration changes:");
        for (i = 0; i < removed.n; i++) {
            VLOG_INFO("-%s", removed.names[i]);
        }
        for (i = 0; i < added.n; i++) {
            VLOG_INFO("+%s", added.names[i]);
        }
    } else {
        VLOG_INFO("configuration unchanged");
    }
    svec_destroy(&added);
    svec_destroy(&removed);
    svec_swap(&new_cfg, &orig_cfg);
    svec_destroy(&new_cfg);
}

int main(int argc, char *argv[])
{
    enum {
        OPT_DEL_MATCH = UCHAR_MAX + 1,
    };
    static const struct option long_options[] = {
        {"config-file",  required_argument, 0, 'F'},
        {"timeout",      required_argument, 0, 'T'},
        {"add",          required_argument, 0, 'a'},
        {"del-entry",    required_argument, 0, 'd'},
        {"del-section",  required_argument, 0, 'D'},
        {"del-match",    required_argument, 0, OPT_DEL_MATCH},
        {"query",        required_argument, 0, 'q'},
        {"changes",      no_argument, 0, 'c'},
        {"verbose",      optional_argument, 0, 'v'},
        {"help",         no_argument, 0, 'h'},
        {"version",      no_argument, 0, 'V'},
        {0, 0, 0, 0},
    };
    char *short_options;
    bool config_set = false;
    int timeout = INT_MAX;

    set_program_name(argv[0]);
    time_init();
    vlog_init();

    short_options = long_options_to_short_options(long_options);
    for (;;) {
        int option;

        option = getopt_long(argc, argv, short_options, long_options, NULL);
        if (option == -1) {
            break;
        }

        if ((option > UCHAR_MAX || !strchr("FhVv?", option))
            && config_set == false) {
            ovs_fatal(0, "no config file specified (use --help for help)");
        }

        switch (option) {
        case 'T':
            if (config_set) {
                ovs_fatal(0, "--timeout or -T must be specified "
                          "before --file or -F");
            }
            timeout = atoi(optarg);
            break;

        case 'F': 
            open_config(optarg, timeout);
            config_set = true;
            break;

       case 'a':
            cfg_add_entry("%s", optarg);
            break;

        case 'd':
            cfg_del_entry("%s", optarg);
            break;

        case 'D':
            cfg_del_section("%s", optarg);
            break;

        case OPT_DEL_MATCH:
            cfg_del_match("%s", optarg);
            break;

        case 'q':
            print_vals(optarg);
            break;

        case 'c':
            log_diffs();
            break;

        case 'h':
            usage(argv[0], EXIT_SUCCESS);
            break;

        case 'V':
            OVS_PRINT_VERSION(0, 0);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            NOT_REACHED();
        }
    }
    free(short_options);

    if (optind != argc) {
        ovs_fatal(0, "non-option arguments not accepted "
                  "(use --help for help)");
    }

    if (cfg_is_dirty()) {
        cfg_write();
    }
    cfg_unlock();

    exit(0);
}
