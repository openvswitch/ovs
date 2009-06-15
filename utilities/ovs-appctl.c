/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include "vlog.h"

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "command-line.h"
#include "compiler.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

static void
usage(char *prog_name, int exit_code)
{
    printf("Usage: %s [TARGET] [ACTION...]\n"
           "Targets:\n"
           "  -t, --target=TARGET  Path to Unix domain socket\n"
           "Actions:\n"
           "  -l, --list         List current settings\n"
           "  -s, --set=MODULE[:FACILITY[:LEVEL]]\n"
           "        Set MODULE and FACILITY log level to LEVEL\n"
           "        MODULE may be any valid module name or 'ANY'\n"
           "        FACILITY may be 'syslog', 'console', 'file', or 'ANY' (default)\n"
           "        LEVEL may be 'emer', 'err', 'warn', 'info', or 'dbg' (default)\n"
           "  -r, --reopen       Make the program reopen its log file\n"
           "  -e, --execute=COMMAND  Execute control COMMAND and print its output\n"
           "Other options:\n"
           "  -h, --help         Print this helpful information\n"
           "  -V, --version      Display version information\n",
           prog_name);
    exit(exit_code);
}

static char *
transact(struct unixctl_client *client, const char *request, bool *ok)
{
    int code;
    char *reply;
    int error = unixctl_client_transact(client, request, &code, &reply);
    if (error) {
        fprintf(stderr, "%s: transaction error: %s\n",
                unixctl_client_target(client), strerror(error));
        *ok = false;
        return xstrdup("");
    } else {
        if (code / 100 != 2) {
            fprintf(stderr, "%s: server returned reply code %03d\n",
                    unixctl_client_target(client), code);
        }
        return reply;
    }
}

static void
transact_ack(struct unixctl_client *client, const char *request, bool *ok)
{
    free(transact(client, request, ok));
}

static void
execute_command(struct unixctl_client *client, const char *request, bool *ok)
{
    int code;
    char *reply;
    int error = unixctl_client_transact(client, request, &code, &reply);
    if (error) {
        fprintf(stderr, "%s: transaction error: %s\n",
                unixctl_client_target(client), strerror(error));
        *ok = false;
    } else {
        if (code / 100 != 2) {
            fprintf(stderr, "%s: server returned reply code %03d\n",
                    unixctl_client_target(client), code);
            fputs(reply, stderr);
            *ok = false;
        } else {
            fputs(reply, stdout);
        }
    }
}

static void
add_target(struct unixctl_client ***clients, size_t *n_clients,
           const char *path, bool *ok)
{
    struct unixctl_client *client;
    int error = unixctl_client_create(path, &client);
    if (error) {
        fprintf(stderr, "Error connecting to \"%s\": %s\n",
                path, strerror(error));
        *ok = false;
    } else {
        *clients = xrealloc(*clients, sizeof *clients * (*n_clients + 1));
        (*clients)[*n_clients] = client;
        ++*n_clients;
    }
}

int main(int argc, char *argv[])
{
    static const struct option long_options[] = {
        /* Target options must come first. */
        {"target", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},

        /* Action options come afterward. */
        {"list", no_argument, NULL, 'l'},
        {"set", required_argument, NULL, 's'},
        {"reopen", no_argument, NULL, 'r'},
        {"execute", required_argument, NULL, 'e'},
        {0, 0, 0, 0},
    };
    char *short_options;

    /* Determine targets. */
    bool ok = true;
    int n_actions = 0;
    struct unixctl_client **clients = NULL;
    size_t n_clients = 0;

    set_program_name(argv[0]);
    time_init();

    short_options = long_options_to_short_options(long_options);
    for (;;) {
        int option;
        size_t i;

        option = getopt_long(argc, argv, short_options, long_options, NULL);
        if (option == -1) {
            break;
        }
        if (!strchr("thV", option) && n_clients == 0) {
            ovs_fatal(0, "no targets specified (use --help for help)");
        } else {
            ++n_actions;
        }
        switch (option) {
        case 't':
            add_target(&clients, &n_clients, optarg, &ok);
            break;

        case 'l':
            for (i = 0; i < n_clients; i++) {
                struct unixctl_client *client = clients[i];
                char *reply;

                printf("%s:\n", unixctl_client_target(client));
                reply = transact(client, "vlog/list", &ok);
                fputs(reply, stdout);
                free(reply);
            }
            break;

        case 's':
            for (i = 0; i < n_clients; i++) {
                struct unixctl_client *client = clients[i];
                char *request = xasprintf("vlog/set %s", optarg);
                transact_ack(client, request, &ok);
                free(request);
            }
            break;

        case 'r':
            for (i = 0; i < n_clients; i++) {
                struct unixctl_client *client = clients[i];
                char *request = xstrdup("vlog/reopen");
                transact_ack(client, request, &ok);
                free(request);
            }
            break;

        case 'e':
            for (i = 0; i < n_clients; i++) {
                execute_command(clients[i], optarg, &ok);
            }
            break;

        case 'h':
            usage(argv[0], EXIT_SUCCESS);
            break;

        case 'V':
            OVS_PRINT_VERSION(0, 0);
            exit(EXIT_SUCCESS);

        case '?':
            exit(EXIT_FAILURE);

        default:
            NOT_REACHED();
        }
    }
    if (!n_actions) {
        fprintf(stderr,
                "warning: no actions specified (use --help for help)\n");
    }
    exit(ok ? 0 : 1);
}
