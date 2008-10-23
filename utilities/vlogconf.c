/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
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
#include "util.h"
#include "vlog-socket.h"

void
usage(char *prog_name, int exit_code)
{
    printf("Usage: %s [TARGET] [ACTION...]\n"
           "Targets:\n"
           "  -a, --all            Apply to all targets (default)\n"
           "  -t, --target=TARGET  Specify target program, as a pid, a\n"
           "                       pidfile, or an absolute path to a Unix\n"
           "                       domain socket\n"
           "Actions:\n"
           "  -l, --list         List current settings\n"
           "  -s, --set=MODULE[:FACILITY[:LEVEL]]\n"
           "        Set MODULE and FACILITY log level to LEVEL\n"
           "        MODULE may be any valid module name or 'ANY'\n"
           "        FACILITY may be 'syslog', 'console', 'file', or 'ANY' (default)\n"
           "        LEVEL may be 'emer', 'err', 'warn', or 'dbg' (default)\n"
           "  -r, --reopen       Make the program reopen its log file\n"
           "  -h, --help         Print this helpful information\n",
           prog_name);
    exit(exit_code);
}

static char *
transact(struct vlog_client *client, const char *request, bool *ok)
{
    char *reply;
    int error = vlog_client_transact(client, request, &reply);
    if (error) {
        fprintf(stderr, "%s: transaction error: %s\n",
                vlog_client_target(client), strerror(error));
        *ok = false;
    }
    return reply ? reply : xstrdup("");
}

static void
transact_ack(struct vlog_client *client, const char* request, bool *ok)
{
    char *reply;
    int error = vlog_client_transact(client, request, &reply);
    if (error) {
        fprintf(stderr, "%s: transaction error: %s\n",
                vlog_client_target(client), strerror(error));
        *ok = false;
    } else if (strcmp(reply, "ack")) {
        fprintf(stderr, "Received unexpected reply from %s: %s\n",
                vlog_client_target(client), reply);
        *ok = false;
    }
    free(reply);
}

static void
add_target(struct vlog_client ***clients, size_t *n_clients,
           const char *path, bool *ok)
{
    struct vlog_client *client;
    int error = vlog_client_connect(path, &client);
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

static void
add_all_targets(struct vlog_client ***clients, size_t *n_clients, bool *ok)
{
    DIR *directory;
    struct dirent* de;

    directory = opendir("/tmp");
    if (!directory) {
        fprintf(stderr, "/tmp: opendir: %s\n", strerror(errno));
    }

    while ((de = readdir(directory)) != NULL) {
        if (!strncmp(de->d_name, "vlogs.", 5)) {
            char *path = xasprintf("/tmp/%s", de->d_name);
            add_target(clients, n_clients, path, ok);
            free(path);
        }
    }

    closedir(directory);
}

int main(int argc, char *argv[])
{
    static const struct option long_options[] = {
        /* Target options must come first. */
        {"all", no_argument, NULL, 'a'},
        {"target", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},

        /* Action options come afterward. */
        {"list", no_argument, NULL, 'l'},
        {"set", required_argument, NULL, 's'},
        {"reopen", no_argument, NULL, 'r'},
        {0, 0, 0, 0},
    };
    char *short_options;

    /* Determine targets. */
    bool ok = true;
    int n_actions = 0;
    struct vlog_client **clients = NULL;
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
        if (!strchr("ath", option) && n_clients == 0) {
            ofp_fatal(0, "no targets specified (use --help for help)");
        } else {
            ++n_actions;
        }
        switch (option) {
        case 'a':
            add_all_targets(&clients, &n_clients, &ok);
            break;

        case 't':
            add_target(&clients, &n_clients, optarg, &ok);
            break;

        case 'l':
            for (i = 0; i < n_clients; i++) {
                struct vlog_client *client = clients[i];
                char *reply;

                printf("%s:\n", vlog_client_target(client));
                reply = transact(client, "list", &ok);
                fputs(reply, stdout);
                free(reply);
            }
            break;

        case 's':
            for (i = 0; i < n_clients; i++) {
                struct vlog_client *client = clients[i];
                char *request = xasprintf("set %s", optarg);
                transact_ack(client, request, &ok);
                free(request);
            }
            break;

        case 'r':
            for (i = 0; i < n_clients; i++) {
                struct vlog_client *client = clients[i];
                char *request = xasprintf("reopen");
                transact_ack(client, request, &ok);
                free(request);
            }
            break;

        case 'h':
            usage(argv[0], EXIT_SUCCESS);
            break;

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
