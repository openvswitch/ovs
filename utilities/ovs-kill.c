/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "command-line.h"
#include "daemon.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

/* -s, --signal: signal to send. */
static int sig_nr = SIGTERM;

/* -f, --force: ignore errors. */
static bool force;

static void cond_error(int err_no, const char *, ...) PRINTF_FORMAT(2, 3);

static void parse_options(int argc, char *argv[]);
static void usage(void);

int
main(int argc, char *argv[])
{
    bool ok = true;
    int i;

    set_program_name(argv[0]);
    parse_options(argc, argv);

    argc -= optind;
    argv += optind;
    if (argc < 1) {
        if (!force) {
            ovs_fatal(0, "need at least one non-option argument; "
                      "use --help for usage");
        }
    }

    for (i = 0; i < argc; i++) {
        char *pidfile;
        pid_t pid;

        pidfile = make_pidfile_name(argv[i]);
        pid = read_pidfile(pidfile);
        if (pid >= 0) {
            if (kill(pid, sig_nr) < 0) {
                cond_error(errno, "%s: kill(%ld)", pidfile, (long int) pid);
            }
        } else {
            cond_error(-pid, "could not read %s", pidfile);
        }
        free(pidfile);
    }

    return ok || force ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void
parse_options(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"signal",      required_argument, 0, 's'},
        {"force",       no_argument, 0, 'f'},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 's':
            if (atoi(optarg) || !strcmp(optarg, "0")) {
                sig_nr = atoi(optarg);
            } else {
                struct signal_name {
                    const char *name;
                    int number;
                };

                static const struct signal_name signals[] = {
#define SIGNAL(NAME) { #NAME, NAME }
                    SIGNAL(SIGABRT),
                    SIGNAL(SIGALRM),
                    SIGNAL(SIGBUS),
                    SIGNAL(SIGCHLD),
                    SIGNAL(SIGCONT),
                    SIGNAL(SIGFPE),
                    SIGNAL(SIGHUP),
                    SIGNAL(SIGILL),
                    SIGNAL(SIGINT),
                    SIGNAL(SIGKILL),
                    SIGNAL(SIGPIPE),
                    SIGNAL(SIGQUIT),
                    SIGNAL(SIGSEGV),
                    SIGNAL(SIGSTOP),
                    SIGNAL(SIGTERM),
                    SIGNAL(SIGTSTP),
                    SIGNAL(SIGTTIN),
                    SIGNAL(SIGTTOU),
                    SIGNAL(SIGUSR1),
                    SIGNAL(SIGUSR2),
#ifdef SIGPOLL
                    SIGNAL(SIGPOLL),
#endif
                    SIGNAL(SIGPROF),
                    SIGNAL(SIGSYS),
                    SIGNAL(SIGTRAP),
                    SIGNAL(SIGURG),
                    SIGNAL(SIGVTALRM),
                    SIGNAL(SIGXCPU),
                    SIGNAL(SIGXFSZ),
#undef SIGNAL
                };
                int i;

                for (i = 0; i < ARRAY_SIZE(signals); i++) {
                    const struct signal_name *s = &signals[i];
                    if (!strcmp(optarg, s->name)
                        || !strcmp(optarg, s->name + 3)) {
                        sig_nr = s->number;
                        goto got_name;
                    }
                }
                ovs_fatal(0, "unknown signal \"%s\"", optarg);
            got_name: ;
            }
            break;

        case 'f':
            force = true;
            break;

        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(0, 0);
            exit(EXIT_SUCCESS);

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: kills a program using a pidfile\n"
           "usage: %s [OPTIONS] PIDFILE [PIDFILE...]\n"
           "where PIDFILE is a pidfile created by an Open vSwitch daemon.\n"
           "\nOptions:\n"
           "  -s, --signal=NUMBER|NAME  signal to send (default: TERM)\n"
           "  -f, --force             ignore errors\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n",
           program_name, program_name);
    exit(EXIT_SUCCESS);
}

static void
cond_error(int err_no, const char *format, ...)
{
    if (!force) {
        va_list args;

        fprintf(stderr, "%s: ", program_name);
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        if (err_no != 0)
            fprintf(stderr, " (%s)", strerror(err_no));
        putc('\n', stderr);
    }
}
