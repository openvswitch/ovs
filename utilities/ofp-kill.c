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
    time_init();
    vlog_init();
    parse_options(argc, argv);

    argc -= optind;
    argv += optind;
    if (argc < 1) {
        if (!force) {
            ofp_fatal(0, "need at least one non-option argument; "
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
                ofp_fatal(0, "unknown signal \"%s\"", optarg);
            got_name: ;
            }
            break;

        case 'f':
            force = true;
            break;

        case 'h':
            usage();

        case 'V':
            printf("%s %s compiled "__DATE__" "__TIME__"\n",
                   program_name, VERSION BUILDNR);
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
           "where each PIDFILE is a pidfile created by an OpenFlow daemon.\n"
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
